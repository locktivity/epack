package ziputil

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
)

func TestCheckCompressionRatio_AllowsEmptyAndReasonableEntries(t *testing.T) {
	t.Parallel()

	zipBytes := buildZip(t, map[string]zipEntrySpec{
		"empty.txt":                {data: []byte{}, method: zip.Deflate},
		"dir/":                     {isDir: true},
		"dir/hello.txt":            {data: []byte("hello"), method: zip.Deflate},
		"dir/subdir/":              {isDir: true},
		"dir/subdir/also-okay.bin": {data: bytes.Repeat([]byte("a"), 1024), method: zip.Store}, // 1:1 ratio
	})

	reader := mustZipReader(t, zipBytes)

	if err := CheckCompressionRatio(reader, 10); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestCheckCompressionRatio_RejectsHighExpansionRatio(t *testing.T) {
	t.Parallel()

	// Very compressible payload: large uncompressed, tiny compressed.
	highlyCompressible := bytes.Repeat([]byte("A"), 512*1024) // 512 KiB of same byte

	zipBytes := buildZip(t, map[string]zipEntrySpec{
		"bomb.txt": {data: highlyCompressible, method: zip.Deflate},
	})

	reader := mustZipReader(t, zipBytes)

	// Threshold deliberately low so this reliably trips.
	err := CheckCompressionRatio(reader, 2)
	if err == nil {
		t.Fatalf("expected an error, got nil")
	}

	// Keep assertions loose: different compressors/platforms can vary slightly.
	if !strings.Contains(err.Error(), "exceeds compression ratio limit") &&
		!strings.Contains(err.Error(), "ZipBomb") {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(err.Error(), "bomb.txt") {
		t.Fatalf("expected entry name in error, got: %v", err)
	}
}

func TestCheckCompressionRatio_RejectsZeroCompressedNonZeroUncompressed(t *testing.T) {
	t.Parallel()

	zipBytes := buildZip(t, map[string]zipEntrySpec{
		// This is not something zip.Writer will produce, so we patch headers after.
		"weird.bin": {data: []byte("not empty"), method: zip.Deflate},
	})

	zipBytes = forceZipSizes(t, zipBytes, "weird.bin" /*compressed*/, 0 /*uncompressed*/, 123)

	reader := mustZipReader(t, zipBytes)

	err := CheckCompressionRatio(reader, 100)
	if err == nil {
		t.Fatalf("expected an error, got nil")
	}
	if !strings.Contains(err.Error(), "suspicious zip entry") {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(err.Error(), "weird.bin") {
		t.Fatalf("expected entry name in error, got: %v", err)
	}
}

type zipEntrySpec struct {
	data   []byte
	method uint16
	isDir  bool
}

func buildZip(t *testing.T, entries map[string]zipEntrySpec) []byte {
	t.Helper()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	for name, spec := range entries {
		if spec.isDir {
			// zip directories are typically entries ending in "/"
			if !strings.HasSuffix(name, "/") {
				name += "/"
			}
			h := &zip.FileHeader{
				Name:   name,
				Method: zip.Store,
			}
			h.SetMode(0o755 | 0o040000) // dir bit
			if _, err := zw.CreateHeader(h); err != nil {
				t.Fatalf("CreateHeader(%q): %v", name, err)
			}
			continue
		}

		h := &zip.FileHeader{
			Name:   name,
			Method: spec.method,
		}
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatalf("CreateHeader(%q): %v", name, err)
		}
		if _, err := w.Write(spec.data); err != nil {
			t.Fatalf("write(%q): %v", name, err)
		}
	}

	if err := zw.Close(); err != nil {
		t.Fatalf("Close zip writer: %v", err)
	}
	return buf.Bytes()
}

func mustZipReader(t *testing.T, zipBytes []byte) *zip.Reader {
	t.Helper()

	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("zip.NewReader: %v", err)
	}
	return zr
}

// forceZipSizes patches the central directory header fields so that the zip.Reader
// sees the provided compressed/uncompressed sizes for the named entry.
// This lets us test impossible headers that zip.Writer won't emit.
func forceZipSizes(t *testing.T, zipBytes []byte, filename string, compressedSize, uncompressedSize uint32) []byte {
	t.Helper()

	// Central directory file header signature = 0x02014b50
	// Local file header signature = 0x04034b50
	// We'll patch the central directory entry for `filename`.
	const (
		cdSignature = 0x02014b50
	)

	b := make([]byte, len(zipBytes))
	copy(b, zipBytes)

	// Minimal parser: scan for central directory headers, match filename, patch sizes.
	for i := 0; i+4 < len(b); i++ {
		if uint32(b[i])|uint32(b[i+1])<<8|uint32(b[i+2])<<16|uint32(b[i+3])<<24 != cdSignature {
			continue
		}

		// Offsets in central directory header (from APPNOTE.TXT):
		// 28: filename length (2)
		// 30: extra length (2)
		// 32: comment length (2)
		// 20: compressed size (4)
		// 24: uncompressed size (4)
		if i+46 > len(b) {
			break
		}

		fileNameLen := int(uint16(b[i+28]) | uint16(b[i+29])<<8)
		extraLen := int(uint16(b[i+30]) | uint16(b[i+31])<<8)
		commentLen := int(uint16(b[i+32]) | uint16(b[i+33])<<8)

		nameStart := i + 46
		nameEnd := nameStart + fileNameLen
		if nameEnd > len(b) {
			break
		}

		name := string(b[nameStart:nameEnd])
		if name != filename {
			// skip this CD entry
			i = nameEnd + extraLen + commentLen - 1
			continue
		}

		putU32LE(b[i+20:i+24], compressedSize)
		putU32LE(b[i+24:i+28], uncompressedSize)
		return b
	}

	t.Fatalf("central directory entry not found for %q", filename)
	return nil
}

func putU32LE(dst []byte, v uint32) {
	dst[0] = byte(v)
	dst[1] = byte(v >> 8)
	dst[2] = byte(v >> 16)
	dst[3] = byte(v >> 24)
}

func TestValidatePath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
		errMsg  string
	}{
		// Valid paths
		{name: "simple file", path: "file.txt"},
		{name: "nested path", path: "artifacts/data.json"},
		{name: "deeply nested", path: "artifacts/subdir/nested/file.json"},
		{name: "with dots in name", path: "artifacts/foo.bar.json"},
		{name: "double dot in name", path: "artifacts/foo..bar.json"},

		// Empty path
		{name: "empty path", path: "", wantErr: true, errMsg: "empty path"},

		// Control characters
		{name: "null byte", path: "file\x00.txt", wantErr: true, errMsg: "control character"},
		{name: "tab", path: "file\t.txt", wantErr: true, errMsg: "control character"},
		{name: "newline", path: "file\n.txt", wantErr: true, errMsg: "control character"},

		// Path traversal
		{name: "dot dot segment", path: "../etc/passwd", wantErr: true, errMsg: "traversal"},
		{name: "dot dot in middle", path: "artifacts/../etc/passwd", wantErr: true, errMsg: "traversal"},
		{name: "dot segment", path: "./file.txt", wantErr: true, errMsg: "traversal"},
		{name: "dot dot only", path: "..", wantErr: true, errMsg: "traversal"},
		{name: "dot only", path: ".", wantErr: true, errMsg: "traversal"},

		// Absolute paths
		{name: "leading slash", path: "/etc/passwd", wantErr: true, errMsg: "absolute path"},

		// Windows absolute paths
		{name: "Windows C drive", path: "C:\\Windows\\System32\\file.txt", wantErr: true, errMsg: "backslash"},
		{name: "Windows D drive forward slash", path: "D:/Users/file.txt", wantErr: true, errMsg: "Windows absolute path"},
		{name: "Windows lowercase drive", path: "c:/temp/file.txt", wantErr: true, errMsg: "Windows absolute path"},
		{name: "Windows drive relative", path: "C:file.txt", wantErr: true, errMsg: "Windows absolute path"},

		// Backslashes are rejected outright
		{name: "backslash in path", path: "..\\etc\\passwd", wantErr: true, errMsg: "backslash"},
		{name: "backslash simple", path: "artifacts\\file.txt", wantErr: true, errMsg: "backslash"},

		// Length limits
		{name: "path too long", path: strings.Repeat("a", 241), wantErr: true, errMsg: "maximum length"},
		{name: "segment too long", path: "artifacts/" + strings.Repeat("a", 81), wantErr: true, errMsg: "segment exceeds"},

		// Windows reserved names (bare names AND with extensions are reserved)
		// On Windows, "CON.txt", "aux.log", etc. all map to device files.
		{name: "CON reserved", path: "artifacts/CON", wantErr: true, errMsg: "Windows reserved"},
		{name: "con lowercase", path: "artifacts/con", wantErr: true, errMsg: "Windows reserved"},
		{name: "CON.txt reserved", path: "artifacts/CON.txt", wantErr: true, errMsg: "Windows reserved"},
		{name: "PRN reserved", path: "PRN", wantErr: true, errMsg: "Windows reserved"},
		{name: "COM1 reserved", path: "COM1", wantErr: true, errMsg: "Windows reserved"},
		{name: "LPT1 reserved", path: "LPT1", wantErr: true, errMsg: "Windows reserved"},
		{name: "NUL reserved", path: "NUL", wantErr: true, errMsg: "Windows reserved"},
		{name: "con.json reserved", path: "artifacts/con.json", wantErr: true, errMsg: "Windows reserved"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePath(tt.path)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidatePath(%q) expected error containing %q, got nil", tt.path, tt.errMsg)
					return
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidatePath(%q) error = %q, want error containing %q", tt.path, err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("ValidatePath(%q) unexpected error = %v", tt.path, err)
				}
			}
		})
	}
}

// Additional ValidatePath tests for edge cases

func TestValidatePath_UNCPaths(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"UNC path", "//server/share/file.txt"},
		{"UNC with backslash", "\\\\server\\share\\file.txt"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePath(tt.path)
			if err == nil {
				t.Errorf("ValidatePath(%q) should reject UNC paths", tt.path)
			}
		})
	}
}

func TestValidatePath_Colons(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"colon in middle", "file:name.txt"},
		{"colon in directory", "dir:ectory/file.txt"},
		{"NTFS alternate stream", "file.txt:Zone.Identifier"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePath(tt.path)
			if err == nil {
				t.Errorf("ValidatePath(%q) should reject paths with colons", tt.path)
			}
			if err != nil && !strings.Contains(err.Error(), "colon") {
				t.Errorf("ValidatePath(%q) error should mention colon: %v", tt.path, err)
			}
		})
	}
}

func TestValidatePath_TrailingSlash(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"trailing slash", "artifacts/"},
		{"nested trailing slash", "artifacts/subdir/"},
		{"just slash", "/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePath(tt.path)
			if err == nil {
				t.Errorf("ValidatePath(%q) should reject paths with trailing slash", tt.path)
			}
		})
	}
}

func TestValidatePath_ConsecutiveSlashes(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"double slash", "artifacts//file.txt"},
		{"triple slash", "a///b"},
		{"slash in middle", "a/b//c/d"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePath(tt.path)
			if err == nil {
				t.Errorf("ValidatePath(%q) should reject consecutive slashes", tt.path)
			}
			if err != nil && !strings.Contains(err.Error(), "empty segment") {
				t.Errorf("ValidatePath(%q) error should mention empty segment: %v", tt.path, err)
			}
		})
	}
}

func TestValidatePath_ControlCharacters(t *testing.T) {
	// Test all control characters 0x00-0x1F and 0x7F
	for i := 0; i < 32; i++ {
		t.Run(string(rune(i)), func(t *testing.T) {
			path := "file" + string(rune(i)) + ".txt"
			err := ValidatePath(path)
			if err == nil {
				t.Errorf("ValidatePath with control char 0x%02x should error", i)
			}
		})
	}
	// DEL character (0x7F)
	t.Run("DEL", func(t *testing.T) {
		path := "file\x7f.txt"
		err := ValidatePath(path)
		if err == nil {
			t.Error("ValidatePath with DEL character should error")
		}
	})
}

func TestValidatePath_UnicodeNormalization(t *testing.T) {
	// NFC: é as single codepoint U+00E9
	nfcPath := "caf\u00e9.txt"
	// NFD: é as e + combining acute U+0065 U+0301
	nfdPath := "cafe\u0301.txt"

	t.Run("NFC normalized", func(t *testing.T) {
		err := ValidatePath(nfcPath)
		if err != nil {
			t.Errorf("ValidatePath(%q) should accept NFC: %v", nfcPath, err)
		}
	})

	t.Run("NFD not normalized", func(t *testing.T) {
		err := ValidatePath(nfdPath)
		if err == nil {
			t.Errorf("ValidatePath(%q) should reject NFD (not NFC)", nfdPath)
		}
		if err != nil && !strings.Contains(err.Error(), "NFC") {
			t.Errorf("ValidatePath error should mention NFC: %v", err)
		}
	})
}

func TestValidatePath_AllWindowsReservedNames(t *testing.T) {
	reserved := []string{
		"CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
	}

	for _, name := range reserved {
		// Test uppercase
		t.Run(name, func(t *testing.T) {
			err := ValidatePath(name)
			if err == nil {
				t.Errorf("ValidatePath(%q) should reject Windows reserved name", name)
			}
		})

		// Test lowercase
		t.Run(strings.ToLower(name), func(t *testing.T) {
			err := ValidatePath(strings.ToLower(name))
			if err == nil {
				t.Errorf("ValidatePath(%q) should reject Windows reserved name (lowercase)", strings.ToLower(name))
			}
		})

		// Test mixed case
		if len(name) > 1 {
			mixed := strings.ToLower(name[:1]) + strings.ToUpper(name[1:])
			t.Run(mixed, func(t *testing.T) {
				err := ValidatePath(mixed)
				if err == nil {
					t.Errorf("ValidatePath(%q) should reject Windows reserved name (mixed case)", mixed)
				}
			})
		}

		// Test with extension (should be REJECTED - on Windows, CON.txt maps to CON device)
		withExt := name + ".txt"
		t.Run(withExt+"_reserved", func(t *testing.T) {
			err := ValidatePath(withExt)
			if err == nil {
				t.Errorf("ValidatePath(%q) should reject reserved name with extension (maps to device on Windows)", withExt)
			}
		})
	}
}

func TestValidatePath_LengthBoundaries(t *testing.T) {
	// Test exactly at path length limit with multiple valid segments
	// Path: "aaaa/.../file" where total length is exactly MaxPathLength (240)
	// Each segment must be <= MaxSegmentLength (80)
	t.Run("path exactly at limit", func(t *testing.T) {
		// Build path with valid segment lengths that totals MaxPathLength
		// 79 + 1 + 79 + 1 + 79 = 239, need exactly 240
		// Use: 79 + "/" + 79 + "/" + 80 = 240
		path := strings.Repeat("a", 79) + "/" + strings.Repeat("b", 79) + "/" + strings.Repeat("c", 80)
		if len(path) != MaxPathLength {
			t.Fatalf("Test path length is %d, expected %d", len(path), MaxPathLength)
		}
		err := ValidatePath(path)
		if err != nil {
			t.Errorf("ValidatePath with path length %d should succeed: %v", MaxPathLength, err)
		}
	})

	// Test one over path length limit
	t.Run("path one over limit", func(t *testing.T) {
		// 79 + "/" + 79 + "/" + 80 + "x" = 241
		path := strings.Repeat("a", 79) + "/" + strings.Repeat("b", 79) + "/" + strings.Repeat("c", 80) + "x"
		if len(path) != MaxPathLength+1 {
			t.Fatalf("Test path length is %d, expected %d", len(path), MaxPathLength+1)
		}
		err := ValidatePath(path)
		if err == nil {
			t.Errorf("ValidatePath with path length %d should fail", MaxPathLength+1)
		}
	})

	// Test exactly at segment length limit
	t.Run("segment exactly at limit", func(t *testing.T) {
		path := "dir/" + strings.Repeat("a", MaxSegmentLength)
		err := ValidatePath(path)
		if err != nil {
			t.Errorf("ValidatePath with segment length %d should succeed: %v", MaxSegmentLength, err)
		}
	})

	// Test one over segment length limit
	t.Run("segment one over limit", func(t *testing.T) {
		path := "dir/" + strings.Repeat("a", MaxSegmentLength+1)
		err := ValidatePath(path)
		if err == nil {
			t.Errorf("ValidatePath with segment length %d should fail", MaxSegmentLength+1)
		}
	})
}

// Additional CheckCompressionRatio tests

func TestCheckCompressionRatio_DefaultRatio(t *testing.T) {
	// Verify default ratio is used when maxRatio <= 0
	zipBytes := buildZip(t, map[string]zipEntrySpec{
		"normal.txt": {data: []byte("hello world"), method: zip.Store},
	})
	reader := mustZipReader(t, zipBytes)

	// Pass 0 or negative to use default
	if err := CheckCompressionRatio(reader, 0); err != nil {
		t.Errorf("CheckCompressionRatio with 0 should use default: %v", err)
	}
	if err := CheckCompressionRatio(reader, -1); err != nil {
		t.Errorf("CheckCompressionRatio with -1 should use default: %v", err)
	}
}

func TestCheckCompressionRatio_ExactlyAtLimit(t *testing.T) {
	// Create a file with exactly 100:1 ratio (at the default limit)
	// This is tricky because compression is not predictable, so we use Store method
	// and patch the sizes directly
	zipBytes := buildZip(t, map[string]zipEntrySpec{
		"exact.bin": {data: []byte("x"), method: zip.Store},
	})

	// Patch to have 10 compressed, 1000 uncompressed = exactly 100:1
	zipBytes = forceZipSizes(t, zipBytes, "exact.bin", 10, 1000)
	reader := mustZipReader(t, zipBytes)

	// Exactly at limit should pass
	err := CheckCompressionRatio(reader, 100)
	if err != nil {
		t.Errorf("CheckCompressionRatio at exact 100:1 limit should pass: %v", err)
	}
}

func TestCheckCompressionRatio_JustOverLimit(t *testing.T) {
	zipBytes := buildZip(t, map[string]zipEntrySpec{
		"over.bin": {data: []byte("x"), method: zip.Store},
	})

	// Patch to have 10 compressed, 1001 uncompressed = 100.1:1 (just over)
	zipBytes = forceZipSizes(t, zipBytes, "over.bin", 10, 1001)
	reader := mustZipReader(t, zipBytes)

	err := CheckCompressionRatio(reader, 100)
	if err == nil {
		t.Error("CheckCompressionRatio at 100.1:1 should fail with 100:1 limit")
	}
}

func TestCheckCompressionRatio_SkipsDirectories(t *testing.T) {
	zipBytes := buildZip(t, map[string]zipEntrySpec{
		"dir/":     {isDir: true},
		"dir/a/":   {isDir: true},
		"dir/a/b/": {isDir: true},
		"file.txt": {data: []byte("ok"), method: zip.Store},
	})
	reader := mustZipReader(t, zipBytes)

	// Directories should be skipped without error
	if err := CheckCompressionRatio(reader, 1); err != nil {
		t.Errorf("CheckCompressionRatio should skip directories: %v", err)
	}
}

func TestCheckCompressionRatio_EmptyArchive(t *testing.T) {
	zipBytes := buildZip(t, map[string]zipEntrySpec{})
	reader := mustZipReader(t, zipBytes)

	if err := CheckCompressionRatio(reader, 100); err != nil {
		t.Errorf("CheckCompressionRatio on empty archive should pass: %v", err)
	}
}

func TestCheckCompressionRatio_MultipleFiles(t *testing.T) {
	// One good file, one bad file
	highlyCompressible := bytes.Repeat([]byte("A"), 100*1024)
	zipBytes := buildZip(t, map[string]zipEntrySpec{
		"good.txt": {data: []byte("hello"), method: zip.Store},
		"bad.txt":  {data: highlyCompressible, method: zip.Deflate},
	})
	reader := mustZipReader(t, zipBytes)

	err := CheckCompressionRatio(reader, 2)
	if err == nil {
		t.Error("CheckCompressionRatio should fail if any file exceeds limit")
	}
	if err != nil && !strings.Contains(err.Error(), "bad.txt") {
		t.Errorf("Error should mention the problematic file 'bad.txt': %v", err)
	}
}

func TestExceedsCompressionRatioLimit(t *testing.T) {
	tests := []struct {
		name         string
		uncompressed uint64
		compressed   uint64
		maxRatio     uint64
		want         bool
	}{
		{"1:1 ratio within 100:1", 100, 100, 100, false},
		{"100:1 exactly", 100, 1, 100, false},
		{"101:1 over limit", 101, 1, 100, true},
		{"100.5:1 over limit", 201, 2, 100, true},
		{"50:1 within 100:1", 50, 1, 100, false},
		{"large values within limit", 1000000000, 10000000, 100, false},
		{"large values at limit", 10000000000, 100000000, 100, false},
		{"large values over limit", 10000000001, 100000000, 100, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := exceedsCompressionRatioLimit(tt.uncompressed, tt.compressed, tt.maxRatio)
			if got != tt.want {
				t.Errorf("exceedsCompressionRatioLimit(%d, %d, %d) = %v, want %v",
					tt.uncompressed, tt.compressed, tt.maxRatio, got, tt.want)
			}
		})
	}
}

func TestIsTrulyEmpty(t *testing.T) {
	tests := []struct {
		compressed   uint64
		uncompressed uint64
		want         bool
	}{
		{0, 0, true},
		{0, 1, false},
		{1, 0, false},
		{1, 1, false},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			got := isTrulyEmpty(tt.compressed, tt.uncompressed)
			if got != tt.want {
				t.Errorf("isTrulyEmpty(%d, %d) = %v, want %v",
					tt.compressed, tt.uncompressed, got, tt.want)
			}
		})
	}
}

// Tests for ValidateDirectoryEntry

func TestValidateDirectoryEntry(t *testing.T) {
	t.Run("valid directory with trailing slash", func(t *testing.T) {
		zipBytes := buildZip(t, map[string]zipEntrySpec{
			"dir/": {isDir: true},
		})
		reader := mustZipReader(t, zipBytes)
		for _, f := range reader.File {
			if err := ValidateDirectoryEntry(f); err != nil {
				t.Errorf("ValidateDirectoryEntry(%q) unexpected error: %v", f.Name, err)
			}
		}
	})

	t.Run("valid file without trailing slash", func(t *testing.T) {
		zipBytes := buildZip(t, map[string]zipEntrySpec{
			"file.txt": {data: []byte("hello"), method: zip.Store},
		})
		reader := mustZipReader(t, zipBytes)
		for _, f := range reader.File {
			if err := ValidateDirectoryEntry(f); err != nil {
				t.Errorf("ValidateDirectoryEntry(%q) unexpected error: %v", f.Name, err)
			}
		}
	})
}

// Tests for IsAppleDoubleFile

func TestIsAppleDoubleFile(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		// AppleDouble files - should be detected
		{name: "__MACOSX directory", path: "__MACOSX/file.txt", want: true},
		{name: "__MACOSX nested", path: "__MACOSX/artifacts/._file.txt", want: true},
		{name: "dotunderscore at root", path: "._file.txt", want: true},
		{name: "dotunderscore in subdir", path: "artifacts/._document.pdf", want: true},
		{name: "dotunderscore nested deep", path: "a/b/c/._hidden", want: true},

		// Valid files - should NOT be detected as AppleDouble
		{name: "normal file", path: "file.txt", want: false},
		{name: "dotfile", path: ".gitignore", want: false},
		{name: "nested normal", path: "artifacts/data.json", want: false},
		{name: "underscore prefix", path: "_internal/config.yaml", want: false},
		{name: "double underscore", path: "__init__.py", want: false},
		{name: "dot only", path: "artifacts/.hidden", want: false},
		{name: "MACOSX not at root", path: "artifacts/__MACOSX/file", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsAppleDoubleFile(tt.path)
			if got != tt.want {
				t.Errorf("IsAppleDoubleFile(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestValidateNotAppleDouble(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{name: "__MACOSX", path: "__MACOSX/file.txt", wantErr: true},
		{name: "dotunderscore", path: "artifacts/._file.txt", wantErr: true},
		{name: "normal file", path: "artifacts/file.txt", wantErr: false},
		{name: "dotfile", path: ".gitignore", wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateNotAppleDouble(tt.path)
			if tt.wantErr && err == nil {
				t.Errorf("ValidateNotAppleDouble(%q) expected error, got nil", tt.path)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateNotAppleDouble(%q) unexpected error: %v", tt.path, err)
			}
		})
	}
}

// Tests for ValidateNotSymlink and ValidateNotDeviceFile
// These require creating ZIP files with special mode bits

func TestValidateNotSymlink(t *testing.T) {
	// Create a ZIP with a normal file
	zipBytes := buildZip(t, map[string]zipEntrySpec{
		"normal.txt": {data: []byte("hello"), method: zip.Store},
	})
	reader := mustZipReader(t, zipBytes)

	for _, f := range reader.File {
		if err := ValidateNotSymlink(f); err != nil {
			t.Errorf("ValidateNotSymlink(%q) should accept normal file: %v", f.Name, err)
		}
	}
}

func TestValidateNotDeviceFile(t *testing.T) {
	// Create a ZIP with a normal file
	zipBytes := buildZip(t, map[string]zipEntrySpec{
		"normal.txt": {data: []byte("hello"), method: zip.Store},
	})
	reader := mustZipReader(t, zipBytes)

	for _, f := range reader.File {
		if err := ValidateNotDeviceFile(f); err != nil {
			t.Errorf("ValidateNotDeviceFile(%q) should accept normal file: %v", f.Name, err)
		}
	}
}
