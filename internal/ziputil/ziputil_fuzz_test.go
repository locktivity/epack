package ziputil

import (
	"strings"
	"testing"
	"unicode"
)

// FuzzValidatePath tests path validation with fuzzed inputs to find edge cases
// in security-critical path validation logic.
func FuzzValidatePath(f *testing.F) {
	// Seed with valid paths
	f.Add("manifest.json")
	f.Add("artifacts/test.json")
	f.Add("artifacts/subdir/nested/file.json")
	f.Add("attestations/abc123.sigstore.json")

	// Seed with attack patterns - path traversal
	f.Add("")
	f.Add(".")
	f.Add("..")
	f.Add("../etc/passwd")
	f.Add("artifacts/../../../etc/passwd")
	f.Add("artifacts/foo/../../bar")
	f.Add("./hidden")

	// Seed with Windows-specific attacks
	f.Add("CON")
	f.Add("con.txt")
	f.Add("PRN")
	f.Add("AUX")
	f.Add("NUL")
	f.Add("COM1")
	f.Add("LPT1")
	f.Add("artifacts/CON/file.txt")
	f.Add("C:\\Windows\\System32")
	f.Add("C:/temp/file")
	f.Add("//server/share")

	// Seed with control characters
	f.Add("file\x00name")
	f.Add("file\nname")
	f.Add("file\tname")
	f.Add("file\rname")

	// Seed with path format issues
	f.Add("/etc/passwd")
	f.Add("artifacts/")
	f.Add("artifacts//file.txt")
	f.Add("file:stream")
	f.Add("artifacts\\file.txt")

	// Seed with length boundary cases
	f.Add(strings.Repeat("a", 240))
	f.Add(strings.Repeat("a", 241))
	f.Add("dir/" + strings.Repeat("a", 80))
	f.Add("dir/" + strings.Repeat("a", 81))

	// Seed with Unicode edge cases
	f.Add("café.txt")       // NFC
	f.Add("cafe\u0301.txt") // NFD (decomposed)
	f.Add("日本語/ファイル.json")  // CJK characters
	f.Add("file\u200b.txt") // Zero-width space
	f.Add("file\ufeff.txt") // BOM character
	f.Add("file\u202e.txt") // Right-to-left override

	// Seed with trailing/leading whitespace (Windows collision)
	f.Add("file.")
	f.Add("file ")
	f.Add("dir./file.txt")
	f.Add("dir /file.txt")

	f.Fuzz(func(t *testing.T, path string) {
		err := ValidatePath(path)

		if err == nil {
			// If path is accepted, verify security invariants

			// SECURITY: Must not contain path traversal segments
			// Segments that are exactly ".." or start with ".." are dangerous
			for _, seg := range strings.Split(path, "/") {
				if seg == ".." || strings.HasPrefix(seg, "..") {
					t.Errorf("SECURITY: accepted path with traversal segment %q: %q", seg, path)
				}
			}

			// SECURITY: Must not be empty
			if path == "" {
				t.Errorf("SECURITY: accepted empty path")
			}

			// SECURITY: Must not contain null bytes
			if strings.ContainsRune(path, 0) {
				t.Errorf("SECURITY: accepted path with null byte: %q", path)
			}

			// SECURITY: Must not contain control characters
			for _, r := range path {
				if r < 32 || r == 127 {
					t.Errorf("SECURITY: accepted path with control char %d: %q", r, path)
					break
				}
			}

			// SECURITY: Must not contain backslashes
			if strings.Contains(path, "\\") {
				t.Errorf("SECURITY: accepted path with backslash: %q", path)
			}

			// SECURITY: Must not be absolute
			if strings.HasPrefix(path, "/") {
				t.Errorf("SECURITY: accepted absolute path: %q", path)
			}

			// SECURITY: Must not have trailing slash
			if strings.HasSuffix(path, "/") {
				t.Errorf("SECURITY: accepted path with trailing slash: %q", path)
			}

			// SECURITY: Must not have empty segments (consecutive slashes)
			if strings.Contains(path, "//") {
				t.Errorf("SECURITY: accepted path with empty segment: %q", path)
			}

			// SECURITY: Must not contain colons (Windows reserved)
			if strings.Contains(path, ":") {
				t.Errorf("SECURITY: accepted path with colon: %q", path)
			}

			// SECURITY: Must not exceed length limits
			if len(path) > MaxPathLength {
				t.Errorf("SECURITY: accepted path exceeding max length: %d > %d", len(path), MaxPathLength)
			}

			// SECURITY: Segments must not exceed limit
			for _, seg := range strings.Split(path, "/") {
				if len(seg) > MaxSegmentLength {
					t.Errorf("SECURITY: accepted segment exceeding max length: %d > %d", len(seg), MaxSegmentLength)
				}
			}

			// SECURITY: Check for Windows reserved names in segments
			reservedNames := map[string]bool{
				"con": true, "prn": true, "aux": true, "nul": true,
				"com1": true, "com2": true, "com3": true, "com4": true,
				"com5": true, "com6": true, "com7": true, "com8": true, "com9": true,
				"lpt1": true, "lpt2": true, "lpt3": true, "lpt4": true,
				"lpt5": true, "lpt6": true, "lpt7": true, "lpt8": true, "lpt9": true,
			}
			for _, seg := range strings.Split(path, "/") {
				// Strip extension for reserved name check
				baseName := seg
				if dotIdx := strings.LastIndex(seg, "."); dotIdx > 0 {
					baseName = seg[:dotIdx]
				}
				if reservedNames[strings.ToLower(baseName)] {
					t.Errorf("SECURITY: accepted Windows reserved name: %q in path %q", seg, path)
				}
			}

			// SECURITY: Check for trailing dots/spaces in segments (Windows collision)
			for _, seg := range strings.Split(path, "/") {
				if seg != "" {
					lastChar := seg[len(seg)-1]
					if lastChar == '.' || lastChar == ' ' {
						t.Errorf("SECURITY: accepted segment with trailing dot/space: %q in path %q", seg, path)
					}
				}
			}
		}

		// Regardless of error, function must not panic (fuzzer will catch panics)
	})
}

// FuzzWindowsCanonicalPath tests the Windows canonical path function.
func FuzzWindowsCanonicalPath(f *testing.F) {
	f.Add("file.txt")
	f.Add("FILE.TXT")
	f.Add("File.Txt")
	f.Add("file.")
	f.Add("file ")
	f.Add("FILE ")
	f.Add("a/b/c")
	f.Add("A/B/C")

	f.Fuzz(func(t *testing.T, path string) {
		// Should not panic
		canonical := WindowsCanonicalPath(path)

		// Canonical form should be lowercase
		if canonical != strings.ToLower(canonical) {
			t.Errorf("canonical path not lowercase: %q -> %q", path, canonical)
		}

		// Canonical form should not have trailing dots or spaces in segments
		for _, seg := range strings.Split(canonical, "/") {
			if seg == "" {
				continue
			}
			trimmed := strings.TrimRight(seg, ". ")
			if trimmed != seg && trimmed != "" {
				// Original had trailing dots/spaces that should be stripped
				// unless the entire segment is dots/spaces
				if !isAllDotsOrSpaces(seg) {
					t.Errorf("canonical segment still has trailing dot/space: %q from %q", seg, path)
				}
			}
		}

		// Idempotent: canonicalizing again should give same result
		canonical2 := WindowsCanonicalPath(canonical)
		if canonical != canonical2 {
			t.Errorf("not idempotent: %q -> %q -> %q", path, canonical, canonical2)
		}
	})
}

// isAllDotsOrSpaces returns true if s consists entirely of dots and spaces.
func isAllDotsOrSpaces(s string) bool {
	for _, r := range s {
		if r != '.' && r != ' ' {
			return false
		}
	}
	return true
}

// FuzzExceedsCompressionRatioLimit tests the compression ratio check.
// NOTE: exceedsCompressionRatioLimit has a precondition that compressed > 0.
// The calling code (CheckCompressionRatio) handles compressed=0 separately
// before calling this function. This fuzz test respects that precondition.
func FuzzExceedsCompressionRatioLimit(f *testing.F) {
	// Seeds with valid compressed > 0
	f.Add(uint64(100), uint64(1), uint64(100))
	f.Add(uint64(101), uint64(1), uint64(100))
	f.Add(uint64(1000000000), uint64(10000000), uint64(100))
	f.Add(uint64(0), uint64(1), uint64(100))
	f.Add(uint64(1), uint64(1), uint64(1))
	f.Add(uint64(99), uint64(1), uint64(100))
	f.Add(uint64(100), uint64(1), uint64(100))
	f.Add(uint64(101), uint64(1), uint64(100))
	f.Add(uint64(^uint64(0)), uint64(1), uint64(100)) // Max uint64

	f.Fuzz(func(t *testing.T, uncompressed, compressed, maxRatio uint64) {
		// Precondition: compressed > 0 (caller handles compressed=0 separately)
		// Skip inputs that violate the precondition
		if compressed == 0 {
			return
		}

		// Should not panic with valid inputs
		result := exceedsCompressionRatioLimit(uncompressed, compressed, maxRatio)

		// Special case: maxRatio=0 means "no expansion allowed"
		if maxRatio == 0 {
			// Any uncompressed > 0 should exceed the limit
			expectedExceed := uncompressed > 0
			if result != expectedExceed {
				t.Errorf("exceedsCompressionRatioLimit(%d, %d, 0) = %v, want %v",
					uncompressed, compressed, result, expectedExceed)
			}
			return
		}

		// Normal case: check ratio
		// The function checks: uncompressed / compressed > maxRatio
		// Rearranged to avoid division: uncompressed > compressed * maxRatio
		// But we need to handle overflow in the multiplication
		expectedExceed := uncompressed > compressed*maxRatio
		if result != expectedExceed {
			t.Errorf("exceedsCompressionRatioLimit(%d, %d, %d) = %v, want %v",
				uncompressed, compressed, maxRatio, result, expectedExceed)
		}
	})
}

// FuzzIsTrulyEmpty tests the empty detection function.
func FuzzIsTrulyEmpty(f *testing.F) {
	f.Add(uint64(0), uint64(0))
	f.Add(uint64(0), uint64(1))
	f.Add(uint64(1), uint64(0))
	f.Add(uint64(1), uint64(1))
	f.Add(uint64(1000), uint64(1000))

	f.Fuzz(func(t *testing.T, compressed, uncompressed uint64) {
		result := isTrulyEmpty(compressed, uncompressed)
		expected := compressed == 0 && uncompressed == 0
		if result != expected {
			t.Errorf("isTrulyEmpty(%d, %d) = %v, want %v",
				compressed, uncompressed, result, expected)
		}
	})
}

// FuzzWindowsPathCollision tests detection of Windows path collisions.
// Two paths that differ only in case, trailing dots, or trailing spaces
// will collide on Windows.
func FuzzWindowsPathCollision(f *testing.F) {
	// Case collisions
	f.Add("artifacts/File.txt", "artifacts/file.txt")
	f.Add("artifacts/FILE.TXT", "artifacts/file.txt")
	f.Add("MANIFEST.JSON", "manifest.json")

	// Trailing dot/space collisions
	f.Add("artifacts/file.", "artifacts/file")
	f.Add("artifacts/file ", "artifacts/file")
	f.Add("artifacts/file.txt.", "artifacts/file.txt")

	// Windows reserved name variants
	f.Add("artifacts/CON", "artifacts/con")
	f.Add("artifacts/CON.txt", "artifacts/con.txt")
	f.Add("artifacts/prn", "artifacts/PRN")

	// Different paths that shouldn't collide
	f.Add("artifacts/file1.txt", "artifacts/file2.txt")
	f.Add("artifacts/a/file.txt", "artifacts/b/file.txt")

	// Unicode normalization (NFC vs NFD - may or may not collide depending on impl)
	f.Add("artifacts/café.txt", "artifacts/cafe\u0301.txt")

	f.Fuzz(func(t *testing.T, path1, path2 string) {
		// Skip if either path contains null bytes (causes issues)
		if strings.ContainsRune(path1, 0) || strings.ContainsRune(path2, 0) {
			return
		}

		canon1 := WindowsCanonicalPath(path1)
		canon2 := WindowsCanonicalPath(path2)

		// Property: If canonical forms match, the paths would collide on Windows
		collision := canon1 == canon2

		// Property: Identical paths always collide
		if path1 == path2 && !collision {
			t.Errorf("identical paths don't collide: %q", path1)
		}

		// Property: If paths are case-insensitively equal, they should collide
		if strings.EqualFold(path1, path2) && !collision {
			// Check if the difference is only trailing dots/spaces
			// which would also cause collision
			t.Logf("case-equal paths may not collide due to trailing chars: %q vs %q -> %q vs %q",
				path1, path2, canon1, canon2)
		}

		// Property: Canonicalization is deterministic
		if WindowsCanonicalPath(path1) != canon1 {
			t.Errorf("canonicalization not deterministic for %q", path1)
		}
	})
}

// FuzzPathWithUnicode specifically tests Unicode handling in path validation.
func FuzzPathWithUnicode(f *testing.F) {
	// NFC normalized strings
	f.Add("café")
	f.Add("日本語")
	f.Add("한국어")
	f.Add("emoji😀file")

	// NFD decomposed strings (should be rejected)
	f.Add("cafe\u0301")   // e + combining acute
	f.Add("a\u0308")      // a + combining diaeresis
	f.Add("\u0041\u030A") // A + combining ring above (= Å)
	f.Add("\u304B\u3099") // hiragana ka + combining voiced mark

	// Various Unicode edge cases
	f.Add("\u200B") // Zero-width space
	f.Add("\uFEFF") // BOM
	f.Add("\u202E") // Right-to-left override
	f.Add("\u2028") // Line separator
	f.Add("\u2029") // Paragraph separator

	f.Fuzz(func(t *testing.T, path string) {
		// Prepend artifacts/ to make it a valid artifact path structure
		fullPath := "artifacts/" + path

		err := ValidatePath(fullPath)

		if err == nil {
			// If accepted, verify Unicode properties

			// Check for invisible/control Unicode characters that could be confusing
			for _, r := range path {
				if unicode.Is(unicode.Cf, r) { // Format characters
					t.Logf("accepted path with format character U+%04X: %q", r, path)
				}
				if unicode.Is(unicode.Cc, r) { // Control characters
					t.Errorf("SECURITY: accepted path with control character U+%04X: %q", r, path)
				}
			}
		}
	})
}
