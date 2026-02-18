package ziputil

import (
	"archive/zip"
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestNewSafeReader_ValidArchive(t *testing.T) {
	// Create a valid test archive
	buf := createTestZip(t, map[string]string{
		"file1.txt":     "content1",
		"dir/file2.txt": "content2",
	})

	sr, err := NewSafeReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil {
		t.Fatalf("NewSafeReader failed: %v", err)
	}

	if !sr.IsValidated() {
		t.Error("expected IsValidated() to return true")
	}

	names := sr.FileNames()
	if len(names) != 2 {
		t.Errorf("expected 2 files, got %d", len(names))
	}
}

func TestNewSafeReader_PathTraversal(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"dot-dot", "../etc/passwd"},
		{"hidden-dot-dot", "foo/../../../etc/passwd"},
		{"backslash", "foo\\bar.txt"},
		{"absolute", "/etc/passwd"},
		{"windows-absolute", "C:/Windows/System32"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buf := createTestZipUnsafe(t, map[string]string{
				tc.path: "malicious",
			})

			_, err := NewSafeReader(bytes.NewReader(buf), int64(len(buf)))
			if err == nil {
				t.Errorf("expected error for path %q, got nil", tc.path)
			}
		})
	}
}

func TestNewSafeReader_WindowsCollision(t *testing.T) {
	// Create archive with case-different paths that collide on Windows
	buf := createTestZipUnsafe(t, map[string]string{
		"File.txt": "content1",
		"file.txt": "content2", // Collides with File.txt on Windows
	})

	_, err := NewSafeReader(bytes.NewReader(buf), int64(len(buf)))
	if err == nil {
		t.Error("expected Windows collision error, got nil")
	}
	if !strings.Contains(err.Error(), "collision") {
		t.Errorf("expected collision error, got: %v", err)
	}
}

func TestNewSafeReader_WindowsCollision_Disabled(t *testing.T) {
	buf := createTestZipUnsafe(t, map[string]string{
		"File.txt": "content1",
		"file.txt": "content2",
	})

	sr, err := NewSafeReader(bytes.NewReader(buf), int64(len(buf)), WithSkipCollisionCheck())
	if err != nil {
		t.Fatalf("expected no error with collision check disabled, got: %v", err)
	}
	if !sr.IsValidated() {
		t.Error("expected IsValidated() to return true")
	}
}

func TestNewSafeReader_EntryLimit(t *testing.T) {
	files := make(map[string]string)
	for i := 0; i < 100; i++ {
		files[strings.Repeat("a", 10)+string(rune('0'+i/10))+string(rune('0'+i%10))+".txt"] = "x"
	}
	buf := createTestZip(t, files)

	// Should fail with very low limit
	_, err := NewSafeReader(bytes.NewReader(buf), int64(len(buf)), WithMaxEntries(10))
	if err == nil {
		t.Error("expected entry limit error, got nil")
	}

	// Should succeed with normal limit
	sr, err := NewSafeReader(bytes.NewReader(buf), int64(len(buf)), WithMaxEntries(1000))
	if err != nil {
		t.Fatalf("expected success with higher limit, got: %v", err)
	}
	if len(sr.FileNames()) != 100 {
		t.Errorf("expected 100 files, got %d", len(sr.FileNames()))
	}
}

func TestNewSafeReader_OpenFile(t *testing.T) {
	buf := createTestZip(t, map[string]string{
		"test.txt": "hello world",
	})

	sr, err := NewSafeReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil {
		t.Fatalf("NewSafeReader failed: %v", err)
	}

	rc, err := sr.OpenFile("test.txt")
	if err != nil {
		t.Fatalf("OpenFile failed: %v", err)
	}
	defer func() { _ = rc.Close() }()

	content, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if string(content) != "hello world" {
		t.Errorf("expected 'hello world', got %q", string(content))
	}
}

func TestNewSafeReader_OpenFile_NotFound(t *testing.T) {
	buf := createTestZip(t, map[string]string{
		"exists.txt": "content",
	})

	sr, err := NewSafeReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil {
		t.Fatalf("NewSafeReader failed: %v", err)
	}

	_, err = sr.OpenFile("notfound.txt")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestNewSafeReaderFromZip(t *testing.T) {
	buf := createTestZip(t, map[string]string{
		"file.txt": "content",
	})

	zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil {
		t.Fatalf("zip.NewReader failed: %v", err)
	}

	sr, err := NewSafeReaderFromZip(zr)
	if err != nil {
		t.Fatalf("NewSafeReaderFromZip failed: %v", err)
	}

	if !sr.IsValidated() {
		t.Error("expected IsValidated() to return true")
	}
}

func TestNewSafeReader_ReservedNames(t *testing.T) {
	reservedNames := []string{"con.txt", "prn.log", "aux.dat", "nul", "com1.txt", "lpt1.txt"}

	for _, name := range reservedNames {
		t.Run(name, func(t *testing.T) {
			buf := createTestZipUnsafe(t, map[string]string{
				name: "content",
			})

			_, err := NewSafeReader(bytes.NewReader(buf), int64(len(buf)))
			if err == nil {
				t.Errorf("expected error for reserved name %q", name)
			}
		})
	}
}

// createTestZip creates a valid test zip archive with validated paths.
func createTestZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	for name, content := range files {
		// Validate path before adding
		if err := ValidatePath(name); err != nil {
			t.Fatalf("invalid test path %q: %v", name, err)
		}
		f, err := w.Create(name)
		if err != nil {
			t.Fatalf("Create(%q) failed: %v", name, err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatalf("Write to %q failed: %v", name, err)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatalf("zip.Writer.Close failed: %v", err)
	}
	return buf.Bytes()
}

// createTestZipUnsafe creates a test zip with unvalidated paths (for testing rejection).
func createTestZipUnsafe(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	for name, content := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatalf("Create(%q) failed: %v", name, err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatalf("Write to %q failed: %v", name, err)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatalf("zip.Writer.Close failed: %v", err)
	}
	return buf.Bytes()
}
