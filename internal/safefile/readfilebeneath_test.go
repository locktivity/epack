//go:build !windows

package safefile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/locktivity/epack/internal/limits"
)

func TestReadFileBeneath(t *testing.T) {
	baseDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(baseDir, "documents"), 0o700); err != nil {
		t.Fatal(err)
	}
	content := []byte("staged content")
	if err := os.WriteFile(filepath.Join(baseDir, "documents", "policy.pdf"), content, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("reads nested regular files", func(t *testing.T) {
		data, err := ReadFileBeneath(baseDir, "documents/policy.pdf", limits.Artifact)
		if err != nil {
			t.Fatalf("ReadFileBeneath failed: %v", err)
		}
		if string(data) != string(content) {
			t.Errorf("content mismatch: %q", data)
		}
	})

	t.Run("rejects leaf symlinks", func(t *testing.T) {
		if err := os.Symlink(filepath.Join(baseDir, "documents", "policy.pdf"), filepath.Join(baseDir, "leaf-link.pdf")); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadFileBeneath(baseDir, "leaf-link.pdf", limits.Artifact); err == nil {
			t.Fatal("expected error for leaf symlink")
		}
	})

	t.Run("rejects symlinked intermediate directories", func(t *testing.T) {
		outsideDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(outsideDir, "aliased.pdf"), []byte("outside"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outsideDir, filepath.Join(baseDir, "linked-dir")); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadFileBeneath(baseDir, "linked-dir/aliased.pdf", limits.Artifact); err == nil {
			t.Fatal("expected error for symlinked intermediate directory")
		}
	})

	// The staging root is collector-visible after emit.
	t.Run("rejects a symlinked base directory", func(t *testing.T) {
		realRoot := t.TempDir()
		if err := os.WriteFile(filepath.Join(realRoot, "policy.pdf"), []byte("real"), 0o600); err != nil {
			t.Fatal(err)
		}
		outsideDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(outsideDir, "policy.pdf"), []byte("host secret"), 0o600); err != nil {
			t.Fatal(err)
		}
		swappedRoot := filepath.Join(t.TempDir(), "staging")
		if err := os.Symlink(outsideDir, swappedRoot); err != nil {
			t.Fatal(err)
		}

		if _, err := ReadFileBeneath(swappedRoot, "policy.pdf", limits.Artifact); err == nil {
			t.Fatal("expected error when the base directory is a symlink")
		}
		if err := ValidateFileBeneath(swappedRoot, "policy.pdf"); err == nil {
			t.Fatal("expected ValidateFileBeneath to reject a symlinked base directory")
		}
	})

	t.Run("rejects escapes", func(t *testing.T) {
		for _, rel := range []string{"../outside.pdf", "/etc/passwd", "."} {
			if _, err := ReadFileBeneath(baseDir, rel, limits.Artifact); err == nil {
				t.Errorf("expected error for %q", rel)
			}
		}
	})

	t.Run("rejects missing files", func(t *testing.T) {
		if _, err := ReadFileBeneath(baseDir, "documents/absent.pdf", limits.Artifact); err == nil {
			t.Fatal("expected error for missing file")
		}
	})

	t.Run("rejects directories as leaves", func(t *testing.T) {
		if _, err := ReadFileBeneath(baseDir, "documents", limits.Artifact); err == nil {
			t.Fatal("expected error for directory leaf")
		}
	})
}

func TestOpenForWriteBeneath(t *testing.T) {
	baseDir := t.TempDir()

	t.Run("creates and writes nested files", func(t *testing.T) {
		f, err := OpenForWriteBeneath(baseDir, "documents/policy.pdf")
		if err != nil {
			t.Fatalf("OpenForWriteBeneath failed: %v", err)
		}
		if _, err := f.WriteString("content"); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		got, err := os.ReadFile(filepath.Join(baseDir, "documents", "policy.pdf"))
		if err != nil || string(got) != "content" {
			t.Errorf("content mismatch: %q err=%v", got, err)
		}
	})

	t.Run("rejects a symlinked parent", func(t *testing.T) {
		outside := t.TempDir()
		if err := os.Symlink(outside, filepath.Join(baseDir, "linked")); err != nil {
			t.Fatal(err)
		}
		if f, err := OpenForWriteBeneath(baseDir, "linked/x.pdf"); err == nil {
			_ = f.Close()
			t.Error("wrote through a symlinked parent")
		}
		if _, err := os.Stat(filepath.Join(outside, "x.pdf")); err == nil {
			t.Error("bytes escaped via the symlink")
		}
	})

	t.Run("rejects escapes", func(t *testing.T) {
		for _, rel := range []string{"../escape.pdf", "/abs.pdf", "."} {
			if f, err := OpenForWriteBeneath(baseDir, rel); err == nil {
				_ = f.Close()
				t.Errorf("expected error for %q", rel)
			}
		}
	})
}
