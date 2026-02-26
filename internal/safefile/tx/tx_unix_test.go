//go:build !windows

package tx

import (
	"os"
	"path/filepath"
	"testing"

	epackerrors "github.com/locktivity/epack/errors"
)

func TestWriteAtomicPath_WritesAndOverwrites(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "result.json")

	if err := WriteAtomicPath(path, []byte("one"), 0o644); err != nil {
		t.Fatalf("first write failed: %v", err)
	}
	if err := WriteAtomicPath(path, []byte("two"), 0o644); err != nil {
		t.Fatalf("second write failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading final file failed: %v", err)
	}
	if string(data) != "two" {
		t.Fatalf("unexpected final content: got %q, want %q", string(data), "two")
	}
}

func TestWriteAtomicPath_RefusesSymlinkDestination(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	target := filepath.Join(tmp, "target.txt")
	if err := os.WriteFile(target, []byte("target"), 0o644); err != nil {
		t.Fatalf("writing target failed: %v", err)
	}

	dest := filepath.Join(tmp, "result.json")
	if err := os.Symlink(target, dest); err != nil {
		t.Fatalf("creating symlink failed: %v", err)
	}

	err := WriteAtomicPath(dest, []byte("new"), 0o644)
	if err == nil {
		t.Fatal("expected symlink refusal error")
	}
	if epackerrors.CodeOf(err) != epackerrors.SymlinkNotAllowed {
		t.Fatalf("error code = %q, want %q (err=%v)", epackerrors.CodeOf(err), epackerrors.SymlinkNotAllowed, err)
	}
}

func TestWriteAtomicPath_RefusesSymlinkInDirectoryPath(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	realDir := filepath.Join(tmp, "real")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatalf("creating real directory failed: %v", err)
	}

	linkDir := filepath.Join(tmp, "link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatalf("creating directory symlink failed: %v", err)
	}

	err := WriteAtomicPath(filepath.Join(linkDir, "result.json"), []byte("x"), 0o644)
	if err == nil {
		t.Fatal("expected symlink refusal error")
	}
	if epackerrors.CodeOf(err) != epackerrors.SymlinkNotAllowed {
		t.Fatalf("error code = %q, want %q (err=%v)", epackerrors.CodeOf(err), epackerrors.SymlinkNotAllowed, err)
	}
}
