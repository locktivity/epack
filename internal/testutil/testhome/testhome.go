// Package testhome points os.UserHomeDir at a temporary directory for the
// duration of a test, so nothing under ~/.epack on the developer's machine
// or the CI runner leaks into a test or is written by one.
package testhome

import (
	"path/filepath"
	"testing"
)

// Isolate sets the home directory to a fresh temporary directory and returns
// its symlink-resolved path. Go reads HOME on Unix and USERPROFILE on Windows,
// so both are set.
func Isolate(t *testing.T) string {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolving temp dir: %v", err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return home
}
