//go:build components

package componentcmd

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFindLastPush_FindsLatestNestedReceiptByCreatedAt(t *testing.T) {
	projectRoot := t.TempDir()
	olderPath := filepath.Join(projectRoot, ".epack", "receipts", "push", "alpha", "20260313_110000_old.json")
	newerPath := filepath.Join(projectRoot, ".epack", "receipts", "push", "beta", "20260313_120000_new.json")

	writeReceipt := func(path, remote, releaseID, packPath, createdAt string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("MkdirAll(%q): %v", filepath.Dir(path), err)
		}
		data := []byte(`{
  "remote": "` + remote + `",
  "created_at": "` + createdAt + `",
  "release": {
    "release_id": "` + releaseID + `"
  },
  "pack": {
    "path": "` + packPath + `"
  }
}`)
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatalf("WriteFile(%q): %v", path, err)
		}
	}

	writeReceipt(olderPath, "alpha", "rel_old", "/tmp/old.epack", "2026-03-13T11:00:00Z")
	writeReceipt(newerPath, "beta", "rel_new", "/tmp/new.epack", "2026-03-13T12:00:00Z")

	got := findLastPush(projectRoot)
	if got == nil {
		t.Fatal("findLastPush() = nil")
	}
	if got.Remote != "beta" {
		t.Fatalf("Remote = %q, want %q", got.Remote, "beta")
	}
	if got.ReleaseID != "rel_new" {
		t.Fatalf("ReleaseID = %q, want %q", got.ReleaseID, "rel_new")
	}
	if got.PackPath != "/tmp/new.epack" {
		t.Fatalf("PackPath = %q, want %q", got.PackPath, "/tmp/new.epack")
	}
	if got.ReceiptPath != newerPath {
		t.Fatalf("ReceiptPath = %q, want %q", got.ReceiptPath, newerPath)
	}
	if !got.Timestamp.Equal(time.Date(2026, 3, 13, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("Timestamp = %v, want %v", got.Timestamp, time.Date(2026, 3, 13, 12, 0, 0, 0, time.UTC))
	}
}
