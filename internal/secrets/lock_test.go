package secrets

import (
	"path/filepath"
	"testing"
	"time"
)

func TestLockFile_ExclusiveWaitsThenReportsBusy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scope.lock")
	unlock, err := lockFile(path, true, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockFile(path, true, 150*time.Millisecond); CodeOf(err) != CodeBusy {
		t.Fatalf("second exclusive lock = %v, want busy", err)
	}
	if _, err := lockFile(path, false, 150*time.Millisecond); CodeOf(err) != CodeBusy {
		t.Fatalf("shared lock under an exclusive one = %v, want busy", err)
	}
	unlock()
	unlockShared, err := lockFile(path, false, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	unlockSecond, err := lockFile(path, false, time.Second)
	if err != nil {
		t.Fatalf("two readers must share: %v", err)
	}
	unlockShared()
	unlockSecond()
}
