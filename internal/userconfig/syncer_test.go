package userconfig

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/locktivity/epack/internal/securityaudit"
)

type auditSink struct {
	mu     sync.Mutex
	events []securityaudit.Event
}

func TestInstallUtilityBinary_AtomicReplaceAndCleanup(t *testing.T) {
	tmpDir := t.TempDir()
	installPath := filepath.Join(tmpDir, "utility-bin")
	tmpPath := installPath + ".tmp"

	if err := os.WriteFile(installPath, []byte("old"), 0644); err != nil {
		t.Fatalf("writing existing binary: %v", err)
	}
	if err := os.WriteFile(tmpPath, []byte("new"), 0644); err != nil {
		t.Fatalf("writing temp binary: %v", err)
	}

	if err := installUtilityBinary(tmpPath, installPath); err != nil {
		t.Fatalf("installUtilityBinary() error: %v", err)
	}

	got, err := os.ReadFile(installPath)
	if err != nil {
		t.Fatalf("reading installed binary: %v", err)
	}
	if string(got) != "new" {
		t.Fatalf("installed binary = %q, want %q", string(got), "new")
	}
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Fatalf("expected temp file removed, stat err=%v", err)
	}
}

func TestInstallUtilityBinary_RefusesSymlinkDestination(t *testing.T) {
	tmpDir := t.TempDir()
	targetPath := filepath.Join(tmpDir, "target-bin")
	installPath := filepath.Join(tmpDir, "utility-bin")
	tmpPath := installPath + ".tmp"

	if err := os.WriteFile(targetPath, []byte("target"), 0644); err != nil {
		t.Fatalf("writing target file: %v", err)
	}
	if err := os.Symlink(targetPath, installPath); err != nil {
		// Windows often requires extra privileges for symlink tests.
		if runtime.GOOS == "windows" {
			t.Skipf("symlink not available on this runner: %v", err)
		}
		t.Fatalf("creating symlink destination: %v", err)
	}
	if err := os.WriteFile(tmpPath, []byte("new"), 0644); err != nil {
		t.Fatalf("writing temp binary: %v", err)
	}

	err := installUtilityBinary(tmpPath, installPath)
	if err == nil {
		t.Fatal("expected symlink destination to be rejected")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "symlink") {
		t.Fatalf("expected symlink-related error, got: %v", err)
	}

	targetData, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("reading target file: %v", err)
	}
	if string(targetData) != "target" {
		t.Fatalf("symlink target modified: got %q want %q", string(targetData), "target")
	}
}

func (s *auditSink) HandleSecurityEvent(evt securityaudit.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, evt)
}

func (s *auditSink) snapshot() []securityaudit.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]securityaudit.Event, len(s.events))
	copy(out, s.events)
	return out
}

func TestUtilityInstall_StrictProductionRejectsUnsafeOverrides(t *testing.T) {
	t.Setenv("EPACK_STRICT_PRODUCTION", "1")

	sink := &auditSink{}
	securityaudit.SetSink(sink)
	t.Cleanup(func() { securityaudit.SetSink(nil) })

	syncer := NewUtilitySyncer()
	_, err := syncer.Install(context.Background(), "viewer", "locktivity/epack-tools-viewer@v1", InstallOpts{
		Unsafe: UnsafeInstallOverrides{
			SkipVerify: true,
		},
	})
	if err == nil {
		t.Fatal("expected strict production rejection for unsafe utility install overrides")
	}
	if !strings.Contains(err.Error(), "strict production mode forbids insecure execution overrides") {
		t.Fatalf("unexpected error: %v", err)
	}

	events := sink.snapshot()
	found := false
	for _, evt := range events {
		if evt.Type == securityaudit.EventInsecureBypass && evt.Component == "utility_install" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected insecure bypass audit event for strict rejection, got: %+v", events)
	}
}

func TestUtilityInstall_EmitsInsecureBypassEventWhenAllowed(t *testing.T) {
	t.Setenv("EPACK_STRICT_PRODUCTION", "")

	sink := &auditSink{}
	securityaudit.SetSink(sink)
	t.Cleanup(func() { securityaudit.SetSink(nil) })

	syncer := NewUtilitySyncer()
	_, _ = syncer.Install(context.Background(), "viewer", "invalid-source", InstallOpts{
		Unsafe: UnsafeInstallOverrides{
			SkipVerify: true,
		},
	})

	events := sink.snapshot()
	found := false
	for _, evt := range events {
		if evt.Type == securityaudit.EventInsecureBypass && evt.Component == "utility" && evt.Name == "viewer" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected insecure bypass audit event for allowed unsafe install, got: %+v", events)
	}
}
