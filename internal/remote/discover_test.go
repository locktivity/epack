package remote_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/remote"
)

func TestLookupAdapterPath_NotFound(t *testing.T) {
	path := remote.LookupAdapterPath("nonexistent-adapter-xyz")
	if path != "" {
		t.Errorf("expected empty path for nonexistent adapter, got %q", path)
	}
}

func TestLookupAdapterPath_InPATH(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows - different executable detection")
	}

	// Create a temporary directory with a fake adapter
	dir := t.TempDir()
	adapterPath := filepath.Join(dir, "epack-remote-testadapter")

	// Create fake executable
	if err := os.WriteFile(adapterPath, []byte("#!/bin/sh\necho test\n"), 0755); err != nil {
		t.Fatalf("creating fake adapter: %v", err)
	}

	// Add to PATH
	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+oldPath)

	// Should find the adapter
	path := remote.LookupAdapterPath("testadapter")
	if path != adapterPath {
		t.Errorf("LookupAdapterPath() = %q, want %q", path, adapterPath)
	}
}

func TestLookupAdapterPath_PrefersManaged(t *testing.T) {
	// This test verifies the lookup order: managed dir > project dir > PATH
	// We can't easily test managed dir without mocking, but we can test project dir.
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows")
	}

	// Create project dir with adapter
	projectDir := t.TempDir()
	epackBin := filepath.Join(projectDir, ".epack", "bin")
	if err := os.MkdirAll(epackBin, 0755); err != nil {
		t.Fatalf("creating .epack/bin: %v", err)
	}

	adapterPath := filepath.Join(epackBin, "epack-remote-projectadapter")
	if err := os.WriteFile(adapterPath, []byte("#!/bin/sh\necho project\n"), 0755); err != nil {
		t.Fatalf("creating project adapter: %v", err)
	}

	// Create PATH adapter with same name
	pathDir := t.TempDir()
	pathAdapterPath := filepath.Join(pathDir, "epack-remote-projectadapter")
	if err := os.WriteFile(pathAdapterPath, []byte("#!/bin/sh\necho path\n"), 0755); err != nil {
		t.Fatalf("creating PATH adapter: %v", err)
	}

	// Add pathDir to PATH
	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", pathDir+string(os.PathListSeparator)+oldPath)

	// Change to project directory
	oldWd, _ := os.Getwd()
	_ = os.Chdir(projectDir)
	defer func() { _ = os.Chdir(oldWd) }()

	// Should prefer project dir over PATH
	path := remote.LookupAdapterPath("projectadapter")

	// Resolve symlinks for comparison (macOS /var -> /private/var)
	resolvedPath, _ := filepath.EvalSymlinks(path)
	resolvedExpected, _ := filepath.EvalSymlinks(adapterPath)

	if resolvedPath != resolvedExpected {
		t.Errorf("should prefer project adapter, got %q, want %q", resolvedPath, resolvedExpected)
	}
}

func TestDiscoverAdapters_EmptyPATH(t *testing.T) {
	// Clear PATH
	t.Setenv("PATH", "")

	ctx := context.Background()
	opts := remote.DiscoverOptions{
		ProbePATH: false,
	}

	// Should not panic with empty PATH
	adapters := remote.DiscoverAdapters(ctx, opts)
	// Result may be empty or contain managed adapters
	_ = adapters
}

func TestDiscoverAdapters_FindsInPATH(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows")
	}

	// Create a fake adapter in PATH
	dir := t.TempDir()
	adapterPath := filepath.Join(dir, "epack-remote-discover-test")
	if err := os.WriteFile(adapterPath, []byte("#!/bin/sh\necho test\n"), 0755); err != nil {
		t.Fatalf("creating fake adapter: %v", err)
	}

	// Add to PATH
	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+oldPath)

	ctx := context.Background()
	opts := remote.DiscoverOptions{
		ProbePATH: false, // Don't actually execute
	}

	adapters := remote.DiscoverAdapters(ctx, opts)

	// Find our adapter
	var found *remote.DiscoveredAdapter
	for i := range adapters {
		if adapters[i].Name == "discover-test" {
			found = &adapters[i]
			break
		}
	}

	if found == nil {
		t.Fatal("adapter not discovered")
	}

	if found.BinaryPath != adapterPath {
		t.Errorf("BinaryPath = %q, want %q", found.BinaryPath, adapterPath)
	}

	if found.Status != remote.StatusUnverified {
		t.Errorf("Status = %q, want %q", found.Status, remote.StatusUnverified)
	}

	if found.Source != "path" {
		t.Errorf("Source = %q, want %q", found.Source, "path")
	}
}

func TestFindAdapter(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows")
	}

	// Create a fake adapter
	dir := t.TempDir()
	adapterPath := filepath.Join(dir, "epack-remote-findme")
	if err := os.WriteFile(adapterPath, []byte("#!/bin/sh\necho found\n"), 0755); err != nil {
		t.Fatalf("creating fake adapter: %v", err)
	}

	// Add to PATH
	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+oldPath)

	ctx := context.Background()
	opts := remote.DiscoverOptions{
		ProbePATH: false,
	}

	// Should find existing adapter
	adapter := remote.FindAdapter(ctx, "findme", opts)
	if adapter == nil {
		t.Fatal("FindAdapter returned nil for existing adapter")
	}
	if adapter.Name != "findme" {
		t.Errorf("Name = %q, want %q", adapter.Name, "findme")
	}

	// Should return nil for nonexistent adapter
	notFound := remote.FindAdapter(ctx, "nonexistent-xyz", opts)
	if notFound != nil {
		t.Errorf("FindAdapter should return nil for nonexistent adapter, got %+v", notFound)
	}
}

func TestAdapterStatus_Values(t *testing.T) {
	// Verify status constants are distinct
	statuses := []remote.AdapterStatus{
		remote.StatusVerified,
		remote.StatusUnverified,
		remote.StatusManaged,
		remote.StatusNotFound,
	}

	seen := make(map[remote.AdapterStatus]bool)
	for _, s := range statuses {
		if seen[s] {
			t.Errorf("duplicate status value: %q", s)
		}
		seen[s] = true
		if s == "" {
			t.Error("status should not be empty string")
		}
	}
}

func TestAdapterPrefix(t *testing.T) {
	// Verify the adapter prefix is correct
	if componenttypes.RemoteBinaryPrefix != "epack-remote-" {
		t.Errorf("RemoteBinaryPrefix = %q, want %q", componenttypes.RemoteBinaryPrefix, "epack-remote-")
	}
}

// TestDiscoverAdapters_NoProbeByDefault verifies that ProbePATH=false prevents execution.
func TestDiscoverAdapters_NoProbeByDefault(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows")
	}

	// Create a fake adapter that would fail if executed
	dir := t.TempDir()
	adapterPath := filepath.Join(dir, "epack-remote-failprobe")
	// This script exits with error if executed
	if err := os.WriteFile(adapterPath, []byte("#!/bin/sh\nexit 1\n"), 0755); err != nil {
		t.Fatalf("creating fake adapter: %v", err)
	}

	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+oldPath)

	ctx := context.Background()
	opts := remote.DiscoverOptions{
		ProbePATH: false, // Should NOT execute the adapter
	}

	adapters := remote.DiscoverAdapters(ctx, opts)

	// Find our adapter
	var found *remote.DiscoveredAdapter
	for i := range adapters {
		if adapters[i].Name == "failprobe" {
			found = &adapters[i]
			break
		}
	}

	if found == nil {
		t.Fatal("adapter not discovered")
	}

	// Should have been discovered without probing
	if found.Capabilities != nil {
		t.Error("Capabilities should be nil when ProbePATH=false")
	}
	if found.Error != "" {
		t.Errorf("Error should be empty when not probed, got %q", found.Error)
	}
}

// TestDiscoverAdapters_Deterministic verifies results are sorted.
func TestDiscoverAdapters_Deterministic(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows")
	}

	// Create multiple fake adapters
	dir := t.TempDir()
	names := []string{"alpha", "beta", "gamma", "delta"}
	for _, name := range names {
		path := filepath.Join(dir, "epack-remote-"+name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\necho "+name+"\n"), 0755); err != nil {
			t.Fatalf("creating adapter %s: %v", name, err)
		}
	}

	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+oldPath)

	ctx := context.Background()
	opts := remote.DiscoverOptions{ProbePATH: false}

	// Run multiple times, results should be identical
	first := remote.DiscoverAdapters(ctx, opts)
	for i := 0; i < 5; i++ {
		current := remote.DiscoverAdapters(ctx, opts)
		if len(current) != len(first) {
			t.Fatalf("run %d: length differs (%d vs %d)", i, len(current), len(first))
		}
		for j := range first {
			if current[j].Name != first[j].Name {
				t.Errorf("run %d: position %d differs (%q vs %q)", i, j, current[j].Name, first[j].Name)
			}
		}
	}

	// Verify sorted order
	var lastSeen string
	for _, a := range first {
		if a.Name < lastSeen {
			t.Errorf("adapters not sorted: %q came after %q", a.Name, lastSeen)
		}
		lastSeen = a.Name
	}
}
