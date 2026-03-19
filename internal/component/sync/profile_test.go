package sync

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/lockfile"
)

func TestResolveProfilePath(t *testing.T) {
	// Create a temp directory structure for testing
	tempDir := t.TempDir()

	// Create a valid file inside tempDir
	profilesDir := filepath.Join(tempDir, "profiles")
	if err := os.MkdirAll(profilesDir, 0755); err != nil {
		t.Fatalf("failed to create profiles dir: %v", err)
	}
	validFile := filepath.Join(profilesDir, "test.yaml")
	if err := os.WriteFile(validFile, []byte("test content"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Create a file outside tempDir
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "outside.yaml")
	if err := os.WriteFile(outsideFile, []byte("outside content"), 0644); err != nil {
		t.Fatalf("failed to create outside file: %v", err)
	}

	tests := []struct {
		name     string
		workDir  string
		key      string
		filePath string
		wantPath string
		wantErr  bool
	}{
		{
			name:     "relative path uses key",
			workDir:  tempDir,
			key:      "profiles/test.yaml",
			filePath: "profiles/test.yaml", // not absolute
			wantPath: validFile,
			wantErr:  false,
		},
		{
			name:     "absolute path within workDir",
			workDir:  tempDir,
			key:      "profiles/test.yaml",
			filePath: validFile, // absolute, within workDir
			wantPath: validFile,
			wantErr:  false,
		},
		{
			name:     "absolute path outside workDir rejected",
			workDir:  tempDir,
			key:      "profiles/outside.yaml",
			filePath: outsideFile, // absolute, outside workDir
			wantErr:  true,
		},
		{
			name:     "relative path traversal rejected",
			workDir:  tempDir,
			key:      "../etc/passwd",
			filePath: "../etc/passwd",
			wantErr:  true,
		},
		{
			name:     "nonexistent relative path",
			workDir:  tempDir,
			key:      "profiles/nonexistent.yaml",
			filePath: "profiles/nonexistent.yaml",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := resolveProfilePath(tt.workDir, tt.key, tt.filePath)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if result != tt.wantPath {
				t.Errorf("expected path %q, got %q", tt.wantPath, result)
			}
		})
	}
}

func TestHasProfileDigestDrift(t *testing.T) {
	// Create a temp directory structure for testing
	tempDir := t.TempDir()

	// Create profile and overlay files
	profilesDir := filepath.Join(tempDir, "profiles")
	overlaysDir := filepath.Join(tempDir, "overlays")
	if err := os.MkdirAll(profilesDir, 0755); err != nil {
		t.Fatalf("failed to create profiles dir: %v", err)
	}
	if err := os.MkdirAll(overlaysDir, 0755); err != nil {
		t.Fatalf("failed to create overlays dir: %v", err)
	}

	profileFile := filepath.Join(profilesDir, "hitrust.yaml")
	overlayFile := filepath.Join(overlaysDir, "custom.yaml")

	// Write initial content
	profileContent := []byte("profile: hitrust\nversion: v1")
	overlayContent := []byte("overlay: custom\nversion: v1")
	if err := os.WriteFile(profileFile, profileContent, 0644); err != nil {
		t.Fatalf("failed to write profile: %v", err)
	}
	if err := os.WriteFile(overlayFile, overlayContent, 0644); err != nil {
		t.Fatalf("failed to write overlay: %v", err)
	}

	// Compute digests for the initial content
	profileDigest := computeDigestFromBytes(profileContent)
	overlayDigest := computeDigestFromBytes(overlayContent)

	tests := []struct {
		name        string
		cfg         *config.JobConfig
		lf          *lockfile.LockFile
		modifyFiles func() // function to modify files before test
		wantDrift   bool
	}{
		{
			name: "no drift when digests match",
			cfg: &config.JobConfig{
				Profiles: []config.ProfileConfig{
					{Path: "profiles/hitrust.yaml"},
				},
				Overlays: []config.OverlayConfig{
					{Path: "overlays/custom.yaml"},
				},
			},
			lf: &lockfile.LockFile{
				Profiles: map[string]lockfile.LockedProfile{
					"profiles/hitrust.yaml": {Digest: profileDigest},
				},
				Overlays: map[string]lockfile.LockedOverlay{
					"overlays/custom.yaml": {Digest: overlayDigest},
				},
			},
			wantDrift: false,
		},
		{
			name: "drift detected when profile content changes",
			cfg: &config.JobConfig{
				Profiles: []config.ProfileConfig{
					{Path: "profiles/hitrust.yaml"},
				},
			},
			lf: &lockfile.LockFile{
				Profiles: map[string]lockfile.LockedProfile{
					"profiles/hitrust.yaml": {Digest: "sha256:olddigest"},
				},
			},
			wantDrift: true,
		},
		{
			name: "drift detected when overlay content changes",
			cfg: &config.JobConfig{
				Overlays: []config.OverlayConfig{
					{Path: "overlays/custom.yaml"},
				},
			},
			lf: &lockfile.LockFile{
				Overlays: map[string]lockfile.LockedOverlay{
					"overlays/custom.yaml": {Digest: "sha256:olddigest"},
				},
			},
			wantDrift: true,
		},
		{
			name: "no drift for remote profiles (skipped)",
			cfg: &config.JobConfig{
				Profiles: []config.ProfileConfig{
					{Source: "org/profile@v1"}, // remote, not local
				},
			},
			lf: &lockfile.LockFile{
				Profiles: map[string]lockfile.LockedProfile{
					"org/profile@v1": {Digest: "sha256:somedigest"},
				},
			},
			wantDrift: false,
		},
		{
			name: "no drift when profile missing from lockfile",
			cfg: &config.JobConfig{
				Profiles: []config.ProfileConfig{
					{Path: "profiles/hitrust.yaml"},
				},
			},
			lf: &lockfile.LockFile{
				Profiles: map[string]lockfile.LockedProfile{}, // empty
			},
			wantDrift: false, // missing entries handled elsewhere
		},
		{
			name: "no drift when file doesn't exist (error ignored)",
			cfg: &config.JobConfig{
				Profiles: []config.ProfileConfig{
					{Path: "profiles/nonexistent.yaml"},
				},
			},
			lf: &lockfile.LockFile{
				Profiles: map[string]lockfile.LockedProfile{
					"profiles/nonexistent.yaml": {Digest: "sha256:somedigest"},
				},
			},
			wantDrift: false, // errors ignored, handled during actual sync
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset files to initial state before each test
			if err := os.WriteFile(profileFile, profileContent, 0644); err != nil {
				t.Fatalf("failed to reset profile: %v", err)
			}
			if err := os.WriteFile(overlayFile, overlayContent, 0644); err != nil {
				t.Fatalf("failed to reset overlay: %v", err)
			}

			if tt.modifyFiles != nil {
				tt.modifyFiles()
			}

			result := HasProfileDigestDrift(tt.cfg, tt.lf, tempDir)
			if result != tt.wantDrift {
				t.Errorf("HasProfileDigestDrift() = %v, want %v", result, tt.wantDrift)
			}
		})
	}
}

func TestHasProfileDigestDrift_FileModification(t *testing.T) {
	// This test verifies drift detection when a file is actually modified
	tempDir := t.TempDir()

	profilesDir := filepath.Join(tempDir, "profiles")
	if err := os.MkdirAll(profilesDir, 0755); err != nil {
		t.Fatalf("failed to create profiles dir: %v", err)
	}

	profileFile := filepath.Join(profilesDir, "test.yaml")
	originalContent := []byte("version: v1")
	if err := os.WriteFile(profileFile, originalContent, 0644); err != nil {
		t.Fatalf("failed to write profile: %v", err)
	}

	originalDigest := computeDigestFromBytes(originalContent)

	cfg := &config.JobConfig{
		Profiles: []config.ProfileConfig{
			{Path: "profiles/test.yaml"},
		},
	}
	lf := &lockfile.LockFile{
		Profiles: map[string]lockfile.LockedProfile{
			"profiles/test.yaml": {Digest: originalDigest},
		},
	}

	// Initially no drift
	if HasProfileDigestDrift(cfg, lf, tempDir) {
		t.Error("expected no drift initially")
	}

	// Modify the file
	modifiedContent := []byte("version: v2")
	if err := os.WriteFile(profileFile, modifiedContent, 0644); err != nil {
		t.Fatalf("failed to modify profile: %v", err)
	}

	// Now should detect drift
	if !HasProfileDigestDrift(cfg, lf, tempDir) {
		t.Error("expected drift after file modification")
	}
}
