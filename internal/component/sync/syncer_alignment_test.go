package sync

import (
	"testing"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/componenttypes"
)

// TestValidateAlignment_SkipStaleEntryCheck tests that the SkipStaleEntryCheck option
// allows syncing with a filtered config that doesn't include all lockfile entries.
// This is needed when installing new components with a filtered config.
func TestValidateAlignment_SkipStaleEntryCheck(t *testing.T) {
	syncer := &Syncer{}

	// Create a lockfile with two collectors
	lf := &lockfile.LockFile{
		Collectors: map[string]lockfile.LockedCollector{
			"aws": {
				Source:  "github.com/locktivity/epack-collector-aws",
				Version: "v1.0.0",
				Kind:    "source",
				Platforms: map[string]componenttypes.LockedPlatform{
					"linux/amd64": {Digest: "sha256:abc123"},
				},
			},
			"github": {
				Source:  "github.com/locktivity/epack-collector-github",
				Version: "v1.0.0",
				Kind:    "source",
				Platforms: map[string]componenttypes.LockedPlatform{
					"linux/amd64": {Digest: "sha256:def456"},
				},
			},
		},
	}

	// Create a config with only one collector (filtered config)
	filteredCfg := &config.JobConfig{
		Collectors: map[string]config.CollectorConfig{
			"aws": {Source: "locktivity/epack-collector-aws@v1.0.0"},
		},
	}

	// Without SkipStaleEntryCheck, validation should fail because 'github' is in lockfile but not config
	err := syncer.validateAlignmentWithOpts(filteredCfg, lf, SyncOpts{})
	if err == nil {
		t.Fatal("expected error when lockfile has entries not in config, got nil")
	}

	// With SkipStaleEntryCheck, validation should pass
	err = syncer.validateAlignmentWithOpts(filteredCfg, lf, SyncOpts{SkipStaleEntryCheck: true})
	if err != nil {
		t.Fatalf("expected no error with SkipStaleEntryCheck, got: %v", err)
	}
}

// TestValidateAlignment_SkipStaleEntryCheck_StillValidatesForward tests that even with
// SkipStaleEntryCheck enabled, the forward direction (config entries must exist in lockfile)
// is still validated.
func TestValidateAlignment_SkipStaleEntryCheck_StillValidatesForward(t *testing.T) {
	syncer := &Syncer{}

	// Create a lockfile with one collector
	lf := &lockfile.LockFile{
		Collectors: map[string]lockfile.LockedCollector{
			"aws": {
				Source:  "github.com/locktivity/epack-collector-aws",
				Version: "v1.0.0",
				Kind:    "source",
				Platforms: map[string]componenttypes.LockedPlatform{
					"linux/amd64": {Digest: "sha256:abc123"},
				},
			},
		},
	}

	// Create a config that references a collector NOT in lockfile
	cfg := &config.JobConfig{
		Collectors: map[string]config.CollectorConfig{
			"github": {Source: "locktivity/epack-collector-github@v1.0.0"},
		},
	}

	// Even with SkipStaleEntryCheck, this should fail because config references
	// a collector not in lockfile
	err := syncer.validateAlignmentWithOpts(cfg, lf, SyncOpts{SkipStaleEntryCheck: true})
	if err == nil {
		t.Fatal("expected error when config has entries not in lockfile, got nil")
	}
}

// TestValidateAlignment_Remotes_SkipStaleEntryCheck tests the SkipStaleEntryCheck
// behavior for remotes.
func TestValidateAlignment_Remotes_SkipStaleEntryCheck(t *testing.T) {
	syncer := &Syncer{}

	// Create a lockfile with two remotes
	lf := &lockfile.LockFile{
		Remotes: map[string]lockfile.LockedRemote{
			"locktivity": {
				Source:  "github.com/locktivity/epack-remote-locktivity",
				Version: "v1.0.0",
				Kind:    "source",
				Platforms: map[string]componenttypes.LockedPlatform{
					"linux/amd64": {Digest: "sha256:abc123"},
				},
			},
			"s3": {
				Source:  "github.com/locktivity/epack-remote-s3",
				Version: "v1.0.0",
				Kind:    "source",
				Platforms: map[string]componenttypes.LockedPlatform{
					"linux/amd64": {Digest: "sha256:def456"},
				},
			},
		},
	}

	// Create a config with only one remote (filtered config)
	filteredCfg := &config.JobConfig{
		Remotes: map[string]config.RemoteConfig{
			"locktivity": {Source: "locktivity/epack-remote-locktivity@v1.0.0"},
		},
	}

	// Without SkipStaleEntryCheck, validation should fail
	err := syncer.validateAlignmentWithOpts(filteredCfg, lf, SyncOpts{})
	if err == nil {
		t.Fatal("expected error when lockfile has remote entries not in config, got nil")
	}

	// With SkipStaleEntryCheck, validation should pass
	err = syncer.validateAlignmentWithOpts(filteredCfg, lf, SyncOpts{SkipStaleEntryCheck: true})
	if err != nil {
		t.Fatalf("expected no error with SkipStaleEntryCheck for remotes, got: %v", err)
	}
}

// TestValidateAlignment_ExternalCollectors_Skipped tests that external collectors
// in lockfile don't cause validation failures.
func TestValidateAlignment_ExternalCollectors_Skipped(t *testing.T) {
	syncer := &Syncer{}

	// Create a lockfile with an external collector
	lf := &lockfile.LockFile{
		Collectors: map[string]lockfile.LockedCollector{
			"custom": {
				Kind: "external",
				Platforms: map[string]componenttypes.LockedPlatform{
					"linux/amd64": {Digest: "sha256:abc123"},
				},
			},
		},
	}

	// Create a config with a different external collector
	cfg := &config.JobConfig{
		Collectors: map[string]config.CollectorConfig{
			"other": {Binary: "/usr/local/bin/other"},
		},
	}

	// External collectors in lockfile should be skipped during reverse check
	err := syncer.validateAlignmentWithOpts(cfg, lf, SyncOpts{})
	if err != nil {
		t.Fatalf("external collector in lockfile should not cause error, got: %v", err)
	}
}

// TestValidateAlignment_MixedComponents tests alignment validation with
// collectors and remotes together.
func TestValidateAlignment_MixedComponents(t *testing.T) {
	syncer := &Syncer{}

	// Create a lockfile with collector and remote
	lf := &lockfile.LockFile{
		Collectors: map[string]lockfile.LockedCollector{
			"aws": {
				Source:  "github.com/locktivity/epack-collector-aws",
				Version: "v1.0.0",
				Kind:    "source",
				Platforms: map[string]componenttypes.LockedPlatform{
					"linux/amd64": {Digest: "sha256:abc123"},
				},
			},
			"github": {
				Source:  "github.com/locktivity/epack-collector-github",
				Version: "v1.0.0",
				Kind:    "source",
				Platforms: map[string]componenttypes.LockedPlatform{
					"linux/amd64": {Digest: "sha256:def456"},
				},
			},
		},
		Remotes: map[string]lockfile.LockedRemote{
			"locktivity": {
				Source:  "github.com/locktivity/epack-remote-locktivity",
				Version: "v1.0.0",
				Kind:    "source",
				Platforms: map[string]componenttypes.LockedPlatform{
					"linux/amd64": {Digest: "sha256:ghi789"},
				},
			},
		},
	}

	// Create a filtered config with only aws collector and locktivity remote
	filteredCfg := &config.JobConfig{
		Collectors: map[string]config.CollectorConfig{
			"aws": {Source: "locktivity/epack-collector-aws@v1.0.0"},
		},
		Remotes: map[string]config.RemoteConfig{
			"locktivity": {Source: "locktivity/epack-remote-locktivity@v1.0.0"},
		},
	}

	// Without SkipStaleEntryCheck, should fail (github collector in lockfile but not config)
	err := syncer.validateAlignmentWithOpts(filteredCfg, lf, SyncOpts{})
	if err == nil {
		t.Fatal("expected error when lockfile has entries not in filtered config, got nil")
	}

	// With SkipStaleEntryCheck, should pass
	err = syncer.validateAlignmentWithOpts(filteredCfg, lf, SyncOpts{SkipStaleEntryCheck: true})
	if err != nil {
		t.Fatalf("expected no error with SkipStaleEntryCheck, got: %v", err)
	}
}
