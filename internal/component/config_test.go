package component

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/locktivity/epack/internal/component/config"
)

func TestLoadConfig_ValidFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "collectors.yaml")

	content := `stream: test/stream
signing:
  enabled: true
  method: oidc
collectors:
  github:
    source: owner/repo@v1.0.0
    config:
      token: secret
  custom:
    binary: /usr/local/bin/collector
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("config.Load() error: %v", err)
	}

	if cfg.Stream != "test/stream" {
		t.Errorf("Stream = %q, want %q", cfg.Stream, "test/stream")
	}
	if !cfg.Signing.Enabled {
		t.Error("Signing.Enabled = false, want true")
	}
	if cfg.Signing.Method != "oidc" {
		t.Errorf("Signing.Method = %q, want %q", cfg.Signing.Method, "oidc")
	}
	if len(cfg.Collectors) != 2 {
		t.Errorf("len(Collectors) = %d, want 2", len(cfg.Collectors))
	}

	github, ok := cfg.Collectors["github"]
	if !ok {
		t.Fatal("missing github collector")
	}
	if github.Source != "owner/repo@v1.0.0" {
		t.Errorf("github.Source = %q, want %q", github.Source, "owner/repo@v1.0.0")
	}
	if github.Config["token"] != "secret" {
		t.Errorf("github.Config[token] = %v, want %q", github.Config["token"], "secret")
	}

	custom, ok := cfg.Collectors["custom"]
	if !ok {
		t.Fatal("missing custom collector")
	}
	if custom.Binary != "/usr/local/bin/collector" {
		t.Errorf("custom.Binary = %q, want %q", custom.Binary, "/usr/local/bin/collector")
	}
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	_, err := config.Load("/nonexistent/path/collectors.yaml")
	if err == nil {
		t.Error("config.Load() expected error for missing file, got nil")
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "collectors.yaml")

	content := `
collectors:
  - this is invalid yaml for our schema
  : broken
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	_, err := config.Load(configPath)
	if err == nil {
		t.Error("config.Load() expected error for invalid YAML, got nil")
	}
}

func TestLoadConfig_EmptyCollectors(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "collectors.yaml")

	content := `stream: test/stream
collectors: {}
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	_, err := config.Load(configPath)
	if err == nil {
		t.Error("config.Load() expected error for empty collectors, got nil")
	}
}

func TestLoadConfig_MutuallyExclusive(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "collectors.yaml")

	// Both source and binary set
	content := `collectors:
  bad:
    source: owner/repo@v1.0.0
    binary: /usr/bin/collector
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	_, err := config.Load(configPath)
	if err == nil {
		t.Error("config.Load() expected error for source+binary, got nil")
	}
}

func TestLoadConfig_NeitherSourceNorBinary(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "collectors.yaml")

	content := `collectors:
  empty:
    config:
      key: value
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	_, err := config.Load(configPath)
	if err == nil {
		t.Error("config.Load() expected error for missing source/binary, got nil")
	}
}

func TestParseConfig_Valid(t *testing.T) {
	data := []byte(`collectors:
  test:
    source: owner/repo@latest
`)

	cfg, err := config.Parse(data)
	if err != nil {
		t.Fatalf("config.Parse() error: %v", err)
	}
	if cfg.Collectors["test"].Source != "owner/repo@latest" {
		t.Errorf("Source = %q, want %q", cfg.Collectors["test"].Source, "owner/repo@latest")
	}
}

func TestParseConfig_InvalidCollectorName(t *testing.T) {
	data := []byte(`collectors:
  ../traversal:
    source: owner/repo@v1.0.0
`)

	_, err := config.Parse(data)
	if err == nil {
		t.Error("config.Parse() expected error for path traversal name, got nil")
	}
}

// NOTE: TestParseConfig_ExpandsEnvVars and TestParseConfig_UnsetEnvVarBecomesEmpty
// were removed because ${VAR} expansion was removed for security reasons.
// Secrets should be passed via the secrets: allowlist instead.

func TestJobConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  config.JobConfig
		wantErr bool
	}{
		{
			name: "valid source collector",
			config: config.JobConfig{
				Collectors: map[string]config.CollectorConfig{
					"mycollector": {Source: "owner/repo@v1.0.0"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid binary collector",
			config: config.JobConfig{
				Collectors: map[string]config.CollectorConfig{
					"mycollector": {Binary: "/usr/bin/collector"},
				},
			},
			wantErr: false,
		},
		{
			name:    "empty collectors",
			config:  config.JobConfig{Collectors: map[string]config.CollectorConfig{}},
			wantErr: true,
		},
		{
			name: "invalid collector name uppercase",
			config: config.JobConfig{
				Collectors: map[string]config.CollectorConfig{
					"MyCollector": {Source: "owner/repo@v1.0.0"},
				},
			},
			wantErr: true,
		},
		{
			name: "collector with neither source nor binary",
			config: config.JobConfig{
				Collectors: map[string]config.CollectorConfig{
					"empty": {},
				},
			},
			wantErr: true,
		},
		{
			name: "collector with both source and binary",
			config: config.JobConfig{
				Collectors: map[string]config.CollectorConfig{
					"both": {Source: "owner/repo@v1", Binary: "/bin/x"},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoadConfig_RemoteWithSecrets(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "epack.yaml")

	content := `stream: test/stream
collectors:
  github:
    source: owner/repo@v1.0.0
remotes:
  locktivity:
    source: locktivity/epack-remote-locktivity@v1
    target:
      workspace: acme
      environment: prod
    secrets:
      - LOCKTIVITY_OIDC_TOKEN
      - LOCKTIVITY_CLIENT_ID
      - LOCKTIVITY_CLIENT_SECRET
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("config.Load() error: %v", err)
	}

	remote, ok := cfg.Remotes["locktivity"]
	if !ok {
		t.Fatal("missing locktivity remote")
	}

	if len(remote.Secrets) != 3 {
		t.Errorf("Secrets length = %d, want 3", len(remote.Secrets))
	}

	expectedSecrets := []string{"LOCKTIVITY_OIDC_TOKEN", "LOCKTIVITY_CLIENT_ID", "LOCKTIVITY_CLIENT_SECRET"}
	for i, want := range expectedSecrets {
		if i >= len(remote.Secrets) {
			t.Errorf("missing secret at index %d: want %q", i, want)
			continue
		}
		if remote.Secrets[i] != want {
			t.Errorf("Secrets[%d] = %q, want %q", i, remote.Secrets[i], want)
		}
	}
}

func TestLoadConfig_RemoteWithoutSecrets(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "epack.yaml")

	content := `stream: test/stream
collectors:
  github:
    source: owner/repo@v1.0.0
remotes:
  locktivity:
    source: locktivity/epack-remote-locktivity@v1
    target:
      workspace: acme
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("config.Load() error: %v", err)
	}

	remote, ok := cfg.Remotes["locktivity"]
	if !ok {
		t.Fatal("missing locktivity remote")
	}

	// Secrets should be nil/empty when not specified
	if len(remote.Secrets) != 0 {
		t.Errorf("Secrets should be empty when not specified, got %v", remote.Secrets)
	}
}

func TestLoadConfig_RemoteEmptySecrets(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "epack.yaml")

	content := `stream: test/stream
collectors:
  github:
    source: owner/repo@v1.0.0
remotes:
  locktivity:
    source: locktivity/epack-remote-locktivity@v1
    secrets: []
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("config.Load() error: %v", err)
	}

	remote, ok := cfg.Remotes["locktivity"]
	if !ok {
		t.Fatal("missing locktivity remote")
	}

	// Empty array should result in empty slice
	if len(remote.Secrets) != 0 {
		t.Errorf("Secrets should be empty, got %v", remote.Secrets)
	}
}

func TestLoadConfig_RemoteSecretsRejectReservedNames(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "epack.yaml")

	content := `stream: test/stream
collectors:
  github:
    source: owner/repo@v1.0.0
remotes:
  locktivity:
    source: locktivity/epack-remote-locktivity@v1
    secrets:
      - LD_PRELOAD
      - EPACK_TOKEN
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	_, err := config.Load(configPath)
	if err == nil {
		t.Fatal("config.Load() expected error for reserved remote secret names, got nil")
	}
}

func TestLoadConfig_ProfilesValid(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "epack.yaml")

	content := `stream: test/stream
collectors:
  github:
    source: owner/repo@v1.0.0
profiles:
  - source: evidencepack/soc2-basic@v1
  - path: ./profiles/custom.yaml
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("config.Load() error: %v", err)
	}

	if len(cfg.Profiles) != 2 {
		t.Fatalf("len(Profiles) = %d, want 2", len(cfg.Profiles))
	}
	if cfg.Profiles[0].Source != "evidencepack/soc2-basic@v1" {
		t.Errorf("Profiles[0].Source = %q, want %q", cfg.Profiles[0].Source, "evidencepack/soc2-basic@v1")
	}
	if cfg.Profiles[1].Path != "./profiles/custom.yaml" {
		t.Errorf("Profiles[1].Path = %q, want %q", cfg.Profiles[1].Path, "./profiles/custom.yaml")
	}
}

func TestLoadConfig_ProfileMutuallyExclusive(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "epack.yaml")

	content := `stream: test/stream
collectors:
  github:
    source: owner/repo@v1.0.0
profiles:
  - source: evidencepack/soc2-basic@v1
    path: ./profiles/custom.yaml
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	_, err := config.Load(configPath)
	if err == nil {
		t.Fatal("config.Load() expected error for profile with both source and path, got nil")
	}
}

func TestLoadConfig_ProfileNeitherSourceNorPath(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "epack.yaml")

	content := `stream: test/stream
collectors:
  github:
    source: owner/repo@v1.0.0
profiles:
  - {}
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	_, err := config.Load(configPath)
	if err == nil {
		t.Fatal("config.Load() expected error for profile with neither source nor path, got nil")
	}
}

func TestLoadConfig_OverlaysValid(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "epack.yaml")

	content := `stream: test/stream
collectors:
  github:
    source: owner/repo@v1.0.0
overlays:
  - source: myorg/stricter-freshness@v1
  - path: ./overlays/local.yaml
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("config.Load() error: %v", err)
	}

	if len(cfg.Overlays) != 2 {
		t.Fatalf("len(Overlays) = %d, want 2", len(cfg.Overlays))
	}
	if cfg.Overlays[0].Source != "myorg/stricter-freshness@v1" {
		t.Errorf("Overlays[0].Source = %q, want %q", cfg.Overlays[0].Source, "myorg/stricter-freshness@v1")
	}
	if cfg.Overlays[1].Path != "./overlays/local.yaml" {
		t.Errorf("Overlays[1].Path = %q, want %q", cfg.Overlays[1].Path, "./overlays/local.yaml")
	}
}

func TestLoadConfig_OverlayMutuallyExclusive(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "epack.yaml")

	content := `stream: test/stream
collectors:
  github:
    source: owner/repo@v1.0.0
overlays:
  - source: myorg/stricter@v1
    path: ./overlays/local.yaml
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	_, err := config.Load(configPath)
	if err == nil {
		t.Fatal("config.Load() expected error for overlay with both source and path, got nil")
	}
}

func TestLoadConfig_OverlayNeitherSourceNorPath(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "epack.yaml")

	content := `stream: test/stream
collectors:
  github:
    source: owner/repo@v1.0.0
overlays:
  - {}
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	_, err := config.Load(configPath)
	if err == nil {
		t.Fatal("config.Load() expected error for overlay with neither source nor path, got nil")
	}
}

func TestJobConfig_HasSourceProfiles(t *testing.T) {
	tests := []struct {
		name     string
		profiles []config.ProfileConfig
		want     bool
	}{
		{
			name:     "no profiles",
			profiles: nil,
			want:     false,
		},
		{
			name:     "only path profiles",
			profiles: []config.ProfileConfig{{Path: "./local.yaml"}},
			want:     false,
		},
		{
			name:     "source profile",
			profiles: []config.ProfileConfig{{Source: "org/profile@v1"}},
			want:     true,
		},
		{
			name: "mixed",
			profiles: []config.ProfileConfig{
				{Path: "./local.yaml"},
				{Source: "org/profile@v1"},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.JobConfig{
				Collectors: map[string]config.CollectorConfig{
					"test": {Source: "x/y@v1"},
				},
				Profiles: tt.profiles,
			}
			if got := cfg.HasSourceProfiles(); got != tt.want {
				t.Errorf("HasSourceProfiles() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestJobConfig_HasSourceOverlays(t *testing.T) {
	tests := []struct {
		name     string
		overlays []config.OverlayConfig
		want     bool
	}{
		{
			name:     "no overlays",
			overlays: nil,
			want:     false,
		},
		{
			name:     "only path overlays",
			overlays: []config.OverlayConfig{{Path: "./local.yaml"}},
			want:     false,
		},
		{
			name:     "source overlay",
			overlays: []config.OverlayConfig{{Source: "org/overlay@v1"}},
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.JobConfig{
				Collectors: map[string]config.CollectorConfig{
					"test": {Source: "x/y@v1"},
				},
				Overlays: tt.overlays,
			}
			if got := cfg.HasSourceOverlays(); got != tt.want {
				t.Errorf("HasSourceOverlays() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestJobConfig_HasLocalProfiles(t *testing.T) {
	tests := []struct {
		name     string
		profiles []config.ProfileConfig
		want     bool
	}{
		{
			name:     "no profiles",
			profiles: nil,
			want:     false,
		},
		{
			name:     "only source profiles",
			profiles: []config.ProfileConfig{{Source: "org/profile@v1"}},
			want:     false,
		},
		{
			name:     "local profile",
			profiles: []config.ProfileConfig{{Path: "./local.yaml"}},
			want:     true,
		},
		{
			name: "mixed",
			profiles: []config.ProfileConfig{
				{Source: "org/profile@v1"},
				{Path: "./local.yaml"},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.JobConfig{
				Collectors: map[string]config.CollectorConfig{
					"test": {Source: "x/y@v1"},
				},
				Profiles: tt.profiles,
			}
			if got := cfg.HasLocalProfiles(); got != tt.want {
				t.Errorf("HasLocalProfiles() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestJobConfig_HasLocalOverlays(t *testing.T) {
	tests := []struct {
		name     string
		overlays []config.OverlayConfig
		want     bool
	}{
		{
			name:     "no overlays",
			overlays: nil,
			want:     false,
		},
		{
			name:     "only source overlays",
			overlays: []config.OverlayConfig{{Source: "org/overlay@v1"}},
			want:     false,
		},
		{
			name:     "local overlay",
			overlays: []config.OverlayConfig{{Path: "./local.yaml"}},
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.JobConfig{
				Collectors: map[string]config.CollectorConfig{
					"test": {Source: "x/y@v1"},
				},
				Overlays: tt.overlays,
			}
			if got := cfg.HasLocalOverlays(); got != tt.want {
				t.Errorf("HasLocalOverlays() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestJobConfig_Normalize_ValidPaths(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &config.JobConfig{
		Profiles: []config.ProfileConfig{
			{Path: "profiles/custom.yaml"},
			{Source: "org/profile@v1"}, // Source-based, should not get ResolvedPath
		},
		Overlays: []config.OverlayConfig{
			{Path: "overlays/local.yaml"},
			{Source: "org/overlay@v1"}, // Source-based, should not get ResolvedPath
		},
	}

	if err := cfg.Normalize(tmpDir); err != nil {
		t.Fatalf("Normalize() error: %v", err)
	}

	// Check profile paths
	if cfg.Profiles[0].ResolvedPath == "" {
		t.Error("Profiles[0].ResolvedPath should be set for path-based profile")
	}
	if !filepath.IsAbs(cfg.Profiles[0].ResolvedPath) {
		t.Errorf("Profiles[0].ResolvedPath should be absolute, got %q", cfg.Profiles[0].ResolvedPath)
	}
	if cfg.Profiles[1].ResolvedPath != "" {
		t.Errorf("Profiles[1].ResolvedPath should be empty for source-based profile, got %q", cfg.Profiles[1].ResolvedPath)
	}

	// Check overlay paths
	if cfg.Overlays[0].ResolvedPath == "" {
		t.Error("Overlays[0].ResolvedPath should be set for path-based overlay")
	}
	if !filepath.IsAbs(cfg.Overlays[0].ResolvedPath) {
		t.Errorf("Overlays[0].ResolvedPath should be absolute, got %q", cfg.Overlays[0].ResolvedPath)
	}
	if cfg.Overlays[1].ResolvedPath != "" {
		t.Errorf("Overlays[1].ResolvedPath should be empty for source-based overlay, got %q", cfg.Overlays[1].ResolvedPath)
	}
}

func TestJobConfig_Normalize_PathTraversal(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name        string
		profilePath string
		wantErr     bool
	}{
		{
			name:        "valid relative path",
			profilePath: "profiles/custom.yaml",
			wantErr:     false,
		},
		{
			name:        "path traversal",
			profilePath: "../outside.yaml",
			wantErr:     true,
		},
		{
			name:        "absolute path",
			profilePath: "/etc/passwd",
			wantErr:     true,
		},
		{
			name:        "hidden traversal",
			profilePath: "profiles/../../../etc/passwd",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.JobConfig{
				Profiles: []config.ProfileConfig{
					{Path: tt.profilePath},
				},
			}

			err := cfg.Normalize(tmpDir)
			if (err != nil) != tt.wantErr {
				t.Errorf("Normalize() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestJobConfig_Normalize_OverlayPathTraversal(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &config.JobConfig{
		Overlays: []config.OverlayConfig{
			{Path: "../escape.yaml"},
		},
	}

	err := cfg.Normalize(tmpDir)
	if err == nil {
		t.Error("Normalize() expected error for overlay path traversal, got nil")
	}
}

func TestLoadConfig_NormalizesLocalPaths(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "epack.yaml")

	content := `stream: test/stream
collectors:
  github:
    source: owner/repo@v1.0.0
profiles:
  - path: profiles/custom.yaml
overlays:
  - path: overlays/local.yaml
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("config.Load() error: %v", err)
	}

	// Check that paths were normalized
	if cfg.Profiles[0].ResolvedPath == "" {
		t.Error("Profiles[0].ResolvedPath should be set after Load()")
	}
	expectedProfilePath := filepath.Join(tmpDir, "profiles", "custom.yaml")
	if cfg.Profiles[0].ResolvedPath != expectedProfilePath {
		t.Errorf("Profiles[0].ResolvedPath = %q, want %q", cfg.Profiles[0].ResolvedPath, expectedProfilePath)
	}

	if cfg.Overlays[0].ResolvedPath == "" {
		t.Error("Overlays[0].ResolvedPath should be set after Load()")
	}
	expectedOverlayPath := filepath.Join(tmpDir, "overlays", "local.yaml")
	if cfg.Overlays[0].ResolvedPath != expectedOverlayPath {
		t.Errorf("Overlays[0].ResolvedPath = %q, want %q", cfg.Overlays[0].ResolvedPath, expectedOverlayPath)
	}
}

func TestLoadConfig_RejectsPathTraversal(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "epack.yaml")

	content := `stream: test/stream
collectors:
  github:
    source: owner/repo@v1.0.0
profiles:
  - path: ../escape.yaml
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	_, err := config.Load(configPath)
	if err == nil {
		t.Fatal("config.Load() expected error for path traversal, got nil")
	}
}

func TestParseConfig_DoesNotNormalize(t *testing.T) {
	data := []byte(`collectors:
  test:
    source: owner/repo@latest
profiles:
  - path: profiles/custom.yaml
`)

	cfg, err := config.Parse(data)
	if err != nil {
		t.Fatalf("config.Parse() error: %v", err)
	}

	// Parse() should NOT set ResolvedPath (it has no base directory)
	if cfg.Profiles[0].ResolvedPath != "" {
		t.Errorf("Profiles[0].ResolvedPath should be empty after Parse(), got %q", cfg.Profiles[0].ResolvedPath)
	}
}
