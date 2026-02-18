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
