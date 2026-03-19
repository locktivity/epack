package config

import "testing"

func TestProfileConfig_Key(t *testing.T) {
	tests := []struct {
		name   string
		config ProfileConfig
		want   string
	}{
		{
			name:   "path takes precedence",
			config: ProfileConfig{Path: "local/profile.yaml", Source: "org/profile@v1"},
			want:   "local/profile.yaml",
		},
		{
			name:   "source when no path",
			config: ProfileConfig{Source: "org/profile@v1"},
			want:   "org/profile@v1",
		},
		{
			name:   "path only",
			config: ProfileConfig{Path: "profiles/hitrust.yaml"},
			want:   "profiles/hitrust.yaml",
		},
		{
			name:   "empty returns empty",
			config: ProfileConfig{},
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.Key(); got != tt.want {
				t.Errorf("Key() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestOverlayConfig_Key(t *testing.T) {
	tests := []struct {
		name   string
		config OverlayConfig
		want   string
	}{
		{
			name:   "path takes precedence",
			config: OverlayConfig{Path: "local/overlay.yaml", Source: "org/overlay@v1"},
			want:   "local/overlay.yaml",
		},
		{
			name:   "source when no path",
			config: OverlayConfig{Source: "org/overlay@v1"},
			want:   "org/overlay@v1",
		},
		{
			name:   "path only",
			config: OverlayConfig{Path: "overlays/custom.yaml"},
			want:   "overlays/custom.yaml",
		},
		{
			name:   "empty returns empty",
			config: OverlayConfig{},
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.Key(); got != tt.want {
				t.Errorf("Key() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestProfileConfig_FilePath(t *testing.T) {
	tests := []struct {
		name   string
		config ProfileConfig
		want   string
	}{
		{
			name:   "resolved path takes precedence",
			config: ProfileConfig{Path: "profiles/test.yaml", ResolvedPath: "/abs/path/profiles/test.yaml"},
			want:   "/abs/path/profiles/test.yaml",
		},
		{
			name:   "falls back to path when no resolved",
			config: ProfileConfig{Path: "profiles/test.yaml"},
			want:   "profiles/test.yaml",
		},
		{
			name:   "empty when no path",
			config: ProfileConfig{Source: "org/profile@v1"},
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.FilePath(); got != tt.want {
				t.Errorf("FilePath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestOverlayConfig_FilePath(t *testing.T) {
	tests := []struct {
		name   string
		config OverlayConfig
		want   string
	}{
		{
			name:   "resolved path takes precedence",
			config: OverlayConfig{Path: "overlays/test.yaml", ResolvedPath: "/abs/path/overlays/test.yaml"},
			want:   "/abs/path/overlays/test.yaml",
		},
		{
			name:   "falls back to path when no resolved",
			config: OverlayConfig{Path: "overlays/test.yaml"},
			want:   "overlays/test.yaml",
		},
		{
			name:   "empty when no path",
			config: OverlayConfig{Source: "org/overlay@v1"},
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.FilePath(); got != tt.want {
				t.Errorf("FilePath() = %q, want %q", got, tt.want)
			}
		})
	}
}
