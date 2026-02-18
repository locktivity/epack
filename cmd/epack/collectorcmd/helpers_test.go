//go:build components

package collectorcmd

import (
	"testing"

	"github.com/locktivity/epack/internal/component/config"
)

func TestParseCommaSeparated(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"", nil},
		{"a", []string{"a"}},
		{"a,b", []string{"a", "b"}},
		{"a, b, c", []string{"a", "b", "c"}},
		{" a , b ", []string{"a", "b"}},
		{"linux/amd64,darwin/arm64", []string{"linux/amd64", "darwin/arm64"}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseCommaSeparated(tt.input)
			if len(got) != len(tt.want) {
				t.Errorf("parseCommaSeparated(%q) = %v, want %v", tt.input, got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("parseCommaSeparated(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestValidateCollectorNames(t *testing.T) {
	cfg := &config.JobConfig{
		Collectors: map[string]config.CollectorConfig{
			"github": {Source: "owner/repo@v1.0.0"},
			"aws":    {Source: "owner/aws@v2.0.0"},
		},
	}

	tests := []struct {
		name    string
		names   []string
		wantErr bool
	}{
		{"empty list", nil, false},
		{"valid single", []string{"github"}, false},
		{"valid multiple", []string{"github", "aws"}, false},
		{"invalid single", []string{"nonexistent"}, true},
		{"mixed valid invalid", []string{"github", "nonexistent"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCollectorNames(cfg, tt.names)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateCollectorNames() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFilterConfigCollectors(t *testing.T) {
	cfg := &config.JobConfig{
		Stream: "test-stream",
		Collectors: map[string]config.CollectorConfig{
			"github": {Source: "owner/repo@v1.0.0"},
			"aws":    {Source: "owner/aws@v2.0.0"},
			"gcp":    {Source: "owner/gcp@v3.0.0"},
		},
	}

	t.Run("filter to subset", func(t *testing.T) {
		filtered, err := filterConfigCollectors(cfg, []string{"github", "aws"})
		if err != nil {
			t.Fatalf("filterConfigCollectors() error = %v", err)
		}
		if len(filtered.Collectors) != 2 {
			t.Errorf("got %d collectors, want 2", len(filtered.Collectors))
		}
		if _, ok := filtered.Collectors["github"]; !ok {
			t.Error("missing github collector")
		}
		if _, ok := filtered.Collectors["aws"]; !ok {
			t.Error("missing aws collector")
		}
		if filtered.Stream != "test-stream" {
			t.Errorf("stream = %q, want %q", filtered.Stream, "test-stream")
		}
	})

	t.Run("filter preserves original", func(t *testing.T) {
		_, _ = filterConfigCollectors(cfg, []string{"github"})
		if len(cfg.Collectors) != 3 {
			t.Error("original config was modified")
		}
	})

	t.Run("invalid collector name", func(t *testing.T) {
		_, err := filterConfigCollectors(cfg, []string{"nonexistent"})
		if err == nil {
			t.Error("expected error for nonexistent collector")
		}
	})
}
