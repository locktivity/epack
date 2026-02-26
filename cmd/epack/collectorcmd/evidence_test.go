//go:build components

package collectorcmd

import (
	"strings"
	"testing"

	"github.com/locktivity/epack/pack"
)

func TestFindSourceForArtifact(t *testing.T) {
	manifest := pack.Manifest{
		Sources: []pack.Source{
			{Name: "github", Artifacts: []string{"artifacts/github/posture.json", "artifacts/github/repos.json"}},
			{Name: "aws", Artifacts: []string{"artifacts/aws/config.json"}},
		},
	}

	tests := []struct {
		path string
		want string
	}{
		{"artifacts/github/posture.json", "github"},
		{"artifacts/github/repos.json", "github"},
		{"artifacts/aws/config.json", "aws"},
		{"artifacts/unknown/data.json", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := findSourceForArtifact(manifest, tt.path)
			if got != tt.want {
				t.Errorf("findSourceForArtifact(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestFormatArtifactSummary(t *testing.T) {
	tests := []struct {
		name     string
		artifact pack.Artifact
		want     string
	}{
		{
			name: "display name only",
			artifact: pack.Artifact{
				Path:        "artifacts/test.json",
				DisplayName: "Test Data",
			},
			want: "Test Data",
		},
		{
			name: "display name with description",
			artifact: pack.Artifact{
				Path:        "artifacts/test.json",
				DisplayName: "Test Data",
				Description: "A test artifact for unit testing",
			},
			want: "Test Data: A test artifact for unit testing",
		},
		{
			name: "path only",
			artifact: pack.Artifact{
				Path: "artifacts/github/posture.json",
			},
			want: "posture.json",
		},
		{
			name: "path with description",
			artifact: pack.Artifact{
				Path:        "artifacts/github/posture.json",
				Description: "GitHub security posture data",
			},
			want: "posture.json: GitHub security posture data",
		},
		{
			name: "long description truncated",
			artifact: pack.Artifact{
				Path:        "artifacts/data.json",
				Description: "This is a very long description that exceeds the sixty character limit and should be truncated",
			},
			// Truncated at 57 chars + "..."
			want: "data.json: This is a very long description that exceeds the sixty ch...",
		},
		{
			name: "non-json content type",
			artifact: pack.Artifact{
				Path:        "artifacts/report.pdf",
				ContentType: "application/pdf",
			},
			want: "report.pdf (application/pdf)",
		},
		{
			name: "json content type not shown",
			artifact: pack.Artifact{
				Path:        "artifacts/data.json",
				ContentType: "application/json",
			},
			want: "data.json",
		},
		{
			name: "description takes precedence over content type",
			artifact: pack.Artifact{
				Path:        "artifacts/report.pdf",
				ContentType: "application/pdf",
				Description: "Monthly report",
			},
			want: "report.pdf: Monthly report",
		},
		{
			name: "empty path returns dot",
			artifact: pack.Artifact{
				Path: "",
			},
			// filepath.Base("") returns "."
			want: ".",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatArtifactSummary(tt.artifact)
			if got != tt.want {
				t.Errorf("formatArtifactSummary() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCollectControls(t *testing.T) {
	tests := []struct {
		name      string
		artifacts []pack.Artifact
		want      []string
	}{
		{
			name:      "empty artifacts",
			artifacts: []pack.Artifact{},
			want:      nil,
		},
		{
			name: "single artifact no controls",
			artifacts: []pack.Artifact{
				{Path: "a.json"},
			},
			want: nil,
		},
		{
			name: "single artifact with controls",
			artifacts: []pack.Artifact{
				{Path: "a.json", Controls: []string{"SOC2-CC6.1", "SOC2-CC6.2"}},
			},
			want: []string{"SOC2-CC6.1", "SOC2-CC6.2"},
		},
		{
			name: "multiple artifacts unique controls",
			artifacts: []pack.Artifact{
				{Path: "a.json", Controls: []string{"SOC2-CC6.1"}},
				{Path: "b.json", Controls: []string{"ISO27001-A.8.1"}},
			},
			want: []string{"SOC2-CC6.1", "ISO27001-A.8.1"},
		},
		{
			name: "multiple artifacts duplicate controls",
			artifacts: []pack.Artifact{
				{Path: "a.json", Controls: []string{"SOC2-CC6.1", "SOC2-CC6.2"}},
				{Path: "b.json", Controls: []string{"SOC2-CC6.1", "SOC2-CC7.1"}},
			},
			want: []string{"SOC2-CC6.1", "SOC2-CC6.2", "SOC2-CC7.1"},
		},
		{
			name: "mixed with and without controls",
			artifacts: []pack.Artifact{
				{Path: "a.json", Controls: []string{"SOC2-CC6.1"}},
				{Path: "b.json"},
				{Path: "c.json", Controls: []string{"SOC2-CC7.1"}},
			},
			want: []string{"SOC2-CC6.1", "SOC2-CC7.1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := collectControls(tt.artifacts)
			if len(got) != len(tt.want) {
				t.Errorf("collectControls() returned %d controls, want %d", len(got), len(tt.want))
				t.Errorf("got: %v, want: %v", got, tt.want)
				return
			}
			// Check that all expected controls are present
			for _, want := range tt.want {
				found := false
				for _, g := range got {
					if g == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("collectControls() missing expected control %q", want)
				}
			}
		})
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes int64
		want  string
	}{
		{0, "0 bytes"},
		{1, "1 bytes"},
		{512, "512 bytes"},
		{1023, "1023 bytes"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1024 * 1024, "1.0 MB"},
		{1024 * 1024 * 1.5, "1.5 MB"},
		{1024 * 1024 * 1024, "1.0 GB"},
		{1024 * 1024 * 1024 * 2.5, "2.5 GB"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := formatBytes(tt.bytes)
			if got != tt.want {
				t.Errorf("formatBytes(%d) = %q, want %q", tt.bytes, got, tt.want)
			}
		})
	}
}

func TestFormatArtifactSummary_TruncationBoundary(t *testing.T) {
	// Test exactly at truncation boundary
	exactlyAt60 := strings.Repeat("a", 60)
	artifact60 := pack.Artifact{
		Path:        "test.json",
		Description: exactlyAt60,
	}
	result := formatArtifactSummary(artifact60)
	if strings.Contains(result, "...") {
		t.Errorf("description of exactly 60 chars should not be truncated")
	}

	// Test one over boundary
	at61 := strings.Repeat("a", 61)
	artifact61 := pack.Artifact{
		Path:        "test.json",
		Description: at61,
	}
	result = formatArtifactSummary(artifact61)
	if !strings.HasSuffix(result, "...") {
		t.Errorf("description of 61 chars should be truncated")
	}
}
