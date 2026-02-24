//go:build components

package utilitycmd

import (
	"testing"

	"github.com/locktivity/epack/internal/catalog"
)

func TestExtractRepoPath(t *testing.T) {
	tests := []struct {
		name    string
		repoURL string
		want    string
		wantErr bool
	}{
		{
			name:    "basic GitHub URL",
			repoURL: "https://github.com/locktivity/epack-tools-viewer",
			want:    "locktivity/epack-tools-viewer",
		},
		{
			name:    "GitHub URL with trailing slash",
			repoURL: "https://github.com/locktivity/epack-tools-viewer/",
			want:    "locktivity/epack-tools-viewer",
		},
		{
			name:    "GitHub URL with extra path segments",
			repoURL: "https://github.com/locktivity/epack-tools-viewer/releases",
			want:    "locktivity/epack-tools-viewer",
		},
		{
			name:    "empty URL",
			repoURL: "",
			wantErr: true,
		},
		{
			name:    "non-GitHub URL",
			repoURL: "https://gitlab.com/owner/repo",
			wantErr: true,
		},
		{
			name:    "missing repo part",
			repoURL: "https://github.com/owner",
			wantErr: true,
		},
		{
			name:    "HTTP instead of HTTPS",
			repoURL: "http://github.com/owner/repo",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractRepoPath(tt.repoURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractRepoPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("extractRepoPath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildSourceString(t *testing.T) {
	tests := []struct {
		name       string
		component  catalog.CatalogComponent
		constraint string
		want       string
		wantErr    bool
	}{
		{
			name: "no constraint",
			component: catalog.CatalogComponent{
				Name:    "viewer",
				RepoURL: "https://github.com/locktivity/epack-tools-viewer",
				Latest:  "v1.2.0",
			},
			constraint: "",
			want:       "locktivity/epack-tools-viewer@v1.2.0",
		},
		{
			name: "latest constraint",
			component: catalog.CatalogComponent{
				Name:    "viewer",
				RepoURL: "https://github.com/locktivity/epack-tools-viewer",
				Latest:  "v1.2.0",
			},
			constraint: "latest",
			want:       "locktivity/epack-tools-viewer@v1.2.0",
		},
		{
			name: "version constraint",
			component: catalog.CatalogComponent{
				Name:    "viewer",
				RepoURL: "https://github.com/locktivity/epack-tools-viewer",
			},
			constraint: "v1.0.0",
			want:       "locktivity/epack-tools-viewer@v1.0.0",
		},
		{
			name: "caret constraint",
			component: catalog.CatalogComponent{
				Name:    "viewer",
				RepoURL: "https://github.com/locktivity/epack-tools-viewer",
			},
			constraint: "^1.0",
			want:       "locktivity/epack-tools-viewer@^1.0",
		},
		{
			name: "invalid repo URL",
			component: catalog.CatalogComponent{
				Name:    "viewer",
				RepoURL: "",
			},
			constraint: "",
			wantErr:    true,
		},
		{
			name: "no releases",
			component: catalog.CatalogComponent{
				Name:    "viewer",
				RepoURL: "https://github.com/locktivity/epack-tools-viewer",
				Latest:  "",
			},
			constraint: "latest",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildSourceString(tt.component, tt.constraint)
			if (err != nil) != tt.wantErr {
				t.Errorf("buildSourceString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("buildSourceString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestValidateUtilityName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid name",
			input:   "viewer",
			wantErr: false,
		},
		{
			name:    "valid name with dash",
			input:   "my-viewer",
			wantErr: false,
		},
		{
			name:    "valid name with underscore",
			input:   "my_viewer",
			wantErr: false,
		},
		{
			name:    "path traversal attack",
			input:   "../escape",
			wantErr: true,
		},
		{
			name:    "empty name",
			input:   "",
			wantErr: true,
		},
		{
			name:    "name with slash",
			input:   "viewer/bad",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateUtilityName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateUtilityName(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}
