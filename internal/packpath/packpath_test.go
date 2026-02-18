package packpath

import (
	"strings"
	"testing"
)

// TestPathConstantsAreNonEmpty ensures all path constants have values.
func TestPathConstantsAreNonEmpty(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"Manifest", Manifest},
		{"ArtifactsDir", ArtifactsDir},
		{"Attestations", Attestations},
		{"SigstoreExt", SigstoreExt},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value == "" {
				t.Errorf("%s is empty", tt.name)
			}
		})
	}
}

// TestDirectoriesHaveTrailingSlash ensures directory paths end with slash.
func TestDirectoriesHaveTrailingSlash(t *testing.T) {
	dirs := []struct {
		name  string
		value string
	}{
		{"ArtifactsDir", ArtifactsDir},
		{"Attestations", Attestations},
	}

	for _, tt := range dirs {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.HasSuffix(tt.value, "/") {
				t.Errorf("%s = %q, want trailing slash", tt.name, tt.value)
			}
		})
	}
}

// TestFilesHaveNoTrailingSlash ensures file paths don't end with slash.
func TestFilesHaveNoTrailingSlash(t *testing.T) {
	files := []struct {
		name  string
		value string
	}{
		{"Manifest", Manifest},
		{"SigstoreExt", SigstoreExt},
	}

	for _, tt := range files {
		t.Run(tt.name, func(t *testing.T) {
			if strings.HasSuffix(tt.value, "/") {
				t.Errorf("%s = %q, should not have trailing slash", tt.name, tt.value)
			}
		})
	}
}

// TestExtensionStartsWithDot ensures extensions have leading dot.
func TestExtensionStartsWithDot(t *testing.T) {
	if !strings.HasPrefix(SigstoreExt, ".") {
		t.Errorf("SigstoreExt = %q, want leading dot", SigstoreExt)
	}
}

// TestManifestIsJSON ensures manifest has .json extension.
func TestManifestIsJSON(t *testing.T) {
	if !strings.HasSuffix(Manifest, ".json") {
		t.Errorf("Manifest = %q, want .json extension", Manifest)
	}
}

// TestPathsAreRelative ensures no paths start with slash (absolute paths).
func TestPathsAreRelative(t *testing.T) {
	paths := []struct {
		name  string
		value string
	}{
		{"Manifest", Manifest},
		{"ArtifactsDir", ArtifactsDir},
		{"Attestations", Attestations},
	}

	for _, tt := range paths {
		t.Run(tt.name, func(t *testing.T) {
			if strings.HasPrefix(tt.value, "/") {
				t.Errorf("%s = %q, should be relative (no leading slash)", tt.name, tt.value)
			}
		})
	}
}

func TestValidateArtifactPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		// Valid paths
		{"valid simple", "artifacts/config.json", false},
		{"valid nested", "artifacts/data/nested/file.txt", false},
		{"valid with hyphen", "artifacts/my-file.json", false},
		{"valid with underscore", "artifacts/my_file.json", false},

		// Invalid paths
		{"missing prefix", "other/config.json", true},
		{"just directory", "artifacts/", true},
		{"absolute path", "/artifacts/config.json", true},
		{"traversal attack", "artifacts/../etc/passwd", true},
		{"dot segment", "artifacts/./file.txt", true},
		{"windows reserved", "artifacts/con.txt", true},
		{"trailing dot", "artifacts/file.", true},
		{"trailing space", "artifacts/file ", true},
		{"backslash", "artifacts\\file.txt", true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateArtifactPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateArtifactPath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestValidateArtifactPathAndCollisionKey(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		wantKey     string
		wantErr     bool
	}{
		{"lowercase", "artifacts/file.txt", "artifacts/file.txt", false},
		{"uppercase", "artifacts/FILE.TXT", "artifacts/file.txt", false},
		{"mixed case", "artifacts/FiLe.TxT", "artifacts/file.txt", false},
		{"nested", "artifacts/Dir/File.txt", "artifacts/dir/file.txt", false},
		{"invalid path", "other/file.txt", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ValidateArtifactPathAndCollisionKey(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateArtifactPathAndCollisionKey(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
				return
			}
			if !tt.wantErr && key != tt.wantKey {
				t.Errorf("ValidateArtifactPathAndCollisionKey(%q) key = %q, want %q", tt.path, key, tt.wantKey)
			}
		})
	}
}

func TestIsArtifactPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"artifacts/file.txt", true},
		{"artifacts/nested/file.txt", true},
		{"artifacts/", false}, // Just the directory
		{"other/file.txt", false},
		{"attestations/file.txt", false},
		{"manifest.json", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := IsArtifactPath(tt.path); got != tt.want {
				t.Errorf("IsArtifactPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestIsAttestationPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"attestations/sig.sigstore.json", true},
		{"attestations/", false}, // Just the directory
		{"artifacts/file.txt", false},
		{"manifest.json", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := IsAttestationPath(tt.path); got != tt.want {
				t.Errorf("IsAttestationPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
