package validate

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestPathComponent(t *testing.T) {
	tests := []struct {
		name    string
		seg     string
		wantErr bool
	}{
		// Valid
		{"simple", "foo", false},
		{"with-extension", "foo.txt", false},
		{"with-dash", "foo-bar", false},
		{"with-underscore", "foo_bar", false},
		{"numeric", "123", false},
		{"dotfile", ".gitignore", false},

		// Invalid
		{"empty", "", true},
		{"dot", ".", true},
		{"dot-dot", "..", true},
		{"starts-dot-dot", "..hidden", true},
		{"forward-slash", "foo/bar", true},
		{"backslash", "foo\\bar", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := PathComponent(tt.seg)
			if (err != nil) != tt.wantErr {
				t.Errorf("PathComponent(%q) error = %v, wantErr %v", tt.seg, err, tt.wantErr)
			}
		})
	}
}

func TestRelativePath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		// Valid
		{"simple", "foo", false},
		{"nested", "foo/bar", false},
		{"with-extension", "foo/bar.txt", false},
		{"dot-prefix", "./foo", false},
		{"current-dir", ".", false},

		// Invalid
		{"empty", "", true},
		{"absolute-unix", "/foo/bar", true},
		{"traversal-simple", "..", true},
		{"traversal-nested", "../foo", true},
		{"traversal-deep", "foo/../../bar", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := RelativePath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("RelativePath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestContainedPath(t *testing.T) {
	tests := []struct {
		name    string
		base    string
		rel     string
		wantErr bool
	}{
		// Valid
		{"simple", "/tmp/base", "foo", false},
		{"nested", "/tmp/base", "foo/bar", false},
		{"with-dot", "/tmp/base", "./foo", false},

		// Invalid
		{"empty-rel", "/tmp/base", "", true},
		{"traversal", "/tmp/base", "../escape", true},
		{"deep-traversal", "/tmp/base", "foo/../../escape", true},
		{"absolute", "/tmp/base", "/etc/passwd", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ContainedPath(tt.base, tt.rel)
			if (err != nil) != tt.wantErr {
				t.Errorf("ContainedPath(%q, %q) error = %v, wantErr %v", tt.base, tt.rel, err, tt.wantErr)
			}
			if err == nil {
				// Verify the result is actually under base
				absBase, _ := filepath.Abs(tt.base)
				if !strings.HasPrefix(result, absBase+string(filepath.Separator)) && result != absBase {
					t.Errorf("ContainedPath(%q, %q) = %q, not under base", tt.base, tt.rel, result)
				}
			}
		})
	}
}

func TestRelativePathWithPrefix(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		prefix  string
		wantErr bool
	}{
		// Valid
		{"artifacts", "artifacts/foo.json", "artifacts/", false},
		{"nested", "artifacts/sub/foo.json", "artifacts/", false},

		// Invalid
		{"wrong-prefix", "other/foo.json", "artifacts/", true},
		{"no-prefix", "foo.json", "artifacts/", true},
		{"traversal", "../artifacts/foo.json", "artifacts/", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := RelativePathWithPrefix(tt.path, tt.prefix)
			if (err != nil) != tt.wantErr {
				t.Errorf("RelativePathWithPrefix(%q, %q) error = %v, wantErr %v", tt.path, tt.prefix, err, tt.wantErr)
			}
		})
	}
}
