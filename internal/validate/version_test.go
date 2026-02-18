package validate

import "testing"

func TestVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		wantErr bool
	}{
		// Valid versions
		{"simple", "v1.2.3", false},
		{"no-v-prefix", "1.2.3", false},
		{"with-prerelease", "v1.2.3-beta.1", false},
		{"major-only", "v1", false},
		{"major-minor", "v1.2", false},
		{"zero-version", "v0.0.0", false},
		{"large-numbers", "v999.999.999", false},

		// Invalid: empty
		{"empty", "", true},

		// Invalid: path separators
		{"forward-slash", "v1.2.3/foo", true},
		{"backslash", "v1.2.3\\foo", true},

		// Invalid: path traversal
		{"dot-only", ".", true},
		{"dot-dot", "..", true},
		{"dot-dot-slash", "../v1.2.3", true},
		{"embedded-traversal", "v1.2.3/../foo", true},
		{"double-dot-in-prerelease", "v1.2.3-..foo", true},
		{"trailing-dot-dot", "v1.2.3-..", true},

		// Invalid: not semver
		{"letters-only", "foo", true},
		{"invalid-chars", "v1.2.3@latest", true},
		{"spaces", "v1.2.3 beta", true},

		// Invalid: too long
		{"too-long", "v1.2.3-" + string(make([]byte, 130)), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Version(tt.version)
			if (err != nil) != tt.wantErr {
				t.Errorf("Version(%q) error = %v, wantErr %v", tt.version, err, tt.wantErr)
			}
		})
	}
}

func TestRejectPathTraversal(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		// Valid
		{"simple", "foo", false},
		{"with-dots", "foo.bar", false},
		{"single-dot-in-name", "foo.bar.baz", false},

		// Invalid: separators
		{"forward-slash", "foo/bar", true},
		{"backslash", "foo\\bar", true},

		// Invalid: exact traversal
		{"dot", ".", true},
		{"dot-dot", "..", true},

		// Invalid: prefix traversal
		{"prefix-slash", "../foo", true},
		{"prefix-backslash", "..\\foo", true},

		// Invalid: embedded traversal
		{"embedded-slash", "foo/../bar", true},
		{"embedded-backslash", "foo\\..\\bar", true},

		// Invalid: double-dot anywhere
		{"trailing-dot-dot", "foo..", true},
		{"leading-dot-dot", "..foo", true},
		{"middle-dot-dot", "foo..bar", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := RejectPathTraversal(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("RejectPathTraversal(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}
