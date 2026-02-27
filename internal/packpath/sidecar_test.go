package packpath

import "testing"

func TestSidecarDir(t *testing.T) {
	tests := []struct {
		name     string
		packPath string
		want     string
	}{
		// With .epack extension - should be stripped
		{"simple with extension", "sample.epack", "sample.runs"},
		{"absolute path with extension", "/path/to/vendor.epack", "/path/to/vendor.runs"},
		{"nested path with extension", "/Users/test/packs/evidence.epack", "/Users/test/packs/evidence.runs"},

		// Without .epack extension - suffix added directly
		{"simple no extension", "evidence", "evidence.runs"},
		{"absolute path no extension", "/path/to/vendor", "/path/to/vendor.runs"},
		{"with other extension", "data.zip", "data.zip.runs"},

		// Edge cases
		{"just extension", ".epack", ".runs"},
		{"double extension", "sample.epack.epack", "sample.epack.runs"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SidecarDir(tt.packPath)
			if got != tt.want {
				t.Errorf("SidecarDir(%q) = %q, want %q", tt.packPath, got, tt.want)
			}
		})
	}
}

func TestSidecarConstants(t *testing.T) {
	// Ensure constants have expected values
	if PackExtension != ".epack" {
		t.Errorf("PackExtension = %q, want %q", PackExtension, ".epack")
	}
	if SidecarSuffix != ".runs" {
		t.Errorf("SidecarSuffix = %q, want %q", SidecarSuffix, ".runs")
	}
}
