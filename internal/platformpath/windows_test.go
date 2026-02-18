package platformpath

import "testing"

func TestIsLocalWindowsPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		// Valid local paths
		{"drive letter uppercase", `C:\Users\test`, true},
		{"drive letter lowercase", `c:\Users\test`, true},
		{"drive letter forward slash", `C:/Users/test`, true},
		{"drive D", `D:\data`, true},

		// UNC paths (should be rejected)
		{"UNC backslash", `\\server\share`, false},
		{"UNC forward slash", `//server/share`, false},
		{"UNC with path", `\\server\share\folder`, false},

		// Invalid/edge cases
		{"empty", "", false},
		{"single char", "C", false},
		{"just drive letter", "C:", false},
		{"relative path", `folder\file`, false},
		{"rooted no drive", `\folder\file`, false},
		{"forward slash rooted", `/folder/file`, false},
		{"invalid drive char", `1:\folder`, false},
		{"invalid drive symbol", `@:\folder`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsLocalWindowsPath(tt.path)
			if got != tt.want {
				t.Errorf("IsLocalWindowsPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestIsUNCPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"UNC backslash", `\\server\share`, true},
		{"UNC forward slash", `//server/share`, true},
		{"UNC with path", `\\server\share\folder\file`, true},
		{"local drive", `C:\Users`, false},
		{"relative", `folder\file`, false},
		{"rooted no drive", `\folder`, false},
		{"empty", "", false},
		{"single backslash", `\`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsUNCPath(tt.path)
			if got != tt.want {
				t.Errorf("IsUNCPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestHasDriveLetter(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"uppercase C", "C:", true},
		{"lowercase c", "c:", true},
		{"with path", "C:\\folder", true},
		{"drive Z", "Z:", true},
		{"no colon", "C", false},
		{"number", "1:", false},
		{"empty", "", false},
		{"UNC", "\\\\server", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasDriveLetter(tt.path)
			if got != tt.want {
				t.Errorf("HasDriveLetter(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
