package validate

import (
	"testing"
)

func TestIsWindowsReserved(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		reserved bool
	}{
		{"con lowercase", "con", true},
		{"CON uppercase", "CON", true},
		{"Con mixed", "Con", true},
		{"con.txt with extension", "con.txt", true},
		{"CON.log with extension", "CON.log", true},
		{"prn", "prn", true},
		{"aux", "aux", true},
		{"nul", "nul", true},
		{"com1", "com1", true},
		{"com9", "com9", true},
		{"lpt1", "lpt1", true},
		{"lpt9", "lpt9", true},
		{"com10 not reserved", "com10", false},
		{"lpt10 not reserved", "lpt10", false},
		{"concat not reserved", "concat", false},
		{"icon not reserved", "icon", false},
		{"conventional not reserved", "conventional", false},
		{"regular file", "file.txt", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsWindowsReserved(tt.input)
			if got != tt.reserved {
				t.Errorf("IsWindowsReserved(%q) = %v, want %v", tt.input, got, tt.reserved)
			}
		})
	}
}

func TestWindowsFilename(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid simple", "file.txt", false},
		{"valid with dash", "my-file.txt", false},
		{"valid with underscore", "my_file.txt", false},
		{"valid numeric", "123.txt", false},
		{"empty", "", true},
		{"reserved con", "con", true},
		{"reserved CON", "CON", true},
		{"reserved con.txt", "con.txt", true},
		{"reserved prn", "prn", true},
		{"reserved aux.log", "aux.log", true},
		{"reserved nul", "nul", true},
		{"reserved com1", "com1", true},
		{"reserved lpt1.dat", "lpt1.dat", true},
		{"forbidden less than", "file<name.txt", true},
		{"forbidden greater than", "file>name.txt", true},
		{"forbidden colon", "file:name.txt", true},
		{"forbidden quote", "file\"name.txt", true},
		{"forbidden pipe", "file|name.txt", true},
		{"forbidden question", "file?name.txt", true},
		{"forbidden asterisk", "file*name.txt", true},
		{"trailing dot", "file.", true},
		{"trailing space", "file ", true},
		{"trailing dot with extension", "file.txt.", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := WindowsFilename(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("WindowsFilename(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestPathSafe(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"simple", "myfile", false},
		{"with dots", "v1.2.3", false},
		{"forward slash", "a/b", true},
		{"backslash", "a\\b", true},
		{"dot", ".", true},
		{"dot-dot", "..", true},
		{"starts with dot-dot", "..foo", true},
		{"ends with dot-dot", "foo..", true},
		{"contains dot-dot", "foo..bar", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := PathSafe(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("PathSafe(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}
