package componenttypes

import (
	"encoding/json"
	"testing"
)

func TestParseCollectorName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid simple", "myapp", false},
		{"valid with dash", "my-app", false},
		{"valid with underscore", "my_app", false},
		{"valid with dot", "my.app", false},
		{"valid with number", "app1", false},
		{"valid starts with number", "1app", false},
		{"empty", "", true},
		{"path traversal dotdot", "..", true},
		{"path traversal embedded", "foo..bar", true},
		{"path traversal prefix", "..foo", true},
		{"path traversal suffix", "foo..", true},
		{"single dot", ".", true},
		{"slash", "foo/bar", true},
		{"uppercase", "MyApp", true},
		{"too long", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true}, // 65 chars
		{"max length", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false},  // 64 chars
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCollectorName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCollectorName(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && string(got) != tt.input {
				t.Errorf("ParseCollectorName(%q) = %q, want %q", tt.input, got, tt.input)
			}
		})
	}
}

func TestCollectorNameJSONUnmarshal(t *testing.T) {
	type container struct {
		Name CollectorName `json:"name"`
	}

	tests := []struct {
		name    string
		json    string
		wantErr bool
	}{
		{"valid", `{"name":"myapp"}`, false},
		{"path traversal", `{"name":".."}`, true},
		{"empty", `{"name":""}`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c container
			err := json.Unmarshal([]byte(tt.json), &c)
			if (err != nil) != tt.wantErr {
				t.Errorf("json.Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseToolName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid", "mytool", false},
		{"path traversal", "..", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseToolName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseToolName(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestParseRemoteName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid", "myremote", false},
		{"path traversal", "..", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseRemoteName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRemoteName(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestParseUtilityName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid", "myutil", false},
		{"path traversal", "..", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseUtilityName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseUtilityName(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestParseEnvironmentName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid", "production", false},
		{"valid with dash", "staging-1", false},
		{"path traversal", "..", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseEnvironmentName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseEnvironmentName(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestMustParseCollectorNamePanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustParseCollectorName did not panic on invalid input")
		}
	}()
	MustParseCollectorName("..")
}

func TestNameString(t *testing.T) {
	name, _ := ParseCollectorName("myapp")
	if name.String() != "myapp" {
		t.Errorf("String() = %q, want %q", name.String(), "myapp")
	}
}
