package validate

import (
	"encoding/json"
	"testing"
)

func TestParseSemVer(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid v prefix", "v1.2.3", false},
		{"valid no prefix", "1.2.3", false},
		{"valid prerelease", "v1.2.3-alpha.1", false},
		{"valid major only", "v1", false},
		{"valid major minor", "v1.2", false},
		{"empty", "", true},
		{"path traversal slash", "v1.0.0/foo", true},
		{"path traversal backslash", "v1.0.0\\foo", true},
		{"path traversal dotdot", "..", true},
		{"path traversal embedded", "v1.0.0/../foo", true},
		{"invalid chars", "v1.0.0?foo", true},
		{"too long", string(make([]byte, 130)), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSemVer(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSemVer(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && string(got) != tt.input {
				t.Errorf("ParseSemVer(%q) = %q, want %q", tt.input, got, tt.input)
			}
		})
	}
}

func TestSemVerJSONUnmarshal(t *testing.T) {
	type container struct {
		Version SemVer `json:"version"`
	}

	tests := []struct {
		name    string
		json    string
		want    string
		wantErr bool
	}{
		{"valid", `{"version":"v1.2.3"}`, "v1.2.3", false},
		{"path traversal", `{"version":"../foo"}`, "", true},
		{"empty", `{"version":""}`, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c container
			err := json.Unmarshal([]byte(tt.json), &c)
			if (err != nil) != tt.wantErr {
				t.Errorf("json.Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && string(c.Version) != tt.want {
				t.Errorf("Version = %q, want %q", c.Version, tt.want)
			}
		})
	}
}

func TestMustParseSemVerPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustParseSemVer did not panic on invalid input")
		}
	}()
	MustParseSemVer("..")
}

func TestSemVerString(t *testing.T) {
	v, _ := ParseSemVer("v1.2.3")
	if v.String() != "v1.2.3" {
		t.Errorf("String() = %q, want %q", v.String(), "v1.2.3")
	}
}

func TestParseSafeInt(t *testing.T) {
	tests := []struct {
		name    string
		input   int64
		wantErr bool
	}{
		{"zero", 0, false},
		{"positive", 100, false},
		{"max safe int", MaxSafeInt, false},
		{"negative", -1, true},
		{"exceeds max safe int", MaxSafeInt + 1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSafeInt(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSafeInt(%d) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got.Int64() != tt.input {
				t.Errorf("ParseSafeInt(%d).Int64() = %d, want %d", tt.input, got.Int64(), tt.input)
			}
		})
	}
}

func TestSafeIntJSONMarshalUnmarshal(t *testing.T) {
	tests := []struct {
		name  string
		value int64
	}{
		{"zero", 0},
		{"small", 42},
		{"large", 1000000000},
		{"max safe", MaxSafeInt},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := ParseSafeInt(tt.value)
			if err != nil {
				t.Fatalf("ParseSafeInt() error = %v", err)
			}

			data, err := json.Marshal(s)
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}

			var got SafeInt
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("Unmarshal() error = %v", err)
			}

			if got.Int64() != tt.value {
				t.Errorf("round-trip: got %d, want %d", got.Int64(), tt.value)
			}
		})
	}
}

func TestSafeIntJSONUnmarshalInvalid(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantErr bool
	}{
		{"valid number", "42", false},
		{"valid string number", `"42"`, false},
		{"negative", "-1", true},
		{"exceeds max", "9007199254740992", true}, // MaxSafeInt + 1
		{"float", "1.5", true},
		{"not a number", `"abc"`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var s SafeInt
			err := json.Unmarshal([]byte(tt.json), &s)
			if (err != nil) != tt.wantErr {
				t.Errorf("Unmarshal(%s) error = %v, wantErr %v", tt.json, err, tt.wantErr)
			}
		})
	}
}

func TestNewSafeIntPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("NewSafeInt did not panic on invalid input")
		}
	}()
	NewSafeInt(-1)
}

func TestSafeIntString(t *testing.T) {
	s, _ := ParseSafeInt(12345)
	if s.String() != "12345" {
		t.Errorf("String() = %q, want %q", s.String(), "12345")
	}
}

func TestMaxSafeIntValue(t *testing.T) {
	// Verify MaxSafeInt is exactly 2^53 - 1
	expected := int64((1 << 53) - 1)
	if MaxSafeInt != expected {
		t.Errorf("MaxSafeInt = %d, want %d", MaxSafeInt, expected)
	}
	// Verify it's 9007199254740991
	if MaxSafeInt != 9007199254740991 {
		t.Errorf("MaxSafeInt = %d, want 9007199254740991", MaxSafeInt)
	}
}
