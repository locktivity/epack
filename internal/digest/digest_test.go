package digest

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid digest",
			input:   "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			wantErr: false,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "missing prefix",
			input:   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			wantErr: true,
		},
		{
			name:    "uppercase hex",
			input:   "sha256:E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
			wantErr: true,
		},
		{
			name:    "mixed case hex",
			input:   "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852B855",
			wantErr: true,
		},
		{
			name:    "wrong length (too short)",
			input:   "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85",
			wantErr: true,
		},
		{
			name:    "wrong length (too long)",
			input:   "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8555",
			wantErr: true,
		},
		{
			name:    "wrong algorithm",
			input:   "sha512:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			wantErr: true,
		},
		{
			name:    "invalid hex char",
			input:   "sha256:g3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := Parse(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && d.String() != tt.input {
				t.Errorf("Parse(%q).String() = %q, want %q", tt.input, d.String(), tt.input)
			}
		})
	}
}

func TestFromBytes(t *testing.T) {
	// SHA256 of empty string
	d := FromBytes([]byte{})
	want := "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if d.String() != want {
		t.Errorf("FromBytes(empty) = %q, want %q", d.String(), want)
	}

	// SHA256 of "hello"
	d = FromBytes([]byte("hello"))
	want = "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if d.String() != want {
		t.Errorf("FromBytes(hello) = %q, want %q", d.String(), want)
	}
}

func TestFromReader(t *testing.T) {
	d, err := FromReader(strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("FromReader: %v", err)
	}
	want := "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if d.String() != want {
		t.Errorf("FromReader(hello) = %q, want %q", d.String(), want)
	}
}

func TestEqual(t *testing.T) {
	d1 := MustParse("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	d2 := MustParse("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	d3 := MustParse("sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
	var zero Digest

	if !d1.Equal(d2) {
		t.Error("Equal digests should be equal")
	}
	if d1.Equal(d3) {
		t.Error("Different digests should not be equal")
	}
	if zero.Equal(d1) {
		t.Error("Zero digest should not equal valid digest")
	}
	if d1.Equal(zero) {
		t.Error("Valid digest should not equal zero digest")
	}
	if zero.Equal(zero) {
		t.Error("Zero digest should not equal itself")
	}
}

func TestIsZero(t *testing.T) {
	var zero Digest
	if !zero.IsZero() {
		t.Error("Zero value should be zero")
	}

	d := MustParse("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	if d.IsZero() {
		t.Error("Parsed digest should not be zero")
	}
}

func TestHex(t *testing.T) {
	d := MustParse("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if d.Hex() != want {
		t.Errorf("Hex() = %q, want %q", d.Hex(), want)
	}

	var zero Digest
	if zero.Hex() != "" {
		t.Errorf("Zero digest Hex() = %q, want empty", zero.Hex())
	}
}

func TestJSONRoundTrip(t *testing.T) {
	original := MustParse("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded Digest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if !original.Equal(decoded) {
		t.Errorf("Round trip failed: got %q, want %q", decoded.String(), original.String())
	}
}

func TestJSONUnmarshalInvalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"uppercase", `"sha256:E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"`},
		{"wrong prefix", `"md5:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"`},
		{"too short", `"sha256:e3b0c44"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var d Digest
			if err := json.Unmarshal([]byte(tt.input), &d); err == nil {
				t.Error("Expected error for invalid digest")
			}
		})
	}
}

func TestJSONEmptyString(t *testing.T) {
	var d Digest
	if err := json.Unmarshal([]byte(`""`), &d); err != nil {
		t.Fatalf("Unmarshal empty string: %v", err)
	}
	if !d.IsZero() {
		t.Error("Empty string should unmarshal to zero digest")
	}

	// Zero digest should marshal to empty string
	data, err := json.Marshal(Digest{})
	if err != nil {
		t.Fatalf("Marshal zero: %v", err)
	}
	if !bytes.Equal(data, []byte(`""`)) {
		t.Errorf("Zero digest should marshal to empty string, got %s", data)
	}
}

func TestMustParsePanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustParse with invalid input should panic")
		}
	}()
	MustParse("invalid")
}

func TestValidate(t *testing.T) {
	if err := Validate("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"); err != nil {
		t.Errorf("Validate valid: %v", err)
	}
	if err := Validate("invalid"); err == nil {
		t.Error("Validate invalid should return error")
	}
}
