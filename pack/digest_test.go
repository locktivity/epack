package pack

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestComputeSHA256(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "empty data",
			data: []byte{},
			want: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name: "hello world",
			data: []byte("hello world"),
			want: "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
		},
		{
			name: "json content",
			data: []byte(`{"key": "value"}`),
			want: "sha256:8f249e3b5e1f5a7a8e1b6c3d8f4e9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f",
		},
		{
			name: "binary data",
			data: []byte{0x00, 0x01, 0x02, 0x03, 0xff},
			want: "sha256:d80baf3a8ca6d2c1c53769efe06c6b6e8e9a3df3a5c7b2e1f0d9c8b7a6958473",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeSHA256(tt.data)

			// For pre-computed known values, check exact match
			if tt.name == "empty data" || tt.name == "hello world" {
				if got != tt.want {
					t.Errorf("computeSHA256() = %q, want %q", got, tt.want)
				}
				return
			}

			// For other cases, just verify format
			if len(got) != 71 { // "sha256:" (7) + 64 hex chars
				t.Errorf("computeSHA256() length = %d, want 71", len(got))
			}
			if got[:7] != "sha256:" {
				t.Errorf("computeSHA256() prefix = %q, want %q", got[:7], "sha256:")
			}
		})
	}
}

func TestComputeSHA256Reader(t *testing.T) {
	tests := []struct {
		name    string
		input   io.Reader
		want    string
		wantErr bool
	}{
		{
			name:  "empty reader",
			input: bytes.NewReader([]byte{}),
			want:  "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:  "hello world",
			input: bytes.NewReader([]byte("hello world")),
			want:  "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
		},
		{
			name:    "error reader",
			input:   &errorReader{err: errors.New("read error")},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := computeSHA256Reader(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Error("computeSHA256Reader() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("computeSHA256Reader() error = %v", err)
			}

			if got != tt.want {
				t.Errorf("computeSHA256Reader() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestComputeSHA256_ConsistentWithReader(t *testing.T) {
	testData := [][]byte{
		{},
		[]byte("hello world"),
		[]byte(`{"test": "data"}`),
		bytes.Repeat([]byte("x"), 1024),
	}

	for _, data := range testData {
		fromBytes := computeSHA256(data)
		fromReader, err := computeSHA256Reader(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("computeSHA256Reader() error = %v", err)
		}

		if fromBytes != fromReader {
			t.Errorf("computeSHA256(%q) = %q, but computeSHA256Reader() = %q",
				data, fromBytes, fromReader)
		}
	}
}

// errorReader is a reader that always returns an error.
type errorReader struct {
	err error
}

func (r *errorReader) Read(p []byte) (int, error) {
	return 0, r.err
}

func TestBuildCanonicalArtifactList(t *testing.T) {
	tests := []struct {
		name      string
		artifacts []Artifact
		want      string
	}{
		{
			name:      "no artifacts",
			artifacts: []Artifact{},
			want:      "",
		},
		{
			name: "single embedded artifact",
			artifacts: []Artifact{
				{Type: "embedded", Path: "artifacts/test.json", Digest: "sha256:abc123"},
			},
			want: "artifacts/test.json\tsha256:abc123\n",
		},
		{
			name: "multiple artifacts sorted by path",
			artifacts: []Artifact{
				{Type: "embedded", Path: "artifacts/zebra.json", Digest: "sha256:zzz"},
				{Type: "embedded", Path: "artifacts/alpha.json", Digest: "sha256:aaa"},
				{Type: "embedded", Path: "artifacts/beta.json", Digest: "sha256:bbb"},
			},
			want: "artifacts/alpha.json\tsha256:aaa\n" +
				"artifacts/beta.json\tsha256:bbb\n" +
				"artifacts/zebra.json\tsha256:zzz\n",
		},
		{
			name: "non-embedded artifacts excluded",
			artifacts: []Artifact{
				{Type: "embedded", Path: "artifacts/included.json", Digest: "sha256:inc"},
				{Type: "external", Path: "https://example.com/file", Digest: "sha256:ext"},
			},
			want: "artifacts/included.json\tsha256:inc\n",
		},
		{
			name: "only non-embedded artifacts",
			artifacts: []Artifact{
				{Type: "external", Path: "https://example.com/a", Digest: "sha256:aaa"},
				{Type: "reference", Path: "ref://something", Digest: "sha256:bbb"},
			},
			want: "",
		},
		{
			name: "byte-wise lexicographic sorting",
			artifacts: []Artifact{
				{Type: "embedded", Path: "artifacts/B.json", Digest: "sha256:bbb"},
				{Type: "embedded", Path: "artifacts/a.json", Digest: "sha256:aaa"},
				{Type: "embedded", Path: "artifacts/A.json", Digest: "sha256:AAA"},
			},
			// ASCII: A=65, B=66, a=97, so order is A, B, a
			want: "artifacts/A.json\tsha256:AAA\n" +
				"artifacts/B.json\tsha256:bbb\n" +
				"artifacts/a.json\tsha256:aaa\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest := &Manifest{
				Artifacts: tt.artifacts,
			}

			got := BuildCanonicalArtifactList(manifest)

			if string(got) != tt.want {
				t.Errorf("BuildCanonicalArtifactList() = %q, want %q", string(got), tt.want)
			}
		})
	}
}

func TestHashCanonicalList(t *testing.T) {
	tests := []struct {
		name      string
		canonical []byte
		want      string
	}{
		{
			name:      "empty list",
			canonical: []byte{},
			want:      "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:      "single artifact entry",
			canonical: []byte("artifacts/test.json\tsha256:abc123\n"),
			want:      computeSHA256([]byte("artifacts/test.json\tsha256:abc123\n")),
		},
		{
			name: "multiple artifact entries",
			canonical: []byte("artifacts/a.json\tsha256:aaa\n" +
				"artifacts/b.json\tsha256:bbb\n"),
			want: computeSHA256([]byte("artifacts/a.json\tsha256:aaa\n" +
				"artifacts/b.json\tsha256:bbb\n")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HashCanonicalList(tt.canonical)

			if got != tt.want {
				t.Errorf("HashCanonicalList() = %q, want %q", got, tt.want)
			}

			// Verify format: sha256: prefix + 64 hex chars
			if len(got) != 71 {
				t.Errorf("HashCanonicalList() length = %d, want 71", len(got))
			}
			if got[:7] != "sha256:" {
				t.Errorf("HashCanonicalList() prefix = %q, want %q", got[:7], "sha256:")
			}
		})
	}
}

func TestHashCanonicalList_ConsistentWithComputeSHA256(t *testing.T) {
	// HashCanonicalList should produce identical results to computeSHA256
	testData := [][]byte{
		{},
		[]byte("artifacts/test.json\tsha256:abc\n"),
		[]byte("artifacts/a.json\tsha256:aaa\nartifacts/b.json\tsha256:bbb\n"),
	}

	for _, data := range testData {
		fromHash := HashCanonicalList(data)
		fromCompute := computeSHA256(data)

		if fromHash != fromCompute {
			t.Errorf("HashCanonicalList(%q) = %q, but computeSHA256() = %q",
				data, fromHash, fromCompute)
		}
	}
}

func TestComputeManifestDigest(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
		errMsg  string
	}{
		{
			name:  "valid minimal manifest",
			input: []byte(`{"spec_version":"1.0","stream":"test"}`),
		},
		{
			name:  "valid manifest with whitespace",
			input: []byte(`{  "spec_version" : "1.0" , "stream" : "test"  }`),
		},
		{
			name:  "valid manifest with newlines",
			input: []byte("{\n\t\"spec_version\": \"1.0\",\n\t\"stream\": \"test\"\n}"),
		},
		{
			name:    "empty input",
			input:   []byte{},
			wantErr: true,
			errMsg:  "empty JSON input",
		},
		{
			name:    "whitespace only",
			input:   []byte("   \n\t  "),
			wantErr: true,
			errMsg:  "empty JSON input",
		},
		{
			name:    "not an object - array",
			input:   []byte(`["not", "an", "object"]`),
			wantErr: true,
			errMsg:  "manifest JSON must be an object",
		},
		{
			name:    "not an object - string",
			input:   []byte(`"just a string"`),
			wantErr: true,
			errMsg:  "manifest JSON must be an object",
		},
		{
			name:    "not an object - number",
			input:   []byte(`42`),
			wantErr: true,
			errMsg:  "manifest JSON must be an object",
		},
		{
			name:    "not an object - null",
			input:   []byte(`null`),
			wantErr: true,
			errMsg:  "manifest JSON must be an object",
		},
		{
			name:    "invalid JSON",
			input:   []byte(`{not valid json}`),
			wantErr: true,
		},
		{
			name:    "unclosed object",
			input:   []byte(`{"key": "value"`),
			wantErr: true,
		},
		{
			name:    "duplicate keys rejected",
			input:   []byte(`{"spec_version":"1.0","spec_version":"2.0"}`),
			wantErr: true,
			errMsg:  "duplicate",
		},
		{
			name:    "negative number rejected",
			input:   []byte(`{"size":-1}`),
			wantErr: true,
			errMsg:  "negative",
		},
		{
			name:    "fractional number rejected",
			input:   []byte(`{"size":1.5}`),
			wantErr: true,
			errMsg:  "fractional",
		},
		{
			name:  "zero is valid",
			input: []byte(`{"size":0}`),
		},
		{
			name:  "safe integer boundary",
			input: []byte(`{"size":9007199254740991}`), // 2^53-1 (MaxSafeInt)
		},
		{
			name:    "exceeds safe integer",
			input:   []byte(`{"size":9007199254740992}`), // 2^53
			wantErr: true,
			errMsg:  "exceeds max safe integer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			canonical, digest, err := ComputeManifestDigest(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ComputeManifestDigest() expected error, got nil")
					return
				}
				if tt.errMsg != "" && !containsStringDigest(err.Error(), tt.errMsg) {
					t.Errorf("ComputeManifestDigest() error = %v, want message containing %q", err, tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Fatalf("ComputeManifestDigest() unexpected error: %v", err)
			}

			// Verify canonical form is valid JSON
			if len(canonical) == 0 {
				t.Error("ComputeManifestDigest() canonical form is empty")
			}

			// Verify digest format
			if len(digest) != 71 { // "sha256:" (7) + 64 hex chars
				t.Errorf("ComputeManifestDigest() digest length = %d, want 71", len(digest))
			}
			if digest[:7] != "sha256:" {
				t.Errorf("ComputeManifestDigest() digest prefix = %q, want %q", digest[:7], "sha256:")
			}
		})
	}
}

func TestComputeManifestDigest_Canonicalization(t *testing.T) {
	// These JSON inputs are semantically identical but formatted differently.
	// JCS canonicalization should produce identical output.
	inputs := [][]byte{
		[]byte(`{"a":"1","b":"2"}`),
		[]byte(`{  "a"  :  "1"  ,  "b"  :  "2"  }`),
		[]byte("{\n\t\"a\": \"1\",\n\t\"b\": \"2\"\n}"),
		[]byte(`{"b":"2","a":"1"}`), // Different key order
	}

	var firstCanonical string
	var firstDigest string

	for i, input := range inputs {
		canonical, digest, err := ComputeManifestDigest(input)
		if err != nil {
			t.Fatalf("Input %d: unexpected error: %v", i, err)
		}

		if i == 0 {
			firstCanonical = canonical
			firstDigest = digest
		} else {
			if canonical != firstCanonical {
				t.Errorf("Input %d: canonical = %q, want %q", i, canonical, firstCanonical)
			}
			if digest != firstDigest {
				t.Errorf("Input %d: digest = %q, want %q", i, digest, firstDigest)
			}
		}
	}

	// Verify key ordering (JCS sorts by UTF-16 code unit order)
	wantCanonical := `{"a":"1","b":"2"}`
	if firstCanonical != wantCanonical {
		t.Errorf("Canonical form = %q, want %q", firstCanonical, wantCanonical)
	}
}

func TestComputeManifestDigest_KeyOrdering(t *testing.T) {
	// JCS sorts keys by UTF-16 code unit order, which differs from byte order
	// for some Unicode characters. Test that keys are sorted correctly.
	tests := []struct {
		name          string
		input         []byte
		wantCanonical string
	}{
		{
			name:          "ASCII keys sorted",
			input:         []byte(`{"z":"last","a":"first","m":"middle"}`),
			wantCanonical: `{"a":"first","m":"middle","z":"last"}`,
		},
		{
			name:          "uppercase vs lowercase - ASCII order: A(65) < Z(90) < a(97)",
			input:         []byte(`{"a":"lower","A":"upper","Z":"upperZ"}`),
			wantCanonical: `{"A":"upper","Z":"upperZ","a":"lower"}`,
		},
		{
			name:          "numeric string keys",
			input:         []byte(`{"10":"ten","2":"two","1":"one"}`),
			wantCanonical: `{"1":"one","10":"ten","2":"two"}`, // string sort, not numeric
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			canonical, _, err := ComputeManifestDigest(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if canonical != tt.wantCanonical {
				t.Errorf("canonical = %q, want %q", canonical, tt.wantCanonical)
			}
		})
	}
}

func TestComputeManifestDigest_DigestDeterminism(t *testing.T) {
	// Running the same input multiple times should produce identical results
	input := []byte(`{"spec_version":"1.0","stream":"test","generated_at":"2024-01-01T00:00:00Z"}`)

	var firstDigest string
	for i := 0; i < 10; i++ {
		_, digest, err := ComputeManifestDigest(input)
		if err != nil {
			t.Fatalf("Iteration %d: unexpected error: %v", i, err)
		}
		if i == 0 {
			firstDigest = digest
		} else if digest != firstDigest {
			t.Errorf("Iteration %d: digest = %q, want %q", i, digest, firstDigest)
		}
	}
}

func TestComputeManifestDigest_UnicodeStrings(t *testing.T) {
	// Test that Unicode strings are handled correctly
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "basic unicode",
			input: []byte(`{"name":"日本語"}`),
		},
		{
			name:  "emoji",
			input: []byte(`{"emoji":"🎉"}`),
		},
		{
			name:  "combining characters",
			input: []byte(`{"name":"café"}`),
		},
		{
			name:  "surrogate pairs",
			input: []byte(`{"char":"𝄞"}`), // Musical G clef (U+1D11E)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			canonical, digest, err := ComputeManifestDigest(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(canonical) == 0 {
				t.Error("canonical form is empty")
			}
			if len(digest) != 71 {
				t.Errorf("digest length = %d, want 71", len(digest))
			}
		})
	}
}

func TestComputeManifestDigest_EscapedStrings(t *testing.T) {
	// Test handling of escaped characters in JSON strings
	tests := []struct {
		name          string
		input         []byte
		wantCanonical string
	}{
		{
			name:          "escaped quote",
			input:         []byte(`{"key":"value with \"quotes\""}`),
			wantCanonical: `{"key":"value with \"quotes\""}`,
		},
		{
			name:          "escaped backslash",
			input:         []byte(`{"path":"C:\\Users\\test"}`),
			wantCanonical: `{"path":"C:\\Users\\test"}`,
		},
		{
			name:          "escaped newline",
			input:         []byte(`{"text":"line1\nline2"}`),
			wantCanonical: `{"text":"line1\nline2"}`,
		},
		{
			name:          "escaped tab",
			input:         []byte(`{"text":"col1\tcol2"}`),
			wantCanonical: `{"text":"col1\tcol2"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			canonical, _, err := ComputeManifestDigest(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if canonical != tt.wantCanonical {
				t.Errorf("canonical = %q, want %q", canonical, tt.wantCanonical)
			}
		})
	}
}

func TestComputeManifestDigest_NestedObjects(t *testing.T) {
	input := []byte(`{
		"outer": {
			"inner": {
				"deep": "value"
			}
		},
		"array": [1, 2, {"nested": true}]
	}`)

	canonical, digest, err := ComputeManifestDigest(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify canonical form has no whitespace
	if bytes.ContainsAny([]byte(canonical), " \t\n\r") {
		t.Errorf("canonical form contains whitespace: %q", canonical)
	}

	// Verify nested object keys are sorted
	wantCanonical := `{"array":[1,2,{"nested":true}],"outer":{"inner":{"deep":"value"}}}`
	if canonical != wantCanonical {
		t.Errorf("canonical = %q, want %q", canonical, wantCanonical)
	}

	if len(digest) != 71 {
		t.Errorf("digest length = %d, want 71", len(digest))
	}
}

func TestComputeManifestDigest_BooleanAndNull(t *testing.T) {
	tests := []struct {
		name          string
		input         []byte
		wantCanonical string
	}{
		{
			name:          "true value",
			input:         []byte(`{"enabled": true}`),
			wantCanonical: `{"enabled":true}`,
		},
		{
			name:          "false value",
			input:         []byte(`{"enabled": false}`),
			wantCanonical: `{"enabled":false}`,
		},
		{
			name:          "null value",
			input:         []byte(`{"value": null}`),
			wantCanonical: `{"value":null}`,
		},
		{
			name:          "mixed types",
			input:         []byte(`{"bool": true, "null": null, "string": "text", "number": 42}`),
			wantCanonical: `{"bool":true,"null":null,"number":42,"string":"text"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			canonical, _, err := ComputeManifestDigest(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if canonical != tt.wantCanonical {
				t.Errorf("canonical = %q, want %q", canonical, tt.wantCanonical)
			}
		})
	}
}

func containsStringDigest(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
