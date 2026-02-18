package output

import (
	"encoding/json"
	"testing"
)

func TestFormatDigest(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "short digest unchanged",
			input: "sha256:abc",
			want:  "sha256:abc",
		},
		{
			name:  "exactly max length",
			input: "sha256:abcdefghijk", // 19 chars
			want:  "sha256:abcdefghijk",
		},
		{
			name:  "truncates long digest",
			input: "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234",
			want:  "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234"[:DigestMaxLen] + "...",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatDigest(tt.input)
			if got != tt.want {
				t.Errorf("FormatDigest(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestTruncateDigest(t *testing.T) {
	tests := []struct {
		name   string
		digest string
		maxLen int
		want   string
	}{
		{
			name:   "custom max length",
			digest: "sha256:abcdef1234567890",
			maxLen: 10,
			want:   "sha256:abc...",
		},
		{
			name:   "zero maxLen uses default",
			digest: "sha256:abcdef1234567890abcdef1234567890",
			maxLen: 0,
			want:   "sha256:abcdef1234567890abcdef1234567890"[:DigestMaxLen] + "...",
		},
		{
			name:   "negative maxLen uses default",
			digest: "sha256:abcdef1234567890abcdef1234567890",
			maxLen: -5,
			want:   "sha256:abcdef1234567890abcdef1234567890"[:DigestMaxLen] + "...",
		},
		{
			name:   "short digest with small maxLen",
			digest: "abc",
			maxLen: 10,
			want:   "abc",
		},
		{
			name:   "maxLen of 1",
			digest: "sha256:abc",
			maxLen: 1,
			want:   "s...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TruncateDigest(tt.digest, tt.maxLen)
			if got != tt.want {
				t.Errorf("TruncateDigest(%q, %d) = %q, want %q", tt.digest, tt.maxLen, got, tt.want)
			}
		})
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		name  string
		input int64
		want  string
	}{
		{
			name:  "zero bytes",
			input: 0,
			want:  "0 B",
		},
		{
			name:  "small bytes",
			input: 512,
			want:  "512 B",
		},
		{
			name:  "one byte below KB",
			input: 1023,
			want:  "1023 B",
		},
		{
			name:  "exactly 1 KB",
			input: 1024,
			want:  "1.0 KB",
		},
		{
			name:  "kilobytes",
			input: 2048,
			want:  "2.0 KB",
		},
		{
			name:  "fractional KB",
			input: 1536,
			want:  "1.5 KB",
		},
		{
			name:  "one byte below MB",
			input: 1024*1024 - 1,
			want:  "1024.0 KB",
		},
		{
			name:  "exactly 1 MB",
			input: 1024 * 1024,
			want:  "1.0 MB",
		},
		{
			name:  "megabytes",
			input: 5 * 1024 * 1024,
			want:  "5.0 MB",
		},
		{
			name:  "one byte below GB",
			input: 1024*1024*1024 - 1,
			want:  "1024.0 MB",
		},
		{
			name:  "exactly 1 GB",
			input: 1024 * 1024 * 1024,
			want:  "1.0 GB",
		},
		{
			name:  "gigabytes",
			input: 2 * 1024 * 1024 * 1024,
			want:  "2.0 GB",
		},
		{
			name:  "large GB value",
			input: 100 * 1024 * 1024 * 1024,
			want:  "100.0 GB",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatBytes(tt.input)
			if got != tt.want {
				t.Errorf("FormatBytes(%d) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestFormatBytesFromJSON(t *testing.T) {
	tests := []struct {
		name  string
		input *json.Number
		want  string
	}{
		{
			name:  "nil returns empty",
			input: nil,
			want:  "",
		},
		{
			name:  "valid integer",
			input: jsonNumber("1024"),
			want:  "1.0 KB",
		},
		{
			name:  "zero",
			input: jsonNumber("0"),
			want:  "0 B",
		},
		{
			name:  "large value",
			input: jsonNumber("1073741824"), // 1 GB
			want:  "1.0 GB",
		},
		{
			name:  "invalid number returns string",
			input: jsonNumber("not-a-number"),
			want:  "not-a-number",
		},
		{
			name:  "float returns string representation",
			input: jsonNumber("1024.5"),
			want:  "1024.5", // Int64() fails, returns original string
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatBytesFromJSON(tt.input)
			if got != tt.want {
				t.Errorf("FormatBytesFromJSON(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// jsonNumber is a helper to create *json.Number for tests.
func jsonNumber(s string) *json.Number {
	n := json.Number(s)
	return &n
}
