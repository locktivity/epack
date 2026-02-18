package sign

import (
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/intoto"
	"github.com/locktivity/epack/internal/packpath"
)

func TestNewStatement_ValidSHA256(t *testing.T) {
	// Valid SHA-256 digest (64 hex chars)
	digest := "sha256:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
	stream := "org/test-stream"

	stmt, err := NewStatement(digest, stream)
	if err != nil {
		t.Fatalf("NewStatement() error: %v", err)
	}

	// Verify statement type
	if stmt.Type != intoto.StatementType {
		t.Errorf("Type = %q, want %q", stmt.Type, intoto.StatementType)
	}

	// Verify predicate type
	if stmt.PredicateType != intoto.EvidencePackPredicateType {
		t.Errorf("PredicateType = %q, want %q", stmt.PredicateType, intoto.EvidencePackPredicateType)
	}

	// Verify subject
	if len(stmt.Subject) != 1 {
		t.Fatalf("len(Subject) = %d, want 1", len(stmt.Subject))
	}
	if stmt.Subject[0].Name != packpath.Manifest {
		t.Errorf("Subject[0].Name = %q, want %q", stmt.Subject[0].Name, packpath.Manifest)
	}
	if stmt.Subject[0].Digest["sha256"] != "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2" {
		t.Errorf("Subject[0].Digest[sha256] = %q, want hash", stmt.Subject[0].Digest["sha256"])
	}

	// Verify predicate
	if stmt.Predicate.PackDigest != digest {
		t.Errorf("Predicate.PackDigest = %q, want %q", stmt.Predicate.PackDigest, digest)
	}
	if stmt.Predicate.Stream != stream {
		t.Errorf("Predicate.Stream = %q, want %q", stmt.Predicate.Stream, stream)
	}
}

func TestNewStatement_ValidSHA512(t *testing.T) {
	// Valid SHA-512 digest (128 hex chars)
	hash := strings.Repeat("a1b2c3d4", 16) // 128 chars
	digest := "sha512:" + hash
	stream := "org/test-stream"

	stmt, err := NewStatement(digest, stream)
	if err != nil {
		t.Fatalf("NewStatement() error: %v", err)
	}

	if stmt.Subject[0].Digest["sha512"] != hash {
		t.Errorf("Subject[0].Digest[sha512] = %q, want hash", stmt.Subject[0].Digest["sha512"])
	}
}

func TestNewStatement_InvalidFormat(t *testing.T) {
	tests := []struct {
		name   string
		digest string
		errMsg string
	}{
		{
			name:   "missing colon",
			digest: "sha256abc123",
			errMsg: "expected format",
		},
		{
			name:   "empty algo",
			digest: ":abc123",
			errMsg: "unsupported digest algorithm",
		},
		{
			name:   "empty hash",
			digest: "sha256:",
			errMsg: "must be 64 hex characters",
		},
		{
			name:   "unsupported algorithm",
			digest: "md5:d41d8cd98f00b204e9800998ecf8427e",
			errMsg: "unsupported digest algorithm",
		},
		{
			name:   "sha256 wrong length",
			digest: "sha256:abc123",
			errMsg: "must be 64 hex characters",
		},
		{
			name:   "sha512 wrong length",
			digest: "sha512:abc123",
			errMsg: "must be 128 hex characters",
		},
		{
			name:   "invalid hex",
			digest: "sha256:ghijklmnopqrstuvwxyzghijklmnopqrstuvwxyzghijklmnopqrstuvwxyz1234",
			errMsg: "invalid hex",
		},
		{
			name:   "spaces in hash",
			digest: "sha256:a1b2c3d4 e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b",
			errMsg: "invalid hex",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewStatement(tt.digest, "org/stream")
			if err == nil {
				t.Errorf("NewStatement(%q) expected error containing %q, got nil", tt.digest, tt.errMsg)
				return
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("NewStatement(%q) error = %q, want containing %q", tt.digest, err.Error(), tt.errMsg)
			}
		})
	}
}

func TestParseDigest_Valid(t *testing.T) {
	tests := []struct {
		digest   string
		wantAlgo string
		wantHash string
	}{
		{
			digest:   "sha256:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
			wantAlgo: "sha256",
			wantHash: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
		},
		{
			digest:   "sha512:" + strings.Repeat("0", 128),
			wantAlgo: "sha512",
			wantHash: strings.Repeat("0", 128),
		},
	}

	for _, tt := range tests {
		t.Run(tt.wantAlgo, func(t *testing.T) {
			algo, hash, err := parseDigest(tt.digest)
			if err != nil {
				t.Fatalf("parseDigest(%q) error: %v", tt.digest, err)
			}
			if algo != tt.wantAlgo {
				t.Errorf("algo = %q, want %q", algo, tt.wantAlgo)
			}
			if hash != tt.wantHash {
				t.Errorf("hash = %q, want %q", hash, tt.wantHash)
			}
		})
	}
}

func TestParseDigest_Invalid(t *testing.T) {
	tests := []struct {
		name   string
		digest string
		errMsg string
	}{
		{"no separator", "sha256abc", "expected format"},
		{"empty", "", "expected format"},
		{"only colon", ":", "unsupported digest algorithm"},
		{"unknown algo", "blake2:abcd", "unsupported digest algorithm"},
		{"sha256 too short", "sha256:abc", "must be 64 hex characters, got 3"},
		{"sha256 too long", "sha256:" + strings.Repeat("a", 65), "must be 64 hex characters, got 65"},
		{"sha512 too short", "sha512:" + strings.Repeat("a", 127), "must be 128 hex characters, got 127"},
		{"sha512 too long", "sha512:" + strings.Repeat("a", 129), "must be 128 hex characters, got 129"},
		{"non-hex chars", "sha256:" + strings.Repeat("g", 64), "invalid hex"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := parseDigest(tt.digest)
			if err == nil {
				t.Errorf("parseDigest(%q) expected error, got nil", tt.digest)
				return
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("parseDigest(%q) error = %q, want containing %q", tt.digest, err.Error(), tt.errMsg)
			}
		})
	}
}
