// Package digest provides a type-safe SHA256 digest implementation.
//
// The Digest type enforces the canonical format "sha256:<64 lowercase hex chars>"
// at construction time and provides constant-time comparison to prevent timing
// side-channel attacks.
//
// # Usage
//
//	d, err := digest.Parse("sha256:abc123...")
//	if err != nil {
//	    // handle invalid format
//	}
//
//	// Compute from bytes
//	d := digest.FromBytes(data)
//
//	// Constant-time comparison
//	if d.Equal(other) { ... }
//
// # Security Properties
//
//   - Format validation at parse time (rejects malformed digests)
//   - Constant-time comparison (prevents timing attacks)
//   - Immutable after construction (prevents TOCTOU)
//   - JSON marshaling preserves format exactly
package digest

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
)

// digestRegex validates the canonical digest format.
// Must be lowercase hex to ensure deterministic string representation.
var digestRegex = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// Digest represents a SHA256 digest in canonical format.
// The zero value is invalid; use Parse, FromBytes, or FromReader to create.
type Digest struct {
	value string // Always "sha256:<64 lowercase hex chars>" or empty
}

// Parse parses a digest string in canonical format.
// Returns an error if the format is invalid.
func Parse(s string) (Digest, error) {
	if !digestRegex.MatchString(s) {
		return Digest{}, fmt.Errorf("invalid digest format: must be sha256:<64 lowercase hex chars>, got %q", s)
	}
	return Digest{value: s}, nil
}

// MustParse parses a digest string, panicking if invalid.
// Use only for compile-time constants and tests.
func MustParse(s string) Digest {
	d, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return d
}

// FromBytes computes the SHA256 digest of the given data.
func FromBytes(data []byte) Digest {
	h := sha256.Sum256(data)
	return Digest{value: "sha256:" + hex.EncodeToString(h[:])}
}

// FromReader computes the SHA256 digest by reading from r.
func FromReader(r io.Reader) (Digest, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return Digest{}, err
	}
	return Digest{value: "sha256:" + hex.EncodeToString(h.Sum(nil))}, nil
}

// String returns the canonical string representation.
// Returns empty string for zero-value Digest.
func (d Digest) String() string {
	return d.value
}

// IsZero reports whether d is the zero value (invalid/unset).
func (d Digest) IsZero() bool {
	return d.value == ""
}

// Equal reports whether d and other represent the same digest.
// Uses constant-time comparison to prevent timing side-channel attacks.
// Returns false if either digest is zero.
func (d Digest) Equal(other Digest) bool {
	if d.IsZero() || other.IsZero() {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(d.value), []byte(other.value)) == 1
}

// Hex returns just the hex portion of the digest (without "sha256:" prefix).
// Returns empty string for zero-value Digest.
func (d Digest) Hex() string {
	if d.IsZero() {
		return ""
	}
	return d.value[7:] // Skip "sha256:"
}

// MarshalJSON implements json.Marshaler.
func (d Digest) MarshalJSON() ([]byte, error) {
	if d.IsZero() {
		return []byte(`""`), nil
	}
	return json.Marshal(d.value)
}

// UnmarshalJSON implements json.Unmarshaler.
// Validates the digest format during unmarshaling.
func (d *Digest) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s == "" {
		*d = Digest{}
		return nil
	}
	parsed, err := Parse(s)
	if err != nil {
		return err
	}
	*d = parsed
	return nil
}

// Validate checks if a string is a valid digest format without allocating a Digest.
// This is useful for validation-only scenarios.
func Validate(s string) error {
	if !digestRegex.MatchString(s) {
		return fmt.Errorf("invalid digest format: must be sha256:<64 lowercase hex chars>")
	}
	return nil
}

// Hasher accumulates data for digest computation.
// Use NewHasher to create, Write to add data, and Digest to get the result.
// Hasher implements io.Writer for use with io.Copy, io.TeeReader, etc.
type Hasher struct {
	h interface {
		io.Writer
		Sum([]byte) []byte
	}
}

// NewHasher creates a new Hasher for incremental digest computation.
func NewHasher() *Hasher {
	return &Hasher{h: sha256.New()}
}

// Write implements io.Writer, adding data to the hash computation.
func (h *Hasher) Write(p []byte) (n int, err error) {
	return h.h.Write(p)
}

// Digest returns the computed digest.
// The Hasher can continue to be used after calling Digest.
func (h *Hasher) Digest() Digest {
	return Digest{value: "sha256:" + hex.EncodeToString(h.h.Sum(nil))}
}
