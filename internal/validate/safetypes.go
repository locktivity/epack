package validate

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// SemVer is a validated semantic version string safe for filesystem paths and URLs.
// Can only be constructed via ParseSemVer.
//
// SECURITY: This type guarantees the version string:
// - Matches semver format (v1.2.3 or v1.2.3-prerelease)
// - Contains no path traversal patterns (/, \, ..)
// - Contains no URL-unsafe characters in prerelease
// - Is under MaxVersionLength bytes
type SemVer string

// ParseSemVer validates and returns a SemVer.
// Returns an error if the version contains path traversal or invalid characters.
func ParseSemVer(version string) (SemVer, error) {
	if err := Version(version); err != nil {
		return "", err
	}
	return SemVer(version), nil
}

// MustParseSemVer parses a version, panicking on invalid input.
// Use only for compile-time constants or test fixtures.
func MustParseSemVer(version string) SemVer {
	v, err := ParseSemVer(version)
	if err != nil {
		panic(err)
	}
	return v
}

// String returns the version as a string.
func (v SemVer) String() string {
	return string(v)
}

// UnmarshalYAML implements yaml.Unmarshaler with validation.
func (v *SemVer) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	parsed, err := ParseSemVer(s)
	if err != nil {
		return err
	}
	*v = parsed
	return nil
}

// UnmarshalJSON implements json.Unmarshaler with validation.
func (v *SemVer) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsed, err := ParseSemVer(s)
	if err != nil {
		return err
	}
	*v = parsed
	return nil
}

// MaxSafeInt is the maximum integer exactly representable in JSON (2^53 - 1).
// JavaScript and many JSON parsers use IEEE 754 doubles which lose precision
// above this value.
const MaxSafeInt int64 = (1 << 53) - 1

// SafeInt is a JSON-safe non-negative integer that fits within IEEE 754 double precision.
// Can only be constructed via ParseSafeInt or NewSafeInt.
//
// SECURITY: This type guarantees the integer:
// - Is non-negative (>= 0)
// - Is at most MaxSafeInt (2^53 - 1)
// - Will be parsed identically by all JSON parsers
type SafeInt int64

// ParseSafeInt validates and returns a SafeInt from an int64.
// Returns an error if the value is negative or exceeds MaxSafeInt.
func ParseSafeInt(n int64) (SafeInt, error) {
	if n < 0 {
		return 0, fmt.Errorf("safe integer %d is invalid: must be non-negative", n)
	}
	if n > MaxSafeInt {
		return 0, fmt.Errorf("safe integer %d exceeds maximum safe value %d", n, MaxSafeInt)
	}
	return SafeInt(n), nil
}

// NewSafeInt creates a SafeInt, panicking if the value is invalid.
// Use only for compile-time constants or when the value is guaranteed valid.
func NewSafeInt(n int64) SafeInt {
	s, err := ParseSafeInt(n)
	if err != nil {
		panic(err)
	}
	return s
}

// Int64 returns the SafeInt as an int64.
func (s SafeInt) Int64() int64 {
	return int64(s)
}

// String returns the SafeInt as a decimal string.
func (s SafeInt) String() string {
	return strconv.FormatInt(int64(s), 10)
}

// UnmarshalJSON implements json.Unmarshaler with validation.
// Accepts both JSON numbers and JSON strings containing integers.
func (s *SafeInt) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as json.Number first (handles both number and string)
	var n json.Number
	if err := json.Unmarshal(data, &n); err != nil {
		return fmt.Errorf("invalid safe integer: %w", err)
	}

	v, err := n.Int64()
	if err != nil {
		return fmt.Errorf("invalid safe integer: %w", err)
	}

	parsed, err := ParseSafeInt(v)
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}

// MarshalJSON implements json.Marshaler.
func (s SafeInt) MarshalJSON() ([]byte, error) {
	return []byte(strconv.FormatInt(int64(s), 10)), nil
}

// UnmarshalYAML implements yaml.Unmarshaler with validation.
func (s *SafeInt) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var v int64
	if err := unmarshal(&v); err != nil {
		return err
	}

	parsed, err := ParseSafeInt(v)
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}
