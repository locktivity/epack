// Package timestamp provides a type-safe timestamp implementation for evidence packs.
//
// The Timestamp type enforces the exact format "YYYY-MM-DDTHH:MM:SSZ" (RFC 3339 strict)
// required by the evidence pack spec. This format is critical for JCS canonicalization -
// different timestamp representations (fractional seconds, timezone offsets) would
// produce different manifest digests.
//
// # Format Requirements
//
//   - Exactly 20 characters
//   - UTC timezone (trailing "Z")
//   - No fractional seconds
//   - No timezone offsets
//
// # Usage
//
//	ts := timestamp.Now()
//	ts, err := timestamp.Parse("2024-01-15T10:30:00Z")
//	ts := timestamp.FromTime(time.Now())
//
// # Security Properties
//
//   - Format validation at parse time
//   - Immutable after construction
//   - JSON marshaling preserves exact format
package timestamp

import (
	"encoding/json"
	"fmt"
	"time"
)

// Format is the exact timestamp format required by the evidence pack spec.
// This is a strict subset of RFC 3339: no fractional seconds, no timezone offsets.
const Format = "2006-01-02T15:04:05Z"

// formatLength is the exact length of a valid timestamp string.
const formatLength = 20 // "YYYY-MM-DDTHH:MM:SSZ"

// Timestamp represents a timestamp in the canonical evidence pack format.
// The zero value is invalid; use Now, Parse, or FromTime to create.
type Timestamp struct {
	value string    // Always exactly 20 chars "YYYY-MM-DDTHH:MM:SSZ" or empty
	t     time.Time // Cached parsed time
}

// Now returns the current time as a Timestamp.
func Now() Timestamp {
	t := time.Now().UTC()
	return Timestamp{
		value: t.Format(Format),
		t:     t.Truncate(time.Second), // Truncate to match string representation
	}
}

// FromTime converts a time.Time to a Timestamp.
// The time is converted to UTC and truncated to second precision.
func FromTime(t time.Time) Timestamp {
	utc := t.UTC().Truncate(time.Second)
	return Timestamp{
		value: utc.Format(Format),
		t:     utc,
	}
}

// Parse parses a timestamp string in the canonical format.
// Returns an error if the format is invalid.
func Parse(s string) (Timestamp, error) {
	// Quick length check before parsing
	if len(s) != formatLength {
		return Timestamp{}, fmt.Errorf("timestamp must be exactly %d characters (YYYY-MM-DDTHH:MM:SSZ), got %d: %q", formatLength, len(s), s)
	}

	t, err := time.Parse(Format, s)
	if err != nil {
		return Timestamp{}, fmt.Errorf("invalid timestamp format (must be YYYY-MM-DDTHH:MM:SSZ): %q", s)
	}

	return Timestamp{value: s, t: t}, nil
}

// MustParse parses a timestamp string, panicking if invalid.
// Use only for compile-time constants and tests.
func MustParse(s string) Timestamp {
	ts, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return ts
}

// String returns the canonical string representation.
// Returns empty string for zero-value Timestamp.
func (ts Timestamp) String() string {
	return ts.value
}

// Time returns the underlying time.Time value.
// Returns zero time for zero-value Timestamp.
func (ts Timestamp) Time() time.Time {
	return ts.t
}

// IsZero reports whether ts is the zero value (invalid/unset).
func (ts Timestamp) IsZero() bool {
	return ts.value == ""
}

// Equal reports whether ts and other represent the same timestamp.
func (ts Timestamp) Equal(other Timestamp) bool {
	return ts.value == other.value
}

// Before reports whether ts is before other.
// Returns false if either timestamp is zero.
func (ts Timestamp) Before(other Timestamp) bool {
	if ts.IsZero() || other.IsZero() {
		return false
	}
	return ts.t.Before(other.t)
}

// After reports whether ts is after other.
// Returns false if either timestamp is zero.
func (ts Timestamp) After(other Timestamp) bool {
	if ts.IsZero() || other.IsZero() {
		return false
	}
	return ts.t.After(other.t)
}

// Sub returns the duration ts - other.
// Returns 0 if either timestamp is zero.
func (ts Timestamp) Sub(other Timestamp) time.Duration {
	if ts.IsZero() || other.IsZero() {
		return 0
	}
	return ts.t.Sub(other.t)
}

// MarshalJSON implements json.Marshaler.
func (ts Timestamp) MarshalJSON() ([]byte, error) {
	if ts.IsZero() {
		return []byte(`""`), nil
	}
	return json.Marshal(ts.value)
}

// UnmarshalJSON implements json.Unmarshaler.
// Validates the timestamp format during unmarshaling.
func (ts *Timestamp) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s == "" {
		*ts = Timestamp{}
		return nil
	}
	parsed, err := Parse(s)
	if err != nil {
		return err
	}
	*ts = parsed
	return nil
}

// Validate checks if a string is a valid timestamp format without allocating a Timestamp.
// This is useful for validation-only scenarios.
func Validate(s string) error {
	if len(s) != formatLength {
		return fmt.Errorf("timestamp must be exactly %d characters (YYYY-MM-DDTHH:MM:SSZ)", formatLength)
	}
	if _, err := time.Parse(Format, s); err != nil {
		return fmt.Errorf("invalid timestamp format (must be YYYY-MM-DDTHH:MM:SSZ): %q", s)
	}
	return nil
}
