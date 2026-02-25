package timestamp

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

// FuzzParse tests timestamp parsing with fuzzed inputs.
// The format must be exactly "YYYY-MM-DDTHH:MM:SSZ" (20 chars, UTC).
func FuzzParse(f *testing.F) {
	// Valid timestamps
	f.Add("2024-01-15T10:30:00Z")
	f.Add("2024-12-31T23:59:59Z")
	f.Add("2024-01-01T00:00:00Z")
	f.Add("1970-01-01T00:00:00Z")
	f.Add("9999-12-31T23:59:59Z")

	// Invalid dates (should be rejected by time.Parse)
	f.Add("2024-02-30T10:30:00Z") // Feb 30
	f.Add("2024-04-31T10:30:00Z") // Apr 31
	f.Add("2024-00-15T10:30:00Z") // Month 0
	f.Add("2024-13-15T10:30:00Z") // Month 13
	f.Add("2024-01-00T10:30:00Z") // Day 0
	f.Add("2024-01-32T10:30:00Z") // Day 32

	// Invalid times
	f.Add("2024-01-15T24:00:00Z") // Hour 24
	f.Add("2024-01-15T10:60:00Z") // Minute 60
	f.Add("2024-01-15T10:30:60Z") // Second 60 (not a leap second)

	// Wrong timezone format (should reject)
	f.Add("2024-01-15T10:30:00+00:00")
	f.Add("2024-01-15T10:30:00-05:00")
	f.Add("2024-01-15T10:30:00z") // lowercase z
	f.Add("2024-01-15T10:30:00")  // no timezone

	// Fractional seconds (should reject)
	f.Add("2024-01-15T10:30:00.000Z")
	f.Add("2024-01-15T10:30:00.123456789Z")

	// Wrong length
	f.Add("2024-01-15T10:30:00ZZ") // too long
	f.Add("2024-01-15T10:30:0Z")   // too short
	f.Add("24-01-15T10:30:00Z")    // 2-digit year
	f.Add("2024-1-15T10:30:00Z")   // 1-digit month
	f.Add("2024-01-5T10:30:00Z")   // 1-digit day
	f.Add("2024-01-15T1:30:00Z")   // 1-digit hour
	f.Add("2024-01-15T10:3:00Z")   // 1-digit minute
	f.Add("2024-01-15T10:30:0Z")   // 1-digit second

	// Completely wrong formats
	f.Add("")
	f.Add("not a timestamp")
	f.Add("2024/01/15 10:30:00")
	f.Add("Jan 15, 2024 10:30:00")
	f.Add("1705315800") // Unix timestamp

	// Edge cases with special characters
	f.Add("2024-01-15T10:30:00\x00")
	f.Add("\x002024-01-15T10:30:00Z")

	f.Fuzz(func(t *testing.T, s string) {
		ts, err := Parse(s)

		if err == nil {
			// Property: String() round-trips exactly
			if ts.String() != s {
				t.Errorf("round-trip failed: input=%q, output=%q", s, ts.String())
			}

			// Property: Must be exactly 20 characters
			if len(s) != formatLength {
				t.Errorf("accepted timestamp of wrong length: %d chars", len(s))
			}

			// Property: Must end with Z
			if !strings.HasSuffix(s, "Z") {
				t.Errorf("accepted timestamp not ending with Z: %q", s)
			}

			// Property: IsZero must be false
			if ts.IsZero() {
				t.Errorf("valid timestamp reports IsZero")
			}

			// Property: Time() should return valid time
			if ts.Time().IsZero() {
				t.Errorf("valid timestamp has zero Time()")
			}

			// Property: Time should be in UTC
			if ts.Time().Location() != time.UTC {
				t.Errorf("parsed time not in UTC: %v", ts.Time().Location())
			}
		}
	})
}

// FuzzValidate tests the standalone validation function.
func FuzzValidate(f *testing.F) {
	f.Add("2024-01-15T10:30:00Z")
	f.Add("2024-02-30T10:30:00Z") // invalid date
	f.Add("invalid")
	f.Add("")

	f.Fuzz(func(t *testing.T, s string) {
		validateErr := Validate(s)
		_, parseErr := Parse(s)

		// Property: Validate and Parse must agree
		if (validateErr == nil) != (parseErr == nil) {
			t.Errorf("Validate and Parse disagree for %q: validate=%v, parse=%v",
				s, validateErr, parseErr)
		}
	})
}

// FuzzFromTime tests conversion from time.Time.
func FuzzFromTime(f *testing.F) {
	// Unix timestamps covering various edge cases
	f.Add(int64(0))            // epoch
	f.Add(int64(1705315800))   // 2024-01-15T10:30:00Z
	f.Add(int64(-1))           // before epoch
	f.Add(int64(253402300799)) // 9999-12-31T23:59:59Z
	f.Add(int64(1000000000))   // 2001-09-09
	f.Add(int64(1609459200))   // 2021-01-01T00:00:00Z

	f.Fuzz(func(t *testing.T, unixSec int64) {
		// Skip extreme values that would cause issues
		if unixSec < -62135596800 || unixSec > 253402300799 {
			return
		}

		inputTime := time.Unix(unixSec, 123456789) // with nanoseconds
		ts := FromTime(inputTime)

		// Property: Result is valid (not zero)
		if ts.IsZero() {
			t.Errorf("FromTime returned zero for %v", inputTime)
		}

		// Property: String format is correct length
		if len(ts.String()) != formatLength {
			t.Errorf("FromTime produced wrong length: %d", len(ts.String()))
		}

		// Property: Ends with Z
		if !strings.HasSuffix(ts.String(), "Z") {
			t.Errorf("FromTime produced non-Z timestamp: %q", ts.String())
		}

		// Property: Time is truncated to seconds (no sub-second precision)
		resultTime := ts.Time()
		if resultTime.Nanosecond() != 0 {
			t.Errorf("FromTime preserved nanoseconds: %d", resultTime.Nanosecond())
		}

		// Property: Time is in UTC
		if resultTime.Location() != time.UTC {
			t.Errorf("FromTime not in UTC")
		}

		// Property: Parses back correctly
		parsed, err := Parse(ts.String())
		if err != nil {
			t.Errorf("FromTime result doesn't parse: %v", err)
		}
		if !ts.Equal(parsed) {
			t.Errorf("FromTime->Parse round-trip failed")
		}
	})
}

// FuzzEqual tests timestamp equality.
func FuzzEqual(f *testing.F) {
	f.Add("2024-01-15T10:30:00Z", "2024-01-15T10:30:00Z")
	f.Add("2024-01-15T10:30:00Z", "2024-01-15T10:30:01Z")
	f.Add("", "2024-01-15T10:30:00Z")
	f.Add("invalid", "invalid")

	f.Fuzz(func(t *testing.T, s1, s2 string) {
		ts1, _ := Parse(s1)
		ts2, _ := Parse(s2)

		// Property: Reflexivity for valid timestamps
		if !ts1.IsZero() && !ts1.Equal(ts1) {
			t.Errorf("reflexivity failed for %q", s1)
		}

		// Property: Symmetry
		if ts1.Equal(ts2) != ts2.Equal(ts1) {
			t.Errorf("symmetry failed: %q vs %q", s1, s2)
		}

		// Property: Equal implies same string
		if ts1.Equal(ts2) && !ts1.IsZero() && !ts2.IsZero() {
			if ts1.String() != ts2.String() {
				t.Errorf("equal timestamps have different strings: %q vs %q",
					ts1.String(), ts2.String())
			}
		}
	})
}

// FuzzBeforeAfter tests temporal ordering.
func FuzzBeforeAfter(f *testing.F) {
	f.Add("2024-01-15T10:30:00Z", "2024-01-15T10:30:01Z")
	f.Add("2024-01-15T10:30:00Z", "2024-01-15T10:30:00Z")
	f.Add("2024-01-15T10:30:01Z", "2024-01-15T10:30:00Z")
	f.Add("", "2024-01-15T10:30:00Z")

	f.Fuzz(func(t *testing.T, s1, s2 string) {
		ts1, _ := Parse(s1)
		ts2, _ := Parse(s2)

		before := ts1.Before(ts2)
		after := ts1.After(ts2)
		equal := ts1.Equal(ts2)

		// Property: Zero timestamps return false for Before/After
		if ts1.IsZero() || ts2.IsZero() {
			if before || after {
				t.Errorf("zero timestamp returned true for Before/After")
			}
			return
		}

		// Property: Exactly one of before, after, equal must be true
		count := 0
		if before {
			count++
		}
		if after {
			count++
		}
		if equal {
			count++
		}
		if count != 1 {
			t.Errorf("exactly one ordering must be true: before=%v, after=%v, equal=%v",
				before, after, equal)
		}

		// Property: Before and After are inverses
		if before != ts2.After(ts1) {
			t.Errorf("Before/After not inverse: ts1.Before(ts2)=%v, ts2.After(ts1)=%v",
				before, ts2.After(ts1))
		}
	})
}

// FuzzJSONRoundTrip tests JSON marshaling/unmarshaling.
func FuzzJSONRoundTrip(f *testing.F) {
	f.Add("2024-01-15T10:30:00Z")
	f.Add("")
	f.Add("invalid")

	f.Fuzz(func(t *testing.T, s string) {
		ts, parseErr := Parse(s)

		// Marshal
		jsonBytes, marshalErr := json.Marshal(ts)
		if marshalErr != nil {
			t.Errorf("Marshal failed: %v", marshalErr)
			return
		}

		// Unmarshal
		var ts2 Timestamp
		if err := json.Unmarshal(jsonBytes, &ts2); err != nil {
			if parseErr == nil {
				t.Errorf("Unmarshal failed for valid timestamp: %v", err)
			}
			return
		}

		// Property: Valid timestamps round-trip
		if parseErr == nil {
			if !ts.Equal(ts2) {
				t.Errorf("JSON round-trip failed: %q -> %q", ts.String(), ts2.String())
			}
		}

		// Property: Zero timestamps marshal to empty string
		if ts.IsZero() {
			if string(jsonBytes) != `""` {
				t.Errorf("zero timestamp didn't marshal to empty: %s", jsonBytes)
			}
		}
	})
}

// FuzzSub tests duration calculation between timestamps.
func FuzzSub(f *testing.F) {
	f.Add("2024-01-15T10:30:00Z", "2024-01-15T10:30:00Z")
	f.Add("2024-01-15T10:30:01Z", "2024-01-15T10:30:00Z")
	f.Add("2024-01-15T10:30:00Z", "2024-01-15T10:30:01Z")
	f.Add("", "2024-01-15T10:30:00Z")

	f.Fuzz(func(t *testing.T, s1, s2 string) {
		ts1, _ := Parse(s1)
		ts2, _ := Parse(s2)

		dur := ts1.Sub(ts2)

		// Property: Zero timestamps return 0 duration
		if ts1.IsZero() || ts2.IsZero() {
			if dur != 0 {
				t.Errorf("Sub with zero timestamp returned non-zero: %v", dur)
			}
			return
		}

		// Property: ts1.Sub(ts2) == -ts2.Sub(ts1)
		// Skip at overflow boundaries: math.MinInt64 cannot be negated without overflow
		// because int64 range is [-2^63, 2^63-1], so -math.MinInt64 overflows.
		reverseDur := ts2.Sub(ts1)
		if dur != time.Duration(math.MinInt64) && reverseDur != time.Duration(math.MinInt64) {
			if dur != -reverseDur {
				t.Errorf("Sub not antisymmetric: %v vs %v", dur, reverseDur)
			}
		}

		// Property: Equal timestamps have zero difference
		if ts1.Equal(ts2) && dur != 0 {
			t.Errorf("equal timestamps have non-zero Sub: %v", dur)
		}

		// Property: Duration matches underlying time difference
		expectedDur := ts1.Time().Sub(ts2.Time())
		if dur != expectedDur {
			t.Errorf("Sub mismatch: got %v, expected %v", dur, expectedDur)
		}
	})
}
