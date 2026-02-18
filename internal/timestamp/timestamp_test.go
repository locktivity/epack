package timestamp

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid timestamp",
			input:   "2024-01-15T10:30:00Z",
			wantErr: false,
		},
		{
			name:    "valid timestamp midnight",
			input:   "2024-01-01T00:00:00Z",
			wantErr: false,
		},
		{
			name:    "valid timestamp end of day",
			input:   "2024-12-31T23:59:59Z",
			wantErr: false,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "fractional seconds",
			input:   "2024-01-15T10:30:00.000Z",
			wantErr: true,
		},
		{
			name:    "timezone offset",
			input:   "2024-01-15T10:30:00+00:00",
			wantErr: true,
		},
		{
			name:    "timezone offset non-zero",
			input:   "2024-01-15T10:30:00-05:00",
			wantErr: true,
		},
		{
			name:    "missing Z",
			input:   "2024-01-15T10:30:00",
			wantErr: true,
		},
		{
			name:    "lowercase z",
			input:   "2024-01-15T10:30:00z",
			wantErr: true,
		},
		{
			name:    "too short",
			input:   "2024-01-15",
			wantErr: true,
		},
		{
			name:    "too long",
			input:   "2024-01-15T10:30:00Z ",
			wantErr: true,
		},
		{
			name:    "invalid month",
			input:   "2024-13-15T10:30:00Z",
			wantErr: true,
		},
		{
			name:    "invalid day",
			input:   "2024-01-32T10:30:00Z",
			wantErr: true,
		},
		{
			name:    "invalid hour",
			input:   "2024-01-15T25:30:00Z",
			wantErr: true,
		},
		{
			name:    "space instead of T",
			input:   "2024-01-15 10:30:00Z",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts, err := Parse(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && ts.String() != tt.input {
				t.Errorf("Parse(%q).String() = %q, want %q", tt.input, ts.String(), tt.input)
			}
		})
	}
}

func TestNow(t *testing.T) {
	ts := Now()
	if ts.IsZero() {
		t.Error("Now() should not be zero")
	}
	if len(ts.String()) != 20 {
		t.Errorf("Now() string length = %d, want 20", len(ts.String()))
	}
	// Verify it parses back
	if _, err := Parse(ts.String()); err != nil {
		t.Errorf("Now() produced unparseable timestamp: %v", err)
	}
}

func TestFromTime(t *testing.T) {
	// Test UTC time
	utc := time.Date(2024, 6, 15, 12, 30, 45, 123456789, time.UTC)
	ts := FromTime(utc)
	want := "2024-06-15T12:30:45Z" // Nanoseconds truncated
	if ts.String() != want {
		t.Errorf("FromTime(UTC) = %q, want %q", ts.String(), want)
	}

	// Test non-UTC time (should convert to UTC)
	loc, _ := time.LoadLocation("America/New_York")
	eastern := time.Date(2024, 6, 15, 8, 30, 45, 0, loc)
	ts = FromTime(eastern)
	want = "2024-06-15T12:30:45Z" // 8:30 EDT = 12:30 UTC
	if ts.String() != want {
		t.Errorf("FromTime(Eastern) = %q, want %q", ts.String(), want)
	}
}

func TestTime(t *testing.T) {
	ts := MustParse("2024-06-15T12:30:45Z")
	got := ts.Time()
	want := time.Date(2024, 6, 15, 12, 30, 45, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("Time() = %v, want %v", got, want)
	}
}

func TestIsZero(t *testing.T) {
	var zero Timestamp
	if !zero.IsZero() {
		t.Error("Zero value should be zero")
	}

	ts := Now()
	if ts.IsZero() {
		t.Error("Now() should not be zero")
	}
}

func TestEqual(t *testing.T) {
	ts1 := MustParse("2024-01-15T10:30:00Z")
	ts2 := MustParse("2024-01-15T10:30:00Z")
	ts3 := MustParse("2024-01-15T10:30:01Z")

	if !ts1.Equal(ts2) {
		t.Error("Equal timestamps should be equal")
	}
	if ts1.Equal(ts3) {
		t.Error("Different timestamps should not be equal")
	}
}

func TestBeforeAfter(t *testing.T) {
	ts1 := MustParse("2024-01-15T10:30:00Z")
	ts2 := MustParse("2024-01-15T10:30:01Z")
	var zero Timestamp

	if !ts1.Before(ts2) {
		t.Error("ts1 should be before ts2")
	}
	if ts2.Before(ts1) {
		t.Error("ts2 should not be before ts1")
	}
	if ts1.Before(ts1) {
		t.Error("ts1 should not be before itself")
	}

	if !ts2.After(ts1) {
		t.Error("ts2 should be after ts1")
	}
	if ts1.After(ts2) {
		t.Error("ts1 should not be after ts2")
	}

	// Zero handling
	if zero.Before(ts1) {
		t.Error("Zero should not be before anything")
	}
	if ts1.Before(zero) {
		t.Error("Nothing should be before zero")
	}
	if zero.After(ts1) {
		t.Error("Zero should not be after anything")
	}
}

func TestSub(t *testing.T) {
	ts1 := MustParse("2024-01-15T10:30:00Z")
	ts2 := MustParse("2024-01-15T10:30:05Z")
	var zero Timestamp

	diff := ts2.Sub(ts1)
	if diff != 5*time.Second {
		t.Errorf("Sub() = %v, want 5s", diff)
	}

	diff = ts1.Sub(ts2)
	if diff != -5*time.Second {
		t.Errorf("Sub() = %v, want -5s", diff)
	}

	if zero.Sub(ts1) != 0 {
		t.Error("Zero.Sub() should return 0")
	}
	if ts1.Sub(zero) != 0 {
		t.Error("Sub(zero) should return 0")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	original := MustParse("2024-01-15T10:30:00Z")

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	// Should be exactly the quoted string
	if string(data) != `"2024-01-15T10:30:00Z"` {
		t.Errorf("Marshal = %s, want quoted timestamp", data)
	}

	var decoded Timestamp
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
		{"fractional seconds", `"2024-01-15T10:30:00.000Z"`},
		{"timezone offset", `"2024-01-15T10:30:00+00:00"`},
		{"missing Z", `"2024-01-15T10:30:00"`},
		{"too short", `"2024-01-15"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ts Timestamp
			if err := json.Unmarshal([]byte(tt.input), &ts); err == nil {
				t.Error("Expected error for invalid timestamp")
			}
		})
	}
}

func TestJSONEmptyString(t *testing.T) {
	var ts Timestamp
	if err := json.Unmarshal([]byte(`""`), &ts); err != nil {
		t.Fatalf("Unmarshal empty string: %v", err)
	}
	if !ts.IsZero() {
		t.Error("Empty string should unmarshal to zero timestamp")
	}

	// Zero timestamp should marshal to empty string
	data, err := json.Marshal(Timestamp{})
	if err != nil {
		t.Fatalf("Marshal zero: %v", err)
	}
	if !bytes.Equal(data, []byte(`""`)) {
		t.Errorf("Zero timestamp should marshal to empty string, got %s", data)
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
	if err := Validate("2024-01-15T10:30:00Z"); err != nil {
		t.Errorf("Validate valid: %v", err)
	}
	if err := Validate("invalid"); err == nil {
		t.Error("Validate invalid should return error")
	}
	if err := Validate("2024-01-15T10:30:00.000Z"); err == nil {
		t.Error("Validate fractional seconds should return error")
	}
}
