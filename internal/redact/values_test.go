package redact

import "testing"

func TestValuesReplacesLongestFirstAndSkipsShortOnes(t *testing.T) {
	got := Values("a=abcdefghijklmnop b=abcdefghij c=12345 d=secret7", "abcdefghij", "abcdefghijklmnop", "12345", "  secret7\n")
	want := "a=[REDACTED] b=[REDACTED] c=12345 d=[REDACTED]"
	if got != want {
		t.Fatalf("Values() = %q, want %q", got, want)
	}
}
