package jsonpointer

import (
	"reflect"
	"testing"
)

func TestTokensAndFormatRoundTrip(t *testing.T) {
	for pointer, want := range map[string][]string{
		"":          nil,
		"/a/b":      {"a", "b"},
		"/a~1b/c~0": {"a/b", "c~"},
		"/":         {""},
		"/x/~01":    {"x", "~1"},
	} {
		got := Tokens(pointer)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Tokens(%q) = %q, want %q", pointer, got, want)
		}
		if back := Format(got); back != pointer {
			t.Errorf("Format(%q) = %q, want %q", got, back, pointer)
		}
	}
}

func TestIndex(t *testing.T) {
	for token, want := range map[string]int{"0": 0, "7": 7, "12": 12} {
		if got, ok := Index(token); !ok || got != want {
			t.Errorf("Index(%q) = %d, %v, want %d", token, got, ok, want)
		}
	}
	for _, token := range []string{"", "-1", "01", "a", "1a"} {
		if _, ok := Index(token); ok {
			t.Errorf("Index(%q) is ok, want not an index", token)
		}
	}
}
