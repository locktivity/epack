package tracemap

import (
	"encoding/json"
	"testing"
)

func TestPatternWritesArrayIndicesAsStars(t *testing.T) {
	var doc any
	if err := json.Unmarshal([]byte(`{"users": [{"factors": [{"id": 1}]}], "by_status": {"403": 2}, "a/b": [1]}`), &doc); err != nil {
		t.Fatal(err)
	}
	for pointer, want := range map[string]string{
		"":                       "",
		"/users/0/factors/0/id":  "/users/*/factors/*/id",
		"/users/7/factors/0/id":  "/users/*/factors/*/id",
		"/by_status/403":         "/by_status/403",
		"/a~1b/0":                "/a~1b/*",
		"/missing/3/x":           "/missing/*/x",
		"/users/0/factors/0/new": "/users/*/factors/*/new",
	} {
		if got := Pattern(pointer, doc); got != want {
			t.Errorf("Pattern(%q) = %q, want %q", pointer, got, want)
		}
	}
	if got := Pattern("/by_status/403", nil, doc); got != "/by_status/403" {
		t.Errorf("a pointer one document cannot place is placed by the next, got %q", got)
	}
}

func TestLinesEncodeInFileAndLineOrder(t *testing.T) {
	raw, err := json.Marshal(Lines{"b.go:2": "y", "a.go:10": "x", "a.go:9": "w"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"a.go:9":"w","a.go:10":"x","b.go:2":"y"}`; string(raw) != want {
		t.Errorf("lines = %s, want %s", raw, want)
	}
	if file, n, ok := SplitLine("internal/x.go:155"); !ok || file != "internal/x.go" || n != 155 || LineRef(file, n) != "internal/x.go:155" {
		t.Errorf("SplitLine = %q %d %v", file, n, ok)
	}
	for _, bad := range []string{"x.go", ":3", "x.go:0", "x.go:a"} {
		if _, _, ok := SplitLine(bad); ok {
			t.Errorf("SplitLine(%q) accepted it", bad)
		}
	}
}
