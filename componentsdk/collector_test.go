package componentsdk

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLevel_DefaultsToTrust(t *testing.T) {
	cases := []struct {
		name string
		ctx  *collectorContext
	}{
		{"nil config", &collectorContext{}},
		{"empty config", &collectorContext{config: map[string]any{}}},
		{"missing key", &collectorContext{config: map[string]any{"other": "value"}}},
		{"empty string", &collectorContext{config: map[string]any{"level": ""}}},
		{"non-string", &collectorContext{config: map[string]any{"level": 42}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.ctx.Level(); got != LevelTrust {
				t.Errorf("Level() = %q, want %q", got, LevelTrust)
			}
		})
	}
}

func TestLevel_ReadsKnownValues(t *testing.T) {
	cases := []struct {
		val  string
		want Level
	}{
		{"trust", LevelTrust},
		{"audit", LevelAudit},
		{"internal", LevelInternal},
	}
	for _, tc := range cases {
		t.Run(tc.val, func(t *testing.T) {
			ctx := &collectorContext{config: map[string]any{"level": tc.val}}
			if got := ctx.Level(); got != tc.want {
				t.Errorf("Level() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLevel_UnknownValueDowngrades(t *testing.T) {
	stderr := captureStderr(t, func() {
		ctx := &collectorContext{config: map[string]any{"level": "audit2"}}
		if got := ctx.Level(); got != LevelTrust {
			t.Errorf("Level() = %q, want %q (must never fail open)", got, LevelTrust)
		}
	})

	if !strings.Contains(stderr, "audit2") {
		t.Errorf("stderr did not echo the bad value, got: %q", stderr)
	}
	if !strings.Contains(stderr, "warning") {
		t.Errorf("stderr did not label the output as a warning, got: %q", stderr)
	}
}

func TestLevel_AtLeast(t *testing.T) {
	cases := []struct {
		a, b Level
		want bool
	}{
		{LevelTrust, LevelTrust, true},
		{LevelTrust, LevelAudit, false},
		{LevelTrust, LevelInternal, false},
		{LevelAudit, LevelTrust, true},
		{LevelAudit, LevelAudit, true},
		{LevelAudit, LevelInternal, false},
		{LevelInternal, LevelTrust, true},
		{LevelInternal, LevelAudit, true},
		{LevelInternal, LevelInternal, true},
	}
	for _, tc := range cases {
		t.Run(string(tc.a)+"_atleast_"+string(tc.b), func(t *testing.T) {
			if got := tc.a.AtLeast(tc.b); got != tc.want {
				t.Errorf("%q.AtLeast(%q) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestLevel_IntegratesWithLoadedJSONConfig(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"level":"audit2","other":"value"}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("EPACK_COLLECTOR_CONFIG", cfgPath)

	ctx := &collectorContext{}
	if err := loadCollectorConfig(ctx); err != nil {
		t.Fatalf("load config: %v", err)
	}

	stderr := captureStderr(t, func() {
		if got := ctx.Level(); got != LevelTrust {
			t.Errorf("Level() = %q, want %q", got, LevelTrust)
		}
	})

	if !strings.Contains(stderr, "audit2") {
		t.Errorf("stderr missing bad value, got: %q", stderr)
	}
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = orig })

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("close pipe: %v", err)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	return buf.String()
}
