package componentsdk

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
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

func TestCollectorArtifactEntry_CarriesDisplayFields(t *testing.T) {
	c := &collectorContext{}

	entry, err := c.collectorArtifactEntry(CollectedArtifact{
		Data:        map[string]any{"k": "v"},
		Path:        "artifacts/doc.json",
		Schema:      "evidencepack/soc2-report@v1",
		DisplayName: "Acme SOC 2 2025",
		Description: "SOC 2 Type II report",
		Controls:    []string{"CC6.1"},
	})
	if err != nil {
		t.Fatalf("collectorArtifactEntry: %v", err)
	}
	if entry["display_name"] != "Acme SOC 2 2025" {
		t.Errorf("display_name = %v, want %q", entry["display_name"], "Acme SOC 2 2025")
	}
	if entry["description"] != "SOC 2 Type II report" {
		t.Errorf("description = %v, want %q", entry["description"], "SOC 2 Type II report")
	}
	controls, ok := entry["controls"].([]string)
	if !ok || len(controls) != 1 || controls[0] != "CC6.1" {
		t.Errorf("controls = %v, want [CC6.1]", entry["controls"])
	}

	bare, err := c.collectorArtifactEntry(CollectedArtifact{
		Data: map[string]any{"k": "v"},
		Path: "artifacts/bare.json",
	})
	if err != nil {
		t.Fatalf("collectorArtifactEntry (bare): %v", err)
	}
	for _, key := range []string{"display_name", "description", "controls"} {
		if _, present := bare[key]; present {
			t.Errorf("bare artifact should omit %q", key)
		}
	}
}

func TestExitCodeFor(t *testing.T) {
	deadline := &url.Error{Op: "Get", URL: "https://graph.example.com/v1.0/users", Err: context.DeadlineExceeded}
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"untyped", errors.New("boom"), 1},
		{"config value", NewConfigError("tenant_id is required"), 2},
		{"auth value", NewAuthError("token rejected"), 3},
		{"network value", NewNetworkError("503 from API"), 4},
		{"wrapped config", fmt.Errorf("loading config: %w", NewConfigError("tenant_id is required")), 2},
		{"wrapped auth", fmt.Errorf("listing users: %w", NewAuthError("token rejected")), 3},
		{"wrapped network", fmt.Errorf("listing users: %w", NewNetworkError("503 from API")), 4},
		{"config pointer", &ConfigError{Err: errors.New("bad level")}, 2},
		{"auth pointer", &AuthError{Err: errors.New("token rejected")}, 3},
		{"wrapped network pointer", fmt.Errorf("listing users: %w", &NetworkError{Err: errors.New("reset")}), 4},
		{"joined", errors.Join(errors.New("cleanup failed"), NewAuthError("token rejected")), 3},
		{"deadline", context.DeadlineExceeded, 4},
		{"wrapped deadline", fmt.Errorf("listing users: %w", deadline), 4},
		{"typed error over a deadline keeps its class", NewAuthError("token exchange: %w", context.DeadlineExceeded), 3},
		{"outermost typed error wins", NetworkError{Err: NewConfigError("bad region")}, 4},
		{"cancellation", fmt.Errorf("listing users: %w", context.Canceled), 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stderr bytes.Buffer
			got := exitCodeFor(&stderr, tc.err)
			if got != tc.want {
				t.Errorf("exitCodeFor() = %d, want %d", got, tc.want)
			}
			if !strings.Contains(stderr.String(), tc.err.Error()) {
				t.Errorf("stderr = %q, want the error message", stderr.String())
			}
		})
	}
}

func TestTypedErrors_Unwrap(t *testing.T) {
	err := NewNetworkError("listing users: %w", io.ErrUnexpectedEOF)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Error("errors.Is should see through NetworkError")
	}
	var urlErr *url.Error
	if !errors.As(AuthError{Err: &url.Error{Op: "Post", URL: "https://login.example.com", Err: io.EOF}}, &urlErr) {
		t.Error("errors.As should see through AuthError")
	}
	if !errors.Is(&ConfigError{Err: io.EOF}, io.EOF) {
		t.Error("errors.Is should see through a ConfigError pointer")
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
