package exec

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestBuildEnvRunIDAndDeadline(t *testing.T) {
	deadline := time.Date(2026, 10, 17, 12, 30, 0, 0, time.FixedZone("EDT", -4*3600))
	env := BuildEnv(EnvInput{Name: "okta", Getenv: func(string) string { return "" }, RunID: "run-7", Deadline: deadline})
	if !slices.Contains(env, "EPACK_RUN_ID=run-7") {
		t.Errorf("env lacks EPACK_RUN_ID: %v", env)
	}
	if !slices.Contains(env, "EPACK_DEADLINE=2026-10-17T16:30:00Z") {
		t.Errorf("env lacks EPACK_DEADLINE in UTC: %v", env)
	}

	env = BuildEnv(EnvInput{Name: "okta", Getenv: func(string) string { return "" }})
	for _, entry := range env {
		if strings.HasPrefix(entry, "EPACK_RUN_ID=") || strings.HasPrefix(entry, "EPACK_DEADLINE=") {
			t.Errorf("unexpected %s without a run ID or deadline", entry)
		}
	}
}
