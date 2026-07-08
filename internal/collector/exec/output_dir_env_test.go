package exec

import (
	"slices"
	"testing"
)

func TestBuildEnvOutputDir(t *testing.T) {
	base := EnvInput{Name: "documents", Getenv: func(string) string { return "" }}

	withDir := base
	withDir.OutputDir = "/tmp/staging"
	env := BuildEnv(withDir)
	if !slices.Contains(env, "EPACK_COLLECTOR_OUTPUT_DIR=/tmp/staging") {
		t.Errorf("expected EPACK_COLLECTOR_OUTPUT_DIR in env, got %v", env)
	}

	env = BuildEnv(base)
	for _, entry := range env {
		if len(entry) >= 26 && entry[:26] == "EPACK_COLLECTOR_OUTPUT_DIR" {
			t.Errorf("did not expect EPACK_COLLECTOR_OUTPUT_DIR, got %s", entry)
		}
	}
}
