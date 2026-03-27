package exec

import "testing"

func TestBuildEnvIncludesManagedEnv(t *testing.T) {
	env := BuildEnv(EnvInput{
		Name:       "github",
		ConfigPath: "/tmp/config.json",
		ManagedEnv: map[string]string{
			"GITHUB_TOKEN": "ghs_test",
		},
		Getenv: func(string) string { return "" },
	})

	if !containsEnv(env, "GITHUB_TOKEN=ghs_test") {
		t.Fatalf("BuildEnv() missing managed env: %v", env)
	}
}

func containsEnv(env []string, want string) bool {
	for _, entry := range env {
		if entry == want {
			return true
		}
	}
	return false
}
