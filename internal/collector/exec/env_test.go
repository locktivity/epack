package exec

import (
	"sort"
	"strings"
	"testing"
)

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

func TestSanitizeStderrRedactsPassedValues(t *testing.T) {
	token := "short-container-tok"
	pem := "-----BEGIN KEY-----\nabc\n-----END KEY-----"
	stderr := "auth failed for " + token + " with key " + pem + " and x=1"

	got := SanitizeStderr(stderr, token, pem, "1")
	if strings.Contains(got, token) || strings.Contains(got, "abc") {
		t.Fatalf("SanitizeStderr() leaked a passed value: %s", got)
	}
	if strings.Count(got, "[REDACTED]") != 2 || !strings.Contains(got, "x=1") {
		t.Fatalf("SanitizeStderr() = %s, want both values replaced and the trivial one left", got)
	}

	long := strings.Repeat("k", 600)
	if got := SanitizeStderr(strings.Repeat("x", 400)+long, long); strings.Contains(got, "kkkkkk") {
		t.Fatalf("a value across the truncation boundary leaked: %s", got)
	}
	if got := SanitizeStderr("key=abcdefghijklmnop", "abcdefghij", "abcdefghijklmnop"); strings.Contains(got, "klmnop") {
		t.Fatalf("the longer of two overlapping values leaked its tail: %s", got)
	}
	if got := SanitizeStderr("token file holds secret-value-here", "secret-value-here\n"); strings.Contains(got, "secret-value") {
		t.Fatalf("a value with a trailing newline leaked: %s", got)
	}
}

func TestSecretValuesCollectsListedAndManagedValues(t *testing.T) {
	values := secretValues(EnvInput{
		Secrets:    []string{"A_TOKEN", "UNSET"},
		ManagedEnv: map[string]string{"GITHUB_TOKEN": "ghs_managed", "EMPTY": ""},
		Getenv: func(name string) string {
			switch name {
			case "A_TOKEN":
				return "from-env"
			case "EPACK_IDENTITY":
				return "identity-token"
			}
			return ""
		},
	})
	sort.Strings(values)
	if strings.Join(values, ",") != "from-env,ghs_managed,identity-token" {
		t.Fatalf("secretValues() = %v", values)
	}
}
