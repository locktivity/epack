package toolprotocol

import (
	"os"
	"runtime"
	"testing"
)

func TestEnrichIdentity_JSONFormat(t *testing.T) {
	t.Setenv("EPACK_IDENTITY", `{"workspace":"acme","actor":"ci-bot","actor_type":"service","auth_mode":"api_key"}`)

	r := &Result{}
	EnrichResultFromEnv(r)

	if r.Identity == nil {
		t.Fatal("expected Identity to be set")
	}
	if r.Identity.Workspace != "acme" {
		t.Errorf("expected workspace=acme, got %s", r.Identity.Workspace)
	}
	if r.Identity.Actor != "ci-bot" {
		t.Errorf("expected actor=ci-bot, got %s", r.Identity.Actor)
	}
	if r.Identity.ActorType != "service" {
		t.Errorf("expected actor_type=service, got %s", r.Identity.ActorType)
	}
	if r.Identity.AuthMode != "api_key" {
		t.Errorf("expected auth_mode=api_key, got %s", r.Identity.AuthMode)
	}
}

func TestEnrichIdentity_PlainString(t *testing.T) {
	t.Setenv("EPACK_IDENTITY", "alice@example.com")

	r := &Result{}
	EnrichResultFromEnv(r)

	if r.Identity == nil {
		t.Fatal("expected Identity to be set")
	}
	if r.Identity.Actor != "alice@example.com" {
		t.Errorf("expected actor=alice@example.com, got %s", r.Identity.Actor)
	}
	if r.Identity.ActorType != "unknown" {
		t.Errorf("expected actor_type=unknown, got %s", r.Identity.ActorType)
	}
}

func TestEnrichIdentity_NonDestructive(t *testing.T) {
	t.Setenv("EPACK_IDENTITY", `{"workspace":"env-workspace","actor":"env-actor"}`)

	r := &Result{
		Identity: &IdentityInfo{
			Workspace: "tool-workspace",
			Actor:     "tool-actor",
		},
	}
	EnrichResultFromEnv(r)

	// Tool values should be preserved
	if r.Identity.Workspace != "tool-workspace" {
		t.Errorf("expected workspace=tool-workspace (preserved), got %s", r.Identity.Workspace)
	}
	if r.Identity.Actor != "tool-actor" {
		t.Errorf("expected actor=tool-actor (preserved), got %s", r.Identity.Actor)
	}
}

func TestEnrichIdentity_Empty(t *testing.T) {
	old := os.Getenv("EPACK_IDENTITY")
	defer func() { _ = os.Setenv("EPACK_IDENTITY", old) }()

	_ = os.Unsetenv("EPACK_IDENTITY")

	r := &Result{}
	EnrichResultFromEnv(r)

	// Identity will be set via RunContext, but the EPACK_IDENTITY env var should not contribute
	// The enrichIdentity function is tested separately in TestEnrichIdentity_EmptyEnvNoChange
	_ = r.Identity // Acknowledge field is populated by RunContext
}

func TestEnrichIdentity_EmptyEnvNoChange(t *testing.T) {
	old := os.Getenv("EPACK_IDENTITY")
	defer func() { _ = os.Setenv("EPACK_IDENTITY", old) }()

	_ = os.Unsetenv("EPACK_IDENTITY")

	r := &Result{}
	enrichIdentity(r)

	if r.Identity != nil {
		t.Error("expected Identity to remain nil when EPACK_IDENTITY is not set")
	}
}

func TestEnrichRunContext_AlwaysPopulatesOSArch(t *testing.T) {
	// Clear CI env vars
	ciVars := []string{"GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "BUILDKITE", "JENKINS_URL", "CI"}
	oldVals := make(map[string]string)
	for _, v := range ciVars {
		oldVals[v] = os.Getenv(v)
		_ = os.Unsetenv(v)
	}
	defer func() {
		for _, v := range ciVars {
			_ = os.Setenv(v, oldVals[v])
		}
	}()

	r := &Result{}
	EnrichResultFromEnv(r)

	if r.RunContext == nil {
		t.Fatal("expected RunContext to be set")
	}
	if r.RunContext.RunnerOS != runtime.GOOS {
		t.Errorf("expected runner_os=%s, got %s", runtime.GOOS, r.RunContext.RunnerOS)
	}
	if r.RunContext.RunnerArch != runtime.GOARCH {
		t.Errorf("expected runner_arch=%s, got %s", runtime.GOARCH, r.RunContext.RunnerArch)
	}
	if r.RunContext.CI {
		t.Error("expected CI=false when not in CI environment")
	}
}

func TestDetectCI_GitHubActions(t *testing.T) {
	// Save and restore env
	envVars := []string{"GITHUB_ACTIONS", "GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_REF"}
	oldVals := make(map[string]string)
	for _, v := range envVars {
		oldVals[v] = os.Getenv(v)
	}
	defer func() {
		for _, v := range envVars {
			if oldVals[v] == "" {
				_ = os.Unsetenv(v)
			} else {
				_ = os.Setenv(v, oldVals[v])
			}
		}
	}()

	_ = os.Setenv("GITHUB_ACTIONS", "true")
	_ = os.Setenv("GITHUB_REPOSITORY", "owner/repo")
	_ = os.Setenv("GITHUB_SHA", "abc123def456")
	_ = os.Setenv("GITHUB_REF", "refs/heads/main")

	ci := detectCI()

	if ci == nil {
		t.Fatal("expected CI to be detected")
	}
	if !ci.CI {
		t.Error("expected CI=true")
	}
	if ci.CIProvider != "github_actions" {
		t.Errorf("expected ci_provider=github_actions, got %s", ci.CIProvider)
	}
	if ci.Repo != "owner/repo" {
		t.Errorf("expected repo=owner/repo, got %s", ci.Repo)
	}
	if ci.Commit != "abc123def456" {
		t.Errorf("expected commit=abc123def456, got %s", ci.Commit)
	}
	if ci.Branch != "main" {
		t.Errorf("expected branch=main, got %s", ci.Branch)
	}
}

func TestDetectCI_GitLabCI(t *testing.T) {
	envVars := []string{"GITLAB_CI", "CI_PROJECT_URL", "CI_COMMIT_SHA", "CI_COMMIT_REF_NAME", "GITHUB_ACTIONS"}
	oldVals := make(map[string]string)
	for _, v := range envVars {
		oldVals[v] = os.Getenv(v)
	}
	defer func() {
		for _, v := range envVars {
			if oldVals[v] == "" {
				_ = os.Unsetenv(v)
			} else {
				_ = os.Setenv(v, oldVals[v])
			}
		}
	}()

	_ = os.Unsetenv("GITHUB_ACTIONS") // Ensure GH Actions doesn't take precedence
	_ = os.Setenv("GITLAB_CI", "true")
	_ = os.Setenv("CI_PROJECT_URL", "https://gitlab.com/org/project")
	_ = os.Setenv("CI_COMMIT_SHA", "def789")
	_ = os.Setenv("CI_COMMIT_REF_NAME", "feature-branch")

	ci := detectCI()

	if ci == nil {
		t.Fatal("expected CI to be detected")
	}
	if ci.CIProvider != "gitlab_ci" {
		t.Errorf("expected ci_provider=gitlab_ci, got %s", ci.CIProvider)
	}
	if ci.Repo != "https://gitlab.com/org/project" {
		t.Errorf("expected repo=https://gitlab.com/org/project, got %s", ci.Repo)
	}
}

func TestDetectCI_CircleCI(t *testing.T) {
	envVars := []string{"CIRCLECI", "CIRCLE_REPOSITORY_URL", "CIRCLE_SHA1", "CIRCLE_BRANCH", "GITHUB_ACTIONS", "GITLAB_CI"}
	oldVals := make(map[string]string)
	for _, v := range envVars {
		oldVals[v] = os.Getenv(v)
	}
	defer func() {
		for _, v := range envVars {
			if oldVals[v] == "" {
				_ = os.Unsetenv(v)
			} else {
				_ = os.Setenv(v, oldVals[v])
			}
		}
	}()

	_ = os.Unsetenv("GITHUB_ACTIONS")
	_ = os.Unsetenv("GITLAB_CI")
	_ = os.Setenv("CIRCLECI", "true")
	_ = os.Setenv("CIRCLE_REPOSITORY_URL", "git@github.com:org/repo.git")
	_ = os.Setenv("CIRCLE_SHA1", "circle123")
	_ = os.Setenv("CIRCLE_BRANCH", "develop")

	ci := detectCI()

	if ci == nil {
		t.Fatal("expected CI to be detected")
	}
	if ci.CIProvider != "circleci" {
		t.Errorf("expected ci_provider=circleci, got %s", ci.CIProvider)
	}
}

func TestDetectCI_CircleCI_FallbackRepo(t *testing.T) {
	envVars := []string{"CIRCLECI", "CIRCLE_REPOSITORY_URL", "CIRCLE_PROJECT_USERNAME", "CIRCLE_PROJECT_REPONAME", "GITHUB_ACTIONS", "GITLAB_CI"}
	oldVals := make(map[string]string)
	for _, v := range envVars {
		oldVals[v] = os.Getenv(v)
	}
	defer func() {
		for _, v := range envVars {
			if oldVals[v] == "" {
				_ = os.Unsetenv(v)
			} else {
				_ = os.Setenv(v, oldVals[v])
			}
		}
	}()

	_ = os.Unsetenv("GITHUB_ACTIONS")
	_ = os.Unsetenv("GITLAB_CI")
	_ = os.Setenv("CIRCLECI", "true")
	_ = os.Unsetenv("CIRCLE_REPOSITORY_URL")
	_ = os.Setenv("CIRCLE_PROJECT_USERNAME", "myorg")
	_ = os.Setenv("CIRCLE_PROJECT_REPONAME", "myrepo")

	ci := detectCI()

	if ci == nil {
		t.Fatal("expected CI to be detected")
	}
	if ci.Repo != "myorg/myrepo" {
		t.Errorf("expected repo=myorg/myrepo, got %s", ci.Repo)
	}
}

func TestDetectCI_Buildkite(t *testing.T) {
	envVars := []string{"BUILDKITE", "BUILDKITE_REPO", "BUILDKITE_COMMIT", "BUILDKITE_BRANCH", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI"}
	oldVals := make(map[string]string)
	for _, v := range envVars {
		oldVals[v] = os.Getenv(v)
	}
	defer func() {
		for _, v := range envVars {
			if oldVals[v] == "" {
				_ = os.Unsetenv(v)
			} else {
				_ = os.Setenv(v, oldVals[v])
			}
		}
	}()

	_ = os.Unsetenv("GITHUB_ACTIONS")
	_ = os.Unsetenv("GITLAB_CI")
	_ = os.Unsetenv("CIRCLECI")
	_ = os.Setenv("BUILDKITE", "true")
	_ = os.Setenv("BUILDKITE_REPO", "git@github.com:org/repo.git")
	_ = os.Setenv("BUILDKITE_COMMIT", "bk123")
	_ = os.Setenv("BUILDKITE_BRANCH", "main")

	ci := detectCI()

	if ci == nil {
		t.Fatal("expected CI to be detected")
	}
	if ci.CIProvider != "buildkite" {
		t.Errorf("expected ci_provider=buildkite, got %s", ci.CIProvider)
	}
}

func TestDetectCI_Jenkins(t *testing.T) {
	envVars := []string{"JENKINS_URL", "GIT_URL", "GIT_COMMIT", "GIT_BRANCH", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "BUILDKITE"}
	oldVals := make(map[string]string)
	for _, v := range envVars {
		oldVals[v] = os.Getenv(v)
	}
	defer func() {
		for _, v := range envVars {
			if oldVals[v] == "" {
				_ = os.Unsetenv(v)
			} else {
				_ = os.Setenv(v, oldVals[v])
			}
		}
	}()

	_ = os.Unsetenv("GITHUB_ACTIONS")
	_ = os.Unsetenv("GITLAB_CI")
	_ = os.Unsetenv("CIRCLECI")
	_ = os.Unsetenv("BUILDKITE")
	_ = os.Setenv("JENKINS_URL", "http://jenkins.example.com/")
	_ = os.Setenv("GIT_URL", "https://github.com/org/repo")
	_ = os.Setenv("GIT_COMMIT", "jenkins123")
	_ = os.Setenv("GIT_BRANCH", "origin/main")

	ci := detectCI()

	if ci == nil {
		t.Fatal("expected CI to be detected")
	}
	if ci.CIProvider != "jenkins" {
		t.Errorf("expected ci_provider=jenkins, got %s", ci.CIProvider)
	}
}

func TestDetectCI_Generic(t *testing.T) {
	envVars := []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "BUILDKITE", "JENKINS_URL"}
	oldVals := make(map[string]string)
	for _, v := range envVars {
		oldVals[v] = os.Getenv(v)
	}
	defer func() {
		for _, v := range envVars {
			if oldVals[v] == "" {
				_ = os.Unsetenv(v)
			} else {
				_ = os.Setenv(v, oldVals[v])
			}
		}
	}()

	_ = os.Unsetenv("GITHUB_ACTIONS")
	_ = os.Unsetenv("GITLAB_CI")
	_ = os.Unsetenv("CIRCLECI")
	_ = os.Unsetenv("BUILDKITE")
	_ = os.Unsetenv("JENKINS_URL")
	_ = os.Setenv("CI", "true")

	ci := detectCI()

	if ci == nil {
		t.Fatal("expected CI to be detected")
	}
	if ci.CIProvider != "generic" {
		t.Errorf("expected ci_provider=generic, got %s", ci.CIProvider)
	}
}

func TestDetectCI_NotInCI(t *testing.T) {
	envVars := []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "BUILDKITE", "JENKINS_URL"}
	oldVals := make(map[string]string)
	for _, v := range envVars {
		oldVals[v] = os.Getenv(v)
	}
	defer func() {
		for _, v := range envVars {
			if oldVals[v] == "" {
				_ = os.Unsetenv(v)
			} else {
				_ = os.Setenv(v, oldVals[v])
			}
		}
	}()

	for _, v := range envVars {
		_ = os.Unsetenv(v)
	}

	ci := detectCI()

	if ci != nil {
		t.Errorf("expected nil when not in CI, got %+v", ci)
	}
}

func TestNormalizeGitRef(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"refs/heads/main", "main"},
		{"refs/tags/v1.0.0", "v1.0.0"},
		{"main", "main"},
		{"feature/branch", "feature/branch"},
		{"refs/heads/feature/branch", "feature/branch"},
	}

	for _, tc := range tests {
		got := normalizeGitRef(tc.input)
		if got != tc.expected {
			t.Errorf("normalizeGitRef(%q) = %q, expected %q", tc.input, got, tc.expected)
		}
	}
}

func TestEnrichRunContext_NonDestructive(t *testing.T) {
	envVars := []string{"GITHUB_ACTIONS", "GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_REF"}
	oldVals := make(map[string]string)
	for _, v := range envVars {
		oldVals[v] = os.Getenv(v)
	}
	defer func() {
		for _, v := range envVars {
			if oldVals[v] == "" {
				_ = os.Unsetenv(v)
			} else {
				_ = os.Setenv(v, oldVals[v])
			}
		}
	}()

	_ = os.Setenv("GITHUB_ACTIONS", "true")
	_ = os.Setenv("GITHUB_REPOSITORY", "env-owner/env-repo")
	_ = os.Setenv("GITHUB_SHA", "env-sha")
	_ = os.Setenv("GITHUB_REF", "refs/heads/env-branch")

	r := &Result{
		RunContext: &RunContextInfo{
			CIProvider: "tool-provider",
			Repo:       "tool-repo",
			Commit:     "tool-sha",
			Branch:     "tool-branch",
			RunnerOS:   "tool-os",
			RunnerArch: "tool-arch",
		},
	}
	EnrichResultFromEnv(r)

	// Tool values should be preserved
	if r.RunContext.CIProvider != "tool-provider" {
		t.Errorf("expected ci_provider=tool-provider (preserved), got %s", r.RunContext.CIProvider)
	}
	if r.RunContext.Repo != "tool-repo" {
		t.Errorf("expected repo=tool-repo (preserved), got %s", r.RunContext.Repo)
	}
	if r.RunContext.Commit != "tool-sha" {
		t.Errorf("expected commit=tool-sha (preserved), got %s", r.RunContext.Commit)
	}
	if r.RunContext.Branch != "tool-branch" {
		t.Errorf("expected branch=tool-branch (preserved), got %s", r.RunContext.Branch)
	}
	if r.RunContext.RunnerOS != "tool-os" {
		t.Errorf("expected runner_os=tool-os (preserved), got %s", r.RunContext.RunnerOS)
	}
	if r.RunContext.RunnerArch != "tool-arch" {
		t.Errorf("expected runner_arch=tool-arch (preserved), got %s", r.RunContext.RunnerArch)
	}
}
