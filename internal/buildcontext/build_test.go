package buildcontext

import "testing"

func TestBuildGitHubActionsContext(t *testing.T) {
	t.Parallel()

	ctx := Build(envGetter(githubActionsEnv()))

	assertBuildContext(t, ctx)
	assertGitHubContext(t, ctx.GitHub)
	assertMappedContext(t, ctx.ToMap())
}

func TestContextReleaseFieldsReturnsPushCompatibleSubset(t *testing.T) {
	t.Parallel()

	ctx := Build(envGetter(map[string]string{
		"GITHUB_ACTIONS":    "true",
		"EPACK_PIPELINE_ID": "01234567-89ab-cdef-0123-456789abcdef",
		"GITHUB_SHA":        "abc123",
		"GITHUB_RUN_URL":    "https://github.com/acme-corp/evidence/actions/runs/12345",
	}))

	fields := ctx.ReleaseFields()
	assertReleaseFields(t, fields)
}

func githubActionsEnv() map[string]string {
	return map[string]string{
		"GITHUB_ACTIONS":      "true",
		"EPACK_PIPELINE_ID":   "01234567-89ab-cdef-0123-456789abcdef",
		"GITHUB_SHA":          "abc123",
		"GITHUB_SERVER_URL":   "https://github.com",
		"GITHUB_REPOSITORY":   "acme-corp/evidence",
		"GITHUB_WORKFLOW_REF": "acme-corp/evidence/.github/workflows/epack.yaml@refs/heads/main",
		"GITHUB_REF":          "refs/heads/main",
		"GITHUB_RUN_ID":       "12345",
		"GITHUB_ACTOR":        "ci-bot",
	}
}

func envGetter(values map[string]string) func(string) string {
	return func(name string) string {
		return values[name]
	}
}

func assertBuildContext(t *testing.T, ctx *Context) {
	t.Helper()
	if ctx == nil {
		t.Fatal("Build() = nil, want context")
	}
	assertEqual(t, "RunnerType", ctx.RunnerType, "github_actions")
	assertEqual(t, "PipelineID", ctx.PipelineID, "01234567-89ab-cdef-0123-456789abcdef")
	assertEqual(t, "GitSHA", ctx.GitSHA, "abc123")
	assertEqual(t, "CIRunURL", ctx.CIRunURL, "https://github.com/acme-corp/evidence/actions/runs/12345")
}

func assertGitHubContext(t *testing.T, ctx *GitHubContext) {
	t.Helper()
	if ctx == nil {
		t.Fatal("GitHub = nil, want context")
	}
	assertEqual(t, "GitHub.Repository", ctx.Repository, "acme-corp/evidence")
	assertEqual(t, "GitHub.Workflow", ctx.Workflow, "acme-corp/evidence/.github/workflows/epack.yaml@refs/heads/main")
	assertEqual(t, "GitHub.Ref", ctx.Ref, "refs/heads/main")
	assertEqual(t, "GitHub.RunID", ctx.RunID, "12345")
	assertEqual(t, "GitHub.Actor", ctx.Actor, "ci-bot")
}

func assertMappedContext(t *testing.T, mapped map[string]any) {
	t.Helper()
	if mapped["runner_type"] != "github_actions" {
		t.Fatalf("ToMap runner_type = %#v", mapped["runner_type"])
	}
	github, ok := mapped["github"].(map[string]string)
	if !ok {
		t.Fatalf("ToMap github = %#v, want map[string]string", mapped["github"])
	}
	assertEqual(t, "ToMap github.repository", github["repository"], "acme-corp/evidence")
}

func assertReleaseFields(t *testing.T, fields map[string]string) {
	t.Helper()
	if len(fields) != 4 {
		t.Fatalf("len(fields) = %d, want 4", len(fields))
	}
	assertEqual(t, "runner_type", fields["runner_type"], "github_actions")
	assertEqual(t, "pipeline_id", fields["pipeline_id"], "01234567-89ab-cdef-0123-456789abcdef")
	assertEqual(t, "git_sha", fields["git_sha"], "abc123")
	assertEqual(t, "ci_run_url", fields["ci_run_url"], "https://github.com/acme-corp/evidence/actions/runs/12345")
}

func assertEqual(t *testing.T, field, got, want string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s = %q, want %q", field, got, want)
	}
}
