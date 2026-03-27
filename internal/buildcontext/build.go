package buildcontext

import (
	"os"
	"strings"
)

// Context is the structured build metadata derived from the ambient runtime.
type Context struct {
	RunnerType string
	PipelineID string
	GitSHA     string
	CIRunURL   string
	GitHub     *GitHubContext
}

// GitHubContext contains GitHub Actions-specific build metadata.
type GitHubContext struct {
	Repository string
	Workflow   string
	Ref        string
	RunID      string
	Actor      string
}

// Build returns structured build metadata derived from the ambient runtime.
// The result is suitable for JSON emission and future transport layers.
func Build(getenv func(string) string) *Context {
	if getenv == nil {
		getenv = os.Getenv
	}

	ctx := &Context{}

	if strings.EqualFold(strings.TrimSpace(getenv("GITHUB_ACTIONS")), "true") {
		ctx.RunnerType = "github_actions"
	}
	ctx.PipelineID = trimmed(getenv("EPACK_PIPELINE_ID"))
	ctx.GitSHA = trimmed(getenv("GITHUB_SHA"))
	ctx.CIRunURL = detectGitHubRunURL(getenv)

	github := &GitHubContext{
		Repository: trimmed(getenv("GITHUB_REPOSITORY")),
		Ref:        trimmed(getenv("GITHUB_REF")),
		RunID:      trimmed(getenv("GITHUB_RUN_ID")),
		Actor:      trimmed(getenv("GITHUB_ACTOR")),
	}
	if workflow := trimmed(getenv("GITHUB_WORKFLOW_REF")); workflow != "" {
		github.Workflow = workflow
	} else {
		github.Workflow = trimmed(getenv("GITHUB_WORKFLOW"))
	}
	if !github.isZero() {
		ctx.GitHub = github
	}
	if ctx.isZero() {
		return nil
	}
	return ctx
}

// ToMap converts the structured context to the transport-friendly map shape.
func (c *Context) ToMap() map[string]any {
	if c == nil || c.isZero() {
		return nil
	}
	ctx := make(map[string]any)
	addAnyString(ctx, "runner_type", c.RunnerType)
	addAnyString(ctx, "pipeline_id", c.PipelineID)
	addAnyString(ctx, "git_sha", c.GitSHA)
	addAnyString(ctx, "ci_run_url", c.CIRunURL)
	if github := c.GitHub.ToMap(); len(github) > 0 {
		ctx["github"] = github
	}
	if len(ctx) == 0 {
		return nil
	}
	return ctx
}

// ReleaseFields returns the build-context subset that current remote transport can carry.
func (c *Context) ReleaseFields() map[string]string {
	if c == nil || c.isZero() {
		return nil
	}
	release := make(map[string]string)
	if c.GitSHA != "" {
		release["git_sha"] = c.GitSHA
	}
	if c.CIRunURL != "" {
		release["ci_run_url"] = c.CIRunURL
	}
	if c.RunnerType != "" {
		release["runner_type"] = c.RunnerType
	}
	if c.PipelineID != "" {
		release["pipeline_id"] = c.PipelineID
	}
	if len(release) == 0 {
		return nil
	}
	return release
}

func (c *Context) isZero() bool {
	return c.RunnerType == "" && c.PipelineID == "" && c.GitSHA == "" && c.CIRunURL == "" && (c.GitHub == nil || c.GitHub.isZero())
}

// ToMap converts the GitHub-specific context to the transport-friendly map shape.
func (g *GitHubContext) ToMap() map[string]string {
	if g == nil || g.isZero() {
		return nil
	}
	ctx := make(map[string]string)
	addString(ctx, "repository", g.Repository)
	addString(ctx, "workflow", g.Workflow)
	addString(ctx, "ref", g.Ref)
	addString(ctx, "run_id", g.RunID)
	addString(ctx, "actor", g.Actor)
	if len(ctx) == 0 {
		return nil
	}
	return ctx
}

func (g *GitHubContext) isZero() bool {
	return g == nil || (g.Repository == "" && g.Workflow == "" && g.Ref == "" && g.RunID == "" && g.Actor == "")
}

func addAnyString(dst map[string]any, key, value string) {
	if value != "" {
		dst[key] = value
	}
}

func addString(dst map[string]string, key, value string) {
	if value != "" {
		dst[key] = value
	}
}

func detectGitHubRunURL(getenv func(string) string) string {
	if explicit := trimmed(getenv("GITHUB_RUN_URL")); explicit != "" {
		return explicit
	}

	serverURL := strings.TrimRight(trimmed(getenv("GITHUB_SERVER_URL")), "/")
	repository := trimmed(getenv("GITHUB_REPOSITORY"))
	runID := trimmed(getenv("GITHUB_RUN_ID"))
	if serverURL == "" || repository == "" || runID == "" {
		return ""
	}
	return serverURL + "/" + repository + "/actions/runs/" + runID
}

func trimmed(value string) string {
	return strings.TrimSpace(value)
}
