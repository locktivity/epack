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
	// HeadSHA is the branch head commit. On pull_request events GITHUB_SHA is
	// the ephemeral merge commit, so the workflow passes the real head
	// explicitly via EPACK_HEAD_SHA.
	HeadSHA  string
	CIRunURL string
	GitHub   *GitHubContext
	GitLab   *GitLabContext
}

// GitHubContext contains GitHub Actions-specific build metadata.
type GitHubContext struct {
	Repository string
	Workflow   string
	Ref        string
	RunID      string
	Actor      string
}

// GitLabContext contains GitLab CI-specific build metadata.
type GitLabContext struct {
	ProjectPath string
	Ref         string
	JobID       string
	PipelineID  string
	Source      string
	Actor       string
}

// Build returns structured build metadata derived from the ambient runtime.
// The result is suitable for JSON emission and future transport layers.
func Build(getenv func(string) string) *Context {
	if getenv == nil {
		getenv = os.Getenv
	}

	ctx := &Context{}

	switch {
	case strings.EqualFold(strings.TrimSpace(getenv("GITHUB_ACTIONS")), "true"):
		ctx.RunnerType = "github_actions"
	case strings.EqualFold(strings.TrimSpace(getenv("GITLAB_CI")), "true"):
		ctx.RunnerType = "gitlab_ci"
	}
	ctx.PipelineID = trimmed(getenv("EPACK_PIPELINE_ID"))
	ctx.GitSHA = firstNonEmpty(trimmed(getenv("GITHUB_SHA")), trimmed(getenv("CI_COMMIT_SHA")))
	ctx.HeadSHA = trimmed(getenv("EPACK_HEAD_SHA"))
	ctx.CIRunURL = firstNonEmpty(detectGitHubRunURL(getenv), trimmed(getenv("CI_JOB_URL")))

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
	gitlab := &GitLabContext{
		ProjectPath: trimmed(getenv("CI_PROJECT_PATH")),
		Ref:         trimmed(getenv("CI_COMMIT_REF_NAME")),
		JobID:       trimmed(getenv("CI_JOB_ID")),
		PipelineID:  trimmed(getenv("CI_PIPELINE_ID")),
		Source:      trimmed(getenv("CI_PIPELINE_SOURCE")),
		Actor:       trimmed(getenv("GITLAB_USER_LOGIN")),
	}
	if !gitlab.isZero() {
		ctx.GitLab = gitlab
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
	addAnyString(ctx, "head_sha", c.HeadSHA)
	addAnyString(ctx, "ci_run_url", c.CIRunURL)
	if github := c.GitHub.ToMap(); len(github) > 0 {
		ctx["github"] = github
	}
	if gitlab := c.GitLab.ToMap(); len(gitlab) > 0 {
		ctx["gitlab"] = gitlab
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
	if c.HeadSHA != "" {
		release["head_sha"] = c.HeadSHA
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
	return c.RunnerType == "" && c.PipelineID == "" && c.GitSHA == "" && c.HeadSHA == "" && c.CIRunURL == "" &&
		(c.GitHub == nil || c.GitHub.isZero()) && (c.GitLab == nil || c.GitLab.isZero())
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

// ToMap converts the GitLab-specific context to the transport-friendly map shape.
func (g *GitLabContext) ToMap() map[string]string {
	if g == nil || g.isZero() {
		return nil
	}
	ctx := make(map[string]string)
	addString(ctx, "project_path", g.ProjectPath)
	addString(ctx, "ref", g.Ref)
	addString(ctx, "job_id", g.JobID)
	addString(ctx, "pipeline_id", g.PipelineID)
	addString(ctx, "source", g.Source)
	addString(ctx, "actor", g.Actor)
	if len(ctx) == 0 {
		return nil
	}
	return ctx
}

func (g *GitLabContext) isZero() bool {
	return g == nil || (g.ProjectPath == "" && g.Ref == "" && g.JobID == "" && g.PipelineID == "" && g.Source == "" && g.Actor == "")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
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
