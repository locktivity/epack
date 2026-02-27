package toolprotocol

import (
	"encoding/json"
	"os"
	"runtime"
	"strings"
)

// EnrichResultFromEnv populates Identity and RunContext fields from environment
// variables. This is non-destructive: it won't overwrite values the tool already set.
// Returns true if any fields were modified.
func EnrichResultFromEnv(r *Result) bool {
	a := enrichIdentity(r)
	b := enrichRunContext(r)
	return a || b
}

// enrichIdentity populates Identity from EPACK_IDENTITY if set.
// Supports two formats:
//   - JSON: {"workspace":"...", "actor":"...", "actor_type":"...", "auth_mode":"..."}
//   - Plain string: treated as actor name with actor_type "unknown"
//
// Returns true if any fields were modified.
func enrichIdentity(r *Result) bool {
	identityEnv := os.Getenv("EPACK_IDENTITY")
	if identityEnv == "" {
		return false
	}

	// Try JSON first
	var parsed IdentityInfo
	if err := json.Unmarshal([]byte(identityEnv), &parsed); err == nil {
		return mergeIdentityFromJSON(r, parsed)
	}

	return mergeIdentityFromPlainString(r, identityEnv)
}

// enrichRunContext populates RunContext from CI environment variables.
// Always populates runner_os and runner_arch from runtime.
// Returns true if any fields were modified.
func enrichRunContext(r *Result) bool {
	changed := ensureRunContext(r)

	// Detect CI environment
	ci := detectCI()
	if ci == nil {
		return changed
	}

	return mergeRunContext(r.RunContext, ci) || changed
}

func mergeIdentityFromJSON(r *Result, parsed IdentityInfo) bool {
	identity, changed := ensureIdentity(r)
	changed = mergeStringField(&identity.Workspace, parsed.Workspace) || changed
	changed = mergeStringField(&identity.Actor, parsed.Actor) || changed
	changed = mergeStringField(&identity.ActorType, parsed.ActorType) || changed
	changed = mergeStringField(&identity.AuthMode, parsed.AuthMode) || changed
	return changed
}

func mergeIdentityFromPlainString(r *Result, actor string) bool {
	identity, changed := ensureIdentity(r)
	if identity.Actor != "" {
		return changed
	}
	identity.Actor = actor
	if identity.ActorType == "" {
		identity.ActorType = "unknown"
	}
	return true
}

func ensureIdentity(r *Result) (*IdentityInfo, bool) {
	if r.Identity != nil {
		return r.Identity, false
	}
	r.Identity = &IdentityInfo{}
	return r.Identity, true
}

func ensureRunContext(r *Result) bool {
	changed := false
	if r.RunContext == nil {
		r.RunContext = &RunContextInfo{}
		changed = true
	}
	changed = mergeStringField(&r.RunContext.RunnerOS, runtime.GOOS) || changed
	changed = mergeStringField(&r.RunContext.RunnerArch, runtime.GOARCH) || changed
	return changed
}

func mergeRunContext(dst, src *RunContextInfo) bool {
	changed := false
	if !dst.CI && src.CI {
		dst.CI = true
		changed = true
	}
	changed = mergeStringField(&dst.CIProvider, src.CIProvider) || changed
	changed = mergeStringField(&dst.Repo, src.Repo) || changed
	changed = mergeStringField(&dst.Commit, src.Commit) || changed
	changed = mergeStringField(&dst.Branch, src.Branch) || changed
	return changed
}

func mergeStringField(dst *string, src string) bool {
	if *dst != "" || src == "" {
		return false
	}
	*dst = src
	return true
}

// detectCI detects CI environment and returns context info.
// Returns nil if not in a CI environment.
func detectCI() *RunContextInfo {
	// GitHub Actions
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		return &RunContextInfo{
			CI:         true,
			CIProvider: "github_actions",
			Repo:       os.Getenv("GITHUB_REPOSITORY"),
			Commit:     os.Getenv("GITHUB_SHA"),
			Branch:     normalizeGitRef(os.Getenv("GITHUB_REF")),
		}
	}

	// GitLab CI
	if os.Getenv("GITLAB_CI") == "true" {
		return &RunContextInfo{
			CI:         true,
			CIProvider: "gitlab_ci",
			Repo:       os.Getenv("CI_PROJECT_URL"),
			Commit:     os.Getenv("CI_COMMIT_SHA"),
			Branch:     os.Getenv("CI_COMMIT_REF_NAME"),
		}
	}

	// CircleCI
	if os.Getenv("CIRCLECI") == "true" {
		repo := os.Getenv("CIRCLE_REPOSITORY_URL")
		if repo == "" {
			// Build from org/project
			if org := os.Getenv("CIRCLE_PROJECT_USERNAME"); org != "" {
				if proj := os.Getenv("CIRCLE_PROJECT_REPONAME"); proj != "" {
					repo = org + "/" + proj
				}
			}
		}
		return &RunContextInfo{
			CI:         true,
			CIProvider: "circleci",
			Repo:       repo,
			Commit:     os.Getenv("CIRCLE_SHA1"),
			Branch:     os.Getenv("CIRCLE_BRANCH"),
		}
	}

	// Buildkite
	if os.Getenv("BUILDKITE") == "true" {
		return &RunContextInfo{
			CI:         true,
			CIProvider: "buildkite",
			Repo:       os.Getenv("BUILDKITE_REPO"),
			Commit:     os.Getenv("BUILDKITE_COMMIT"),
			Branch:     os.Getenv("BUILDKITE_BRANCH"),
		}
	}

	// Jenkins
	if os.Getenv("JENKINS_URL") != "" {
		return &RunContextInfo{
			CI:         true,
			CIProvider: "jenkins",
			Repo:       os.Getenv("GIT_URL"),
			Commit:     os.Getenv("GIT_COMMIT"),
			Branch:     os.Getenv("GIT_BRANCH"),
		}
	}

	// Generic CI detection (CI=true is a common convention)
	if os.Getenv("CI") == "true" {
		return &RunContextInfo{
			CI:         true,
			CIProvider: "generic",
		}
	}

	return nil
}

// normalizeGitRef strips refs/heads/ or refs/tags/ prefix from git refs.
func normalizeGitRef(ref string) string {
	ref = strings.TrimPrefix(ref, "refs/heads/")
	ref = strings.TrimPrefix(ref, "refs/tags/")
	return ref
}
