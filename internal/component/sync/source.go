package sync

import (
	"fmt"
	"strings"
)

// Source URI parsing utilities.
// Source URIs follow the format: github.com/owner/repo

const githubPrefix = "github.com/"

// ParseSourceURI parses "github.com/owner/repo" into owner and repo components.
// This is the lockfile format (no version).
// SECURITY: Error messages use %q to escape untrusted input, preventing log injection.
func ParseSourceURI(source string) (owner, repo string, err error) {
	if !strings.HasPrefix(source, githubPrefix) {
		if len(source) > 0 && source[0] != 'g' {
			return "", "", fmt.Errorf("unsupported source host: %q", source)
		}
		return "", "", fmt.Errorf("invalid source URI: %q", source)
	}

	rest := source[len(githubPrefix):]
	if rest == "" {
		return "", "", fmt.Errorf("invalid source URI: %q", source)
	}

	idx := strings.IndexByte(rest, '/')
	if idx < 0 {
		return "", "", fmt.Errorf("invalid source URI: %q", source)
	}

	owner = rest[:idx]
	repo = rest[idx+1:]

	if owner == "" || repo == "" {
		return "", "", fmt.Errorf("invalid source URI: %q", source)
	}

	return owner, repo, nil
}

// BuildSourceURI constructs "github.com/owner/repo" from components.
func BuildSourceURI(owner, repo string) string {
	return githubPrefix + owner + "/" + repo
}

// BuildGitHubRepoURL constructs "https://github.com/owner/repo" from components.
func BuildGitHubRepoURL(owner, repo string) string {
	return "https://github.com/" + owner + "/" + repo
}

// BuildGitHubRefTag constructs "refs/tags/version" from a version string.
func BuildGitHubRefTag(version string) string {
	return "refs/tags/" + version
}
