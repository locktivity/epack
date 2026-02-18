package verify

import (
	"fmt"
	"regexp"
)

// Common OIDC issuers for preset verifiers.
const (
	// GoogleAccountsIssuer is the OIDC issuer for Google Accounts.
	GoogleAccountsIssuer = "https://accounts.google.com"

	// GitHubActionsIssuer is the OIDC issuer for GitHub Actions.
	GitHubActionsIssuer = "https://token.actions.githubusercontent.com"
)

// NewGitHubActionsVerifier creates a verifier for GitHub Actions workload identity.
// It verifies that attestations were signed by a specific GitHub repository and
// optionally a specific workflow.
//
// The repo parameter should be in "owner/repo" format (e.g., "myorg/myrepo").
// The workflow parameter is optional; if provided, it restricts to a specific
// workflow file (e.g., "release.yml" or ".github/workflows/release.yml").
//
// Example:
//
//	// Any workflow in the repo
//	v, err := verify.NewGitHubActionsVerifier("myorg/myrepo", "")
//
//	// Specific workflow only
//	v, err := verify.NewGitHubActionsVerifier("myorg/myrepo", "release.yml")
func NewGitHubActionsVerifier(repo string, workflow string, opts ...Option) (*SigstoreVerifier, error) {
	if repo == "" {
		return nil, fmt.Errorf("repo is required")
	}

	// GitHub Actions subject format: https://github.com/OWNER/REPO/.github/workflows/WORKFLOW@REF
	// We build a regex to match the expected pattern
	var subjectPattern *regexp.Regexp
	if workflow != "" {
		// Strip leading path if user provided full path
		if len(workflow) > 0 && workflow[0] != '.' {
			// User provided just filename, construct full pattern
			subjectPattern = regexp.MustCompile(
				fmt.Sprintf(`^https://github\.com/%s/\.github/workflows/%s@.+$`,
					regexp.QuoteMeta(repo), regexp.QuoteMeta(workflow)))
		} else {
			// User provided path starting with .github/
			subjectPattern = regexp.MustCompile(
				fmt.Sprintf(`^https://github\.com/%s/%s@.+$`,
					regexp.QuoteMeta(repo), regexp.QuoteMeta(workflow)))
		}
	} else {
		// Any workflow in the repo
		subjectPattern = regexp.MustCompile(
			fmt.Sprintf(`^https://github\.com/%s/\.github/workflows/.+@.+$`,
				regexp.QuoteMeta(repo)))
	}

	// Prepend our preset options, allowing user opts to override
	allOpts := append([]Option{
		WithIssuer(GitHubActionsIssuer),
		WithSubjectRegexp(subjectPattern),
	}, opts...)

	return NewSigstoreVerifier(allOpts...)
}

// NewGoogleCloudVerifier creates a verifier for Google Cloud workload identity.
// It verifies that attestations were signed by a specific service account.
//
// The serviceAccount parameter should be the full email address
// (e.g., "my-sa@my-project.iam.gserviceaccount.com").
//
// Example:
//
//	v, err := verify.NewGoogleCloudVerifier("builder@my-project.iam.gserviceaccount.com")
func NewGoogleCloudVerifier(serviceAccount string, opts ...Option) (*SigstoreVerifier, error) {
	if serviceAccount == "" {
		return nil, fmt.Errorf("serviceAccount is required")
	}

	// Prepend our preset options, allowing user opts to override
	allOpts := append([]Option{
		WithIssuer(GoogleAccountsIssuer),
		WithSubject(serviceAccount),
	}, opts...)

	return NewSigstoreVerifier(allOpts...)
}

// NewGoogleAccountVerifier creates a verifier for any Google account.
// It verifies that attestations were signed by a specific Google account email.
//
// Example:
//
//	v, err := verify.NewGoogleAccountVerifier("user@example.com")
func NewGoogleAccountVerifier(email string, opts ...Option) (*SigstoreVerifier, error) {
	if email == "" {
		return nil, fmt.Errorf("email is required")
	}

	// Prepend our preset options, allowing user opts to override
	allOpts := append([]Option{
		WithIssuer(GoogleAccountsIssuer),
		WithSubject(email),
	}, opts...)

	return NewSigstoreVerifier(allOpts...)
}
