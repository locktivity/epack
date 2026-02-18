// Package version provides shared version information for epack.
// Variables are set at build time via ldflags.
package version

// Build-time variables - set via ldflags:
//
//	-ldflags "-X github.com/locktivity/epack/internal/version.Version=1.0.0 \
//	          -X github.com/locktivity/epack/internal/version.Commit=abc123 \
//	          -X github.com/locktivity/epack/internal/version.BuildDate=2026-01-01"
var (
	// Version is the semantic version of epack.
	Version = "dev"

	// Commit is the git commit SHA.
	Commit = "unknown"

	// BuildDate is the date the binary was built.
	BuildDate = "unknown"
)
