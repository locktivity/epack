//go:build components

package utilitycmd

import (
	"fmt"

	"github.com/locktivity/epack/internal/catalog"
	"github.com/locktivity/epack/internal/catalog/resolve"
	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/userconfig"
	"github.com/spf13/cobra"
)

var (
	installRefresh         bool
	installDryRun          bool
	insecureSkipVerify     bool
	insecureTrustOnFirst   bool
)

func newInstallCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install <name>[@version]",
		Short: "Install a utility from the catalog",
		Long: `Install a utility by looking it up in the catalog.

The utility is looked up in the catalog to discover its source repository,
then downloaded, verified with Sigstore, and installed to ~/.epack/bin/.

Version constraints:
  viewer          Use latest version
  viewer@latest   Same as above
  viewer@^1.0     Caret: >=1.0.0 <2.0.0
  viewer@~1.2     Tilde: >=1.2.0 <1.3.0
  viewer@v1.2.3   Exact version

EXAMPLES

  # Install from catalog
  epack utility install viewer

  # Install specific version
  epack utility install viewer@v1.0.0

  # Preview what would be installed
  epack utility install viewer --dry-run

  # Refresh catalog before lookup
  epack utility install viewer --refresh

  # Install without Sigstore verification (NOT RECOMMENDED)
  epack utility install viewer --insecure-skip-verify`,
		Args: cobra.ExactArgs(1),
		RunE: runInstallUtility,
	}

	cmd.Flags().BoolVar(&installRefresh, "refresh", false,
		"refresh catalog before lookup")
	cmd.Flags().BoolVar(&installDryRun, "dry-run", false,
		"show what would be installed without making changes")
	cmd.Flags().BoolVar(&insecureSkipVerify, "insecure-skip-verify", false,
		"Skip Sigstore signature verification (NOT RECOMMENDED)")
	cmd.Flags().BoolVar(&insecureTrustOnFirst, "insecure-trust-on-first", false,
		"Trust digest without Sigstore verification (NOT RECOMMENDED)")

	return cmd
}

func runInstallUtility(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	// Parse the argument (name or name@version)
	parsed, err := resolve.ParseComponentArg(args[0])
	if err != nil {
		return fmt.Errorf("invalid argument %q: %w (format: name or name@version)", args[0], err)
	}

	// Validate utility name
	if err := validateUtilityName(parsed.Name); err != nil {
		return err
	}

	// Refresh catalog if requested or missing
	if installRefresh || !catalog.Exists() {
		fmt.Println("Refreshing catalog...")
		_, err := catalog.FetchCatalog(ctx, catalog.FetchOptions{})
		if err != nil {
			return fmt.Errorf("fetching catalog: %w", err)
		}
	}

	// Load the cached catalog
	cat, _, err := catalog.ReadCatalog()
	if err != nil {
		if err == catalog.ErrNoCatalog {
			return fmt.Errorf("catalog not found; run 'epack utility install --refresh %s'", parsed.Name)
		}
		return fmt.Errorf("reading catalog: %w", err)
	}

	// Look up the utility in the catalog
	component, found := cat.FindByNameAndKind(parsed.Name, componenttypes.KindUtility)
	if !found {
		return fmt.Errorf("utility %q not found in catalog\n\nTry: epack catalog search --kind utility %s", parsed.Name, parsed.Name)
	}

	// Extract source from catalog entry
	source, err := buildSourceString(component, parsed.Constraint)
	if err != nil {
		return fmt.Errorf("utility %q has invalid repo_url: %w", parsed.Name, err)
	}

	// Dry run: just show what would happen
	if installDryRun {
		fmt.Printf("\nWould install:\n")
		fmt.Printf("  + %s\n", parsed.Name)
		fmt.Printf("\nSource: %s\n", source)
		if component.Description != "" {
			fmt.Printf("Description: %s\n", component.Description)
		}
		fmt.Printf("\nRun without --dry-run to install.\n")
		return nil
	}

	// Install the utility
	fmt.Printf("Installing %s...\n", parsed.Name)

	syncer := userconfig.NewUtilitySyncer()
	result, err := syncer.Install(ctx, parsed.Name, source, userconfig.InstallOpts{
		InsecureSkipVerify:   insecureSkipVerify,
		InsecureTrustOnFirst: insecureTrustOnFirst,
	})
	if err != nil {
		return fmt.Errorf("installing utility: %w", err)
	}

	if result.Verified {
		fmt.Printf("Installed %s@%s (verified)\n", result.Name, result.Version)
	} else {
		fmt.Printf("Installed %s@%s (UNVERIFIED)\n", result.Name, result.Version)
	}
	fmt.Printf("Path: %s\n", result.Path)
	fmt.Printf("\nRun with: epack utility %s\n", parsed.Name)

	return nil
}

// buildSourceString constructs the source string from a catalog component.
// Format: owner/repo@version
func buildSourceString(component catalog.CatalogComponent, constraint string) (string, error) {
	repoPath, err := extractRepoPath(component.RepoURL)
	if err != nil {
		return "", err
	}

	if constraint != "" && constraint != "latest" {
		// User specified an explicit constraint
		return repoPath + "@" + constraint, nil
	}
	if component.Latest != "" {
		// Use latest version from catalog
		return repoPath + "@" + component.Latest, nil
	}
	return "", fmt.Errorf("utility has no published releases yet; check the repository for release status")
}

// extractRepoPath extracts "owner/repo" from a GitHub URL.
func extractRepoPath(repoURL string) (string, error) {
	const githubPrefix = "https://github.com/"
	if repoURL == "" {
		return "", fmt.Errorf("catalog entry is incomplete (missing repository URL)")
	}
	if len(repoURL) < len(githubPrefix) || repoURL[:len(githubPrefix)] != githubPrefix {
		return "", fmt.Errorf("unsupported repo URL format: must start with %s", githubPrefix)
	}

	path := repoURL[len(githubPrefix):]
	// Trim trailing slash if present
	if len(path) > 0 && path[len(path)-1] == '/' {
		path = path[:len(path)-1]
	}

	// Find first and second slash to extract owner/repo
	firstSlash := -1
	for i, c := range path {
		if c == '/' {
			if firstSlash == -1 {
				firstSlash = i
			} else {
				// Return only owner/repo, ignore additional path segments
				return path[:i], nil
			}
		}
	}

	if firstSlash == -1 {
		return "", fmt.Errorf("repo URL must have owner/repo format")
	}

	return path, nil
}

func validateUtilityName(name string) error {
	return config.ValidateUtilityName(name)
}
