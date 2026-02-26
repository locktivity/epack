//go:build components

package remotecmd

import (
	"os"
	"path/filepath"
	"sort"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/project"
	"github.com/locktivity/epack/internal/remote"
	"github.com/spf13/cobra"
)

var (
	whoamiInsecureAllowUnpinned bool
)

func newWhoamiCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "whoami [remote]",
		Short: "Show authentication status",
		Long: `Show the current authentication status for a remote.

If no remote is specified, shows status for all configured remotes.

This command queries the remote adapter for the current identity, which
is useful for debugging authentication issues.

Examples:
  # Show auth status for locktivity remote
  epack remote whoami locktivity

  # Show auth status for all remotes
  epack remote whoami

  # Output in JSON format
  epack remote whoami --json`,
		Args: cobra.MaximumNArgs(1),
		RunE: runWhoami,
	}

	// Support env var for insecure-allow-unpinned
	whoamiInsecureAllowUnpinned = componenttypes.InsecureAllowUnpinnedFromEnv()
	cmd.Flags().BoolVar(&whoamiInsecureAllowUnpinned, "insecure-allow-unpinned", whoamiInsecureAllowUnpinned,
		"allow using adapters not pinned in lockfile (NOT RECOMMENDED)")

	return cmd
}

func runWhoami(cmd *cobra.Command, args []string) error {
	out := outputWriter()
	ctx := cmdContext(cmd)

	// Find project root
	projectRoot, err := project.FindRoot("")
	if err != nil {
		return exitError("not in an epack project: %v", err)
	}

	// Load config
	configPath := filepath.Join(projectRoot, project.ConfigFileName)
	cfg, err := config.Load(configPath)
	if err != nil {
		return exitError("loading config: %v", err)
	}

	// Determine which remotes to query
	var remoteNames []string
	if len(args) > 0 {
		// Single remote specified
		remoteName := args[0]
		if _, ok := cfg.Remotes[remoteName]; !ok {
			return exitError("remote %q not found in config", remoteName)
		}
		remoteNames = []string{remoteName}
	} else {
		// All remotes
		if len(cfg.Remotes) == 0 {
			if out.IsJSON() {
				return out.JSON(map[string]interface{}{
					"identities": []interface{}{},
				})
			}
			out.Print("No remotes configured.\n")
			return nil
		}
		for name := range cfg.Remotes {
			remoteNames = append(remoteNames, name)
		}
		sort.Strings(remoteNames)
	}

	// Query each remote
	type identityInfo struct {
		Remote        string `json:"remote"`
		Authenticated bool   `json:"authenticated"`
		Subject       string `json:"subject,omitempty"`
		Issuer        string `json:"issuer,omitempty"`
		ExpiresAt     string `json:"expires_at,omitempty"`
		Error         string `json:"error,omitempty"`
		Supported     bool   `json:"supported"`
	}

	identities := make([]identityInfo, 0, len(remoteNames))

	for _, remoteName := range remoteNames {
		info := identityInfo{
			Remote:    remoteName,
			Supported: true,
		}

		// Resolve remote config (no environment override for whoami)
		resolvedCfg, err := remote.ResolveRemoteConfig(cfg, remoteName, "")
		if err != nil {
			info.Error = err.Error()
			info.Supported = false
			identities = append(identities, info)
			continue
		}

		// Prepare adapter executor
		opts := remote.AdapterExecutorOptions{
			Stderr: os.Stderr,
			Verification: remote.VerificationOptions{
				AllowUnverifiedSource: whoamiInsecureAllowUnpinned,
			},
		}

		exec, caps, err := remote.PrepareAdapterExecutor(ctx, projectRoot, remoteName, cfg, resolvedCfg, opts)
		if err != nil {
			info.Error = err.Error()
			info.Supported = false
			identities = append(identities, info)
			continue
		}

		// Check if adapter supports whoami
		if !caps.SupportsWhoami() {
			exec.Close()
			info.Supported = false
			info.Error = "adapter does not support whoami"
			identities = append(identities, info)
			continue
		}

		// Query identity
		resp, err := exec.AuthWhoami(ctx)
		exec.Close() // Close executor after use (don't defer in loop)
		if err != nil {
			info.Error = err.Error()
			identities = append(identities, info)
			continue
		}

		info.Authenticated = resp.Identity.Authenticated
		info.Subject = resp.Identity.Subject
		info.Issuer = resp.Identity.Issuer
		info.ExpiresAt = resp.Identity.ExpiresAt

		identities = append(identities, info)
	}

	// JSON output
	if out.IsJSON() {
		return out.JSON(map[string]interface{}{
			"identities": identities,
		})
	}

	// Human-readable output
	p := out.Palette()

	if len(identities) == 1 {
		info := identities[0]
		if info.Error != "" {
			out.Print("%s %s: %s\n", p.Red("✗"), info.Remote, info.Error)
			return nil
		}
		if !info.Supported {
			out.Print("%s %s: whoami not supported by adapter\n", p.Yellow("?"), info.Remote)
			return nil
		}
		if info.Authenticated {
			out.Print("%s Authenticated to %s\n", p.Green("✓"), p.Bold(info.Remote))
			if info.Subject != "" {
				out.Print("  Subject:   %s\n", info.Subject)
			}
			if info.Issuer != "" {
				out.Print("  Issuer:    %s\n", info.Issuer)
			}
			if info.ExpiresAt != "" {
				out.Print("  Expires:   %s\n", info.ExpiresAt)
			}
		} else {
			out.Print("%s Not authenticated to %s\n", p.Yellow("○"), p.Bold(info.Remote))
			out.Print("\nTo authenticate, run:\n")
			out.Print("  epack push %s <pack.epack>\n", info.Remote)
		}
		return nil
	}

	// Multiple remotes
	out.Print("%s\n\n", p.Bold("Authentication Status"))

	for _, info := range identities {
		if info.Error != "" {
			out.Print("%s %s: %s\n", p.Red("✗"), p.Bold(info.Remote), info.Error)
			continue
		}
		if !info.Supported {
			out.Print("%s %s: whoami not supported\n", p.Yellow("?"), p.Bold(info.Remote))
			continue
		}
		if info.Authenticated {
			if info.Subject != "" {
				out.Print("%s %s: %s\n", p.Green("✓"), p.Bold(info.Remote), info.Subject)
			} else {
				out.Print("%s %s: authenticated\n", p.Green("✓"), p.Bold(info.Remote))
			}
		} else {
			out.Print("%s %s: not authenticated\n", p.Yellow("○"), p.Bold(info.Remote))
		}
	}

	return nil
}
