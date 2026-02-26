//go:build components

package remotecmd

import (
	"path/filepath"
	"sort"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/project"
	"github.com/spf13/cobra"
)

func newListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List configured remotes",
		Long: `List all remotes configured in epack.yaml.

Shows remote name, adapter, target workspace, and whether it's a source-based
or external adapter.

Examples:
  # List all remotes
  epack remote list

  # List in JSON format
  epack remote list --json`,
		Aliases: []string{"ls"},
		RunE:    runList,
	}

	return cmd
}

func runList(cmd *cobra.Command, args []string) error {
	out := outputWriter()

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

	// Check if any remotes configured
	if len(cfg.Remotes) == 0 {
		if out.IsJSON() {
			return out.JSON(map[string]interface{}{
				"remotes": []interface{}{},
			})
		}
		out.Print("No remotes configured.\n")
		out.Print("\nTo add a remote, edit epack.yaml:\n")
		out.Print("  remotes:\n")
		out.Print("    locktivity:\n")
		out.Print("      source: locktivity/epack-remote-locktivity@v1\n")
		out.Print("      target:\n")
		out.Print("        workspace: my-workspace\n")
		return nil
	}

	// Sort remote names for consistent output
	names := make([]string, 0, len(cfg.Remotes))
	for name := range cfg.Remotes {
		names = append(names, name)
	}
	sort.Strings(names)

	// Build output
	type remoteInfo struct {
		Name        string `json:"name"`
		Adapter     string `json:"adapter"`
		Source      string `json:"source,omitempty"`
		Binary      string `json:"binary,omitempty"`
		Workspace   string `json:"workspace,omitempty"`
		Environment string `json:"environment,omitempty"`
		Endpoint    string `json:"endpoint,omitempty"`
	}

	remotes := make([]remoteInfo, 0, len(names))
	for _, name := range names {
		remoteCfg := cfg.Remotes[name]
		info := remoteInfo{
			Name:        name,
			Adapter:     remoteCfg.EffectiveAdapter(),
			Source:      remoteCfg.Source,
			Binary:      remoteCfg.Binary,
			Workspace:   remoteCfg.Target.Workspace,
			Environment: remoteCfg.Target.Environment,
			Endpoint:    remoteCfg.Endpoint,
		}
		remotes = append(remotes, info)
	}

	// JSON output
	if out.IsJSON() {
		return out.JSON(map[string]interface{}{
			"remotes": remotes,
		})
	}

	// Human-readable output
	p := out.Palette()
	out.Print("%s\n\n", p.Bold("Configured Remotes"))

	for _, r := range remotes {
		out.Print("%s\n", p.Bold(r.Name))

		if r.Source != "" {
			out.Print("  Adapter:   %s (source)\n", r.Adapter)
			out.Print("  Source:    %s\n", r.Source)
		} else if r.Binary != "" {
			out.Print("  Adapter:   %s (external)\n", r.Adapter)
			out.Print("  Binary:    %s\n", r.Binary)
		} else {
			out.Print("  Adapter:   %s\n", r.Adapter)
		}

		if r.Workspace != "" {
			out.Print("  Workspace: %s\n", r.Workspace)
		}
		if r.Environment != "" {
			out.Print("  Environment: %s\n", r.Environment)
		}
		if r.Endpoint != "" {
			out.Print("  Endpoint:  %s\n", r.Endpoint)
		}

		out.Print("\n")
	}

	return nil
}
