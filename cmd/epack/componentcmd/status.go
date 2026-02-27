//go:build components

package componentcmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/project"
	"github.com/spf13/cobra"
)

func newStatusCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show project status",
		Long: `Show the current status of the epack project.

Displays information about the project configuration, lockfile state,
installed components, and recent push history.

Examples:
  # Show project status
  epack status`,
		Args: cobra.NoArgs,
		RunE: runStatus,
	}
}

// statusInfo contains all status information for JSON output.
type statusInfo struct {
	ProjectRoot string            `json:"project_root"`
	ConfigPath  string            `json:"config_path"`
	ConfigValid bool              `json:"config_valid"`
	ConfigReady bool              `json:"config_ready"`
	ConfigError string            `json:"config_error,omitempty"`
	Stream      string            `json:"stream,omitempty"`
	Lockfile    *lockfileStatus   `json:"lockfile,omitempty"`
	Collectors  []componentStatus `json:"collectors,omitempty"`
	Tools       []componentStatus `json:"tools,omitempty"`
	Remotes     []remoteStatus    `json:"remotes,omitempty"`
	LastPush    *pushStatus       `json:"last_push,omitempty"`
}

type lockfileStatus struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
	Valid  bool   `json:"valid"`
	Error  string `json:"error,omitempty"`
}

type componentStatus struct {
	Name      string `json:"name"`
	Source    string `json:"source,omitempty"`
	Version   string `json:"version,omitempty"`
	Installed bool   `json:"installed"`
}

type remoteStatus struct {
	Name        string `json:"name"`
	Adapter     string `json:"adapter,omitempty"`
	Workspace   string `json:"workspace,omitempty"`
	Environment string `json:"environment,omitempty"`
}

type pushStatus struct {
	Remote      string    `json:"remote"`
	Timestamp   time.Time `json:"timestamp"`
	ReleaseID   string    `json:"release_id,omitempty"`
	PackPath    string    `json:"pack_path,omitempty"`
	ReceiptPath string    `json:"receipt_path"`
}

func runStatus(cmd *cobra.Command, args []string) error {
	out := getOutput(cmd)

	// Find project root
	projectRoot, err := project.FindRoot("")
	if err != nil {
		if out.IsJSON() {
			return out.JSON(statusInfo{
				ConfigValid: false,
				ConfigError: "no epack project found (missing epack.yaml)",
			})
		}
		out.Print("No epack project found.\n")
		out.Print("  Run 'epack init' to initialize a project in this directory.\n")
		return nil
	}

	status := statusInfo{
		ProjectRoot: projectRoot,
		ConfigPath:  filepath.Join(projectRoot, "epack.yaml"),
	}

	// Load config
	cfg, cfgErr := config.Load(status.ConfigPath)
	if cfgErr != nil {
		rawCfg, rawErr := config.LoadUnvalidated(status.ConfigPath)
		if rawErr == nil && isStarterConfig(rawCfg) {
			cfg = rawCfg
			status.ConfigValid = true
			status.ConfigReady = false
			status.Stream = cfg.Stream
		} else {
			status.ConfigValid = false
			status.ConfigReady = false
			status.ConfigError = cfgErr.Error()
		}
	} else {
		status.ConfigValid = true
		status.ConfigReady = true
		status.Stream = cfg.Stream
	}

	// Check lockfile
	lockfilePath := filepath.Join(projectRoot, lockfile.FileName)
	status.Lockfile = &lockfileStatus{
		Path: lockfilePath,
	}

	if _, err := os.Stat(lockfilePath); os.IsNotExist(err) {
		status.Lockfile.Exists = false
	} else {
		status.Lockfile.Exists = true
		if _, err := lockfile.Load(lockfilePath); err != nil {
			status.Lockfile.Valid = false
			status.Lockfile.Error = err.Error()
		} else {
			status.Lockfile.Valid = true
		}
	}

	// List collectors
	if cfg != nil {
		for name, c := range cfg.Collectors {
			status.Collectors = append(status.Collectors, componentStatus{
				Name:      name,
				Source:    c.Source,
				Installed: isComponentInstalled(projectRoot, "collectors", name),
			})
		}
		sort.Slice(status.Collectors, func(i, j int) bool {
			return status.Collectors[i].Name < status.Collectors[j].Name
		})

		// List tools
		for name, t := range cfg.Tools {
			status.Tools = append(status.Tools, componentStatus{
				Name:      name,
				Source:    t.Source,
				Installed: isComponentInstalled(projectRoot, "tools", name),
			})
		}
		sort.Slice(status.Tools, func(i, j int) bool {
			return status.Tools[i].Name < status.Tools[j].Name
		})

		// List remotes
		for name, r := range cfg.Remotes {
			status.Remotes = append(status.Remotes, remoteStatus{
				Name:        name,
				Adapter:     r.EffectiveAdapter(),
				Workspace:   r.Target.Workspace,
				Environment: r.Target.Environment,
			})
		}
		sort.Slice(status.Remotes, func(i, j int) bool {
			return status.Remotes[i].Name < status.Remotes[j].Name
		})
	}

	// Find most recent push receipt
	status.LastPush = findLastPush(projectRoot)

	// Output
	if out.IsJSON() {
		return out.JSON(status)
	}

	// Human-readable output
	palette := out.Palette()

	out.Print("%s\n", palette.Bold("epack project"))
	out.Print("  Root: %s\n", projectRoot)
	out.Print("\n")

	// Config status
	out.Print("%s\n", palette.Bold("Configuration:"))
	if status.ConfigValid {
		if status.ConfigReady {
			out.Print("  %s %s\n", palette.Green("✓"), "epack.yaml")
		} else {
			out.Print("  %s %s\n", palette.Yellow("○"), "epack.yaml")
			out.Print("    Starter config: add at least one collector, tool, or remote.\n")
		}
		if status.Stream != "" {
			out.Print("    Stream: %s\n", status.Stream)
		}
	} else {
		out.Print("  %s %s\n", palette.Red("✗"), "epack.yaml")
		out.Print("    Error: %s\n", status.ConfigError)
	}

	// Lockfile status
	if status.Lockfile.Exists {
		if status.Lockfile.Valid {
			out.Print("  %s %s\n", palette.Green("✓"), lockfile.FileName)
		} else {
			out.Print("  %s %s\n", palette.Red("✗"), lockfile.FileName)
			out.Print("    Error: %s\n", status.Lockfile.Error)
		}
	} else {
		out.Print("  %s %s %s\n", palette.Yellow("○"), lockfile.FileName, palette.Dim("(not created, run 'epack lock')"))
	}

	// Components
	if len(status.Collectors) > 0 || len(status.Tools) > 0 {
		out.Print("\n%s\n", palette.Bold("Components:"))
		for _, c := range status.Collectors {
			icon := palette.Green("✓")
			if !c.Installed {
				icon = palette.Yellow("○")
			}
			out.Print("  %s collector/%s\n", icon, c.Name)
		}
		for _, t := range status.Tools {
			icon := palette.Green("✓")
			if !t.Installed {
				icon = palette.Yellow("○")
			}
			out.Print("  %s tool/%s\n", icon, t.Name)
		}
	}

	// Remotes
	if len(status.Remotes) > 0 {
		out.Print("\n%s\n", palette.Bold("Remotes:"))
		for _, r := range status.Remotes {
			target := r.Workspace
			if r.Environment != "" {
				target += "/" + r.Environment
			}
			out.Print("  %s → %s\n", r.Name, target)
		}
	}

	// Last push
	if status.LastPush != nil {
		out.Print("\n%s\n", palette.Bold("Last push:"))
		out.Print("  Remote: %s\n", status.LastPush.Remote)
		out.Print("  Time:   %s\n", formatTimeAgo(status.LastPush.Timestamp))
		if status.LastPush.ReleaseID != "" {
			out.Print("  Release: %s\n", status.LastPush.ReleaseID)
		}
	}

	return nil
}

func isStarterConfig(cfg *config.JobConfig) bool {
	if cfg == nil {
		return false
	}
	return len(cfg.Collectors) == 0 && len(cfg.Tools) == 0 && len(cfg.Remotes) == 0
}

// isComponentInstalled checks if a component binary is installed.
func isComponentInstalled(projectRoot, kind, name string) bool {
	// Check in .epack/<kind>/<name>/
	dir := filepath.Join(projectRoot, ".epack", kind, name)
	if info, err := os.Stat(dir); err == nil && info.IsDir() {
		return true
	}
	return false
}

// findLastPush finds the most recent push receipt.
func findLastPush(projectRoot string) *pushStatus {
	// Look for receipts in common locations
	receiptsDir := filepath.Join(projectRoot, ".epack", "receipts", "push")
	if _, err := os.Stat(receiptsDir); os.IsNotExist(err) {
		return nil
	}

	entries, err := os.ReadDir(receiptsDir)
	if err != nil || len(entries) == 0 {
		return nil
	}

	// Find most recent receipt
	var latest os.DirEntry
	var latestTime time.Time
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			info, err := e.Info()
			if err == nil && info.ModTime().After(latestTime) {
				latest = e
				latestTime = info.ModTime()
			}
		}
	}

	if latest == nil {
		return nil
	}

	// Parse the receipt
	receiptPath := filepath.Join(receiptsDir, latest.Name())
	data, err := os.ReadFile(receiptPath)
	if err != nil {
		return nil
	}

	var receipt struct {
		Remote    string    `json:"remote"`
		Timestamp time.Time `json:"timestamp"`
		Release   struct {
			ReleaseID string `json:"release_id"`
		} `json:"release"`
		Pack struct {
			Path string `json:"path"`
		} `json:"pack"`
	}
	if err := json.Unmarshal(data, &receipt); err != nil {
		return nil
	}

	return &pushStatus{
		Remote:      receipt.Remote,
		Timestamp:   receipt.Timestamp,
		ReleaseID:   receipt.Release.ReleaseID,
		PackPath:    receipt.Pack.Path,
		ReceiptPath: receiptPath,
	}
}

// formatTimeAgo formats a time as a human-readable "X ago" string.
func formatTimeAgo(t time.Time) string {
	d := time.Since(t)

	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		mins := int(d.Minutes())
		if mins == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", mins)
	case d < 24*time.Hour:
		hours := int(d.Hours())
		if hours == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", hours)
	case d < 7*24*time.Hour:
		days := int(d.Hours() / 24)
		if days == 1 {
			return "1 day ago"
		}
		return fmt.Sprintf("%d days ago", days)
	default:
		return t.Format("2006-01-02 15:04")
	}
}
