// Package cmdutil provides shared CLI helpers for epack commands.
package cmdutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	epackerrors "github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/component/sync"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/exitcode"
	"github.com/spf13/cobra"
)

// GetOutput returns an output writer configured from the command's flags.
func GetOutput(cmd *cobra.Command) *output.Writer {
	quiet, _ := cmd.Flags().GetBool("quiet")
	jsonOut, _ := cmd.Flags().GetBool("json")
	noColor, _ := cmd.Flags().GetBool("no-color")
	verbose, _ := cmd.Flags().GetBool("verbose")

	return output.New(os.Stdout, os.Stderr, output.Options{
		Quiet:   quiet,
		JSON:    jsonOut,
		NoColor: noColor || os.Getenv("NO_COLOR") != "",
		Verbose: verbose,
	})
}

// LoadConfig loads the component configuration from the given path.
// Returns a wrapped error on failure with actionable hints.
func LoadConfig(path string) (*config.JobConfig, error) {
	cfg, err := config.Load(path)
	if err != nil {
		// Check for file not found (may be wrapped)
		if errors.Is(err, os.ErrNotExist) {
			return nil, &epackerrors.Error{
				Code:    epackerrors.InvalidInput,
				Exit:    exitcode.General,
				Message: fmt.Sprintf("config file not found: %s\n\nTo get started, run:\n\n  epack init\n\nThis will walk you through creating an epack.yaml configuration.", path),
				Cause:   err,
			}
		}
		return nil, &epackerrors.Error{
			Code:    epackerrors.InvalidInput,
			Exit:    exitcode.General,
			Message: "loading config",
			Cause:   err,
		}
	}
	return cfg, nil
}

// ResolveWorkDir returns the current working directory.
// Returns a wrapped error on failure.
func ResolveWorkDir() (string, error) {
	workDir, err := os.Getwd()
	if err != nil {
		return "", &epackerrors.Error{
			Code:    epackerrors.InvalidInput,
			Exit:    exitcode.General,
			Message: fmt.Sprintf("getting working directory: %v", err),
		}
	}
	return workDir, nil
}

// ResolveWorkDirFromConfigPath derives the working directory from the config file path.
// If configPath is empty or "epack.yaml" (default), returns the current working directory.
// Otherwise, returns the directory containing the config file.
// This ensures that when --config /other/epack.yaml is used, workDir is /other/,
// matching the base directory used for path normalization in config.Load().
func ResolveWorkDirFromConfigPath(configPath string) (string, error) {
	// Default config name means use CWD
	if configPath == "" || configPath == "epack.yaml" {
		return ResolveWorkDir()
	}

	// Get absolute path of config file
	absConfigPath, err := filepath.Abs(configPath)
	if err != nil {
		return "", &epackerrors.Error{
			Code:    epackerrors.InvalidInput,
			Exit:    exitcode.General,
			Message: fmt.Sprintf("resolving config path: %v", err),
		}
	}

	// Return the directory containing the config
	return filepath.Dir(absConfigPath), nil
}

// ParseCommaSeparated splits a comma-separated string into trimmed elements.
// Returns nil if the input is empty.
func ParseCommaSeparated(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// HandleError ensures errors have proper exit codes.
// If the error already has ExitCode(), it's returned as-is.
// Otherwise wraps it in an errors.Error with General exit code.
func HandleError(err error) error {
	// If it's already our error type, return as-is
	var e *epackerrors.Error
	if errors.As(err, &e) {
		return err
	}
	// Wrap in our error type.
	return &epackerrors.Error{
		Code:    epackerrors.InvalidInput,
		Exit:    exitcode.General,
		Message: err.Error(),
	}
}

// ValidateCollectorNames checks that all names exist in config as collectors.
// Returns an error if any name is not found.
func ValidateCollectorNames(cfg *config.JobConfig, names []string) error {
	for _, name := range names {
		if _, ok := cfg.Collectors[name]; !ok {
			return &epackerrors.Error{
				Code:    epackerrors.InvalidInput,
				Exit:    exitcode.General,
				Message: fmt.Sprintf("collector %q not found in config", name),
			}
		}
	}
	return nil
}

// FilterConfigCollectors returns a copy of cfg with only the specified collectors.
// Returns an error if any collector is not found.
func FilterConfigCollectors(cfg *config.JobConfig, names []string) (*config.JobConfig, error) {
	if err := ValidateCollectorNames(cfg, names); err != nil {
		return nil, err
	}
	filtered := make(map[string]config.CollectorConfig)
	for _, name := range names {
		filtered[name] = cfg.Collectors[name]
	}
	// Create a copy with filtered collectors
	result := *cfg
	result.Collectors = filtered
	return &result, nil
}

// FilterConfigComponents returns a copy of cfg with only the specified components.
// Components can be collectors, tools, or remotes - the function figures out which.
// Returns an error if any component is not found.
func FilterConfigComponents(cfg *config.JobConfig, names []string) (*config.JobConfig, error) {
	// First validate all names exist
	for _, name := range names {
		_, isCollector := cfg.Collectors[name]
		_, isTool := cfg.Tools[name]
		_, isRemote := cfg.Remotes[name]
		if !isCollector && !isTool && !isRemote {
			return nil, &epackerrors.Error{
				Code:    epackerrors.InvalidInput,
				Exit:    exitcode.General,
				Message: fmt.Sprintf("component %q not found in config (not a collector, tool, or remote)", name),
			}
		}
	}

	// Create filtered config
	result := *cfg
	result.Collectors = make(map[string]config.CollectorConfig)
	result.Tools = make(map[string]config.ToolConfig)
	result.Remotes = make(map[string]config.RemoteConfig)

	for _, name := range names {
		if c, ok := cfg.Collectors[name]; ok {
			result.Collectors[name] = c
		}
		if t, ok := cfg.Tools[name]; ok {
			result.Tools[name] = t
		}
		if r, ok := cfg.Remotes[name]; ok {
			result.Remotes[name] = r
		}
	}

	return &result, nil
}

// LockfileNeedsUpdate checks if the lockfile needs updating for the given config.
// This checks collectors, tools, remotes, profiles, and overlays for:
// - Missing lockfile entries (gap check)
// - Missing platform entries
// - Profile/overlay content drift (digest mismatch)
func LockfileNeedsUpdate(cfg *config.JobConfig, lf *lockfile.LockFile, currentPlatform, workDir string) bool {
	platforms := requiredPlatforms(cfg.Platforms, currentPlatform)
	if hasCollectorLockfileGap(cfg, lf, platforms) {
		return true
	}
	if hasToolLockfileGap(cfg, lf, platforms) {
		return true
	}
	if hasRemoteLockfileGap(cfg, lf, platforms) {
		return true
	}
	// Check for missing profile/overlay entries OR content drift
	if sync.HasProfileLockfileGap(cfg, lf) {
		return true
	}
	return sync.HasProfileDigestDrift(cfg, lf, workDir)
}

func requiredPlatforms(platforms []string, currentPlatform string) []string {
	if len(platforms) > 0 {
		return platforms
	}
	return []string{currentPlatform}
}

func hasCollectorLockfileGap(cfg *config.JobConfig, lf *lockfile.LockFile, platforms []string) bool {
	for name, c := range cfg.Collectors {
		if c.Source == "" {
			continue
		}
		locked, ok := lf.GetCollector(name)
		if !ok || missingRequiredPlatforms(locked.Platforms, platforms) {
			return true
		}
	}
	return false
}

func hasToolLockfileGap(cfg *config.JobConfig, lf *lockfile.LockFile, platforms []string) bool {
	for name, t := range cfg.Tools {
		if t.Source == "" {
			continue
		}
		locked, ok := lf.GetTool(name)
		if !ok || missingRequiredPlatforms(locked.Platforms, platforms) {
			return true
		}
	}
	return false
}

func hasRemoteLockfileGap(cfg *config.JobConfig, lf *lockfile.LockFile, platforms []string) bool {
	for name, r := range cfg.Remotes {
		if r.Source == "" {
			continue
		}
		locked, ok := lf.GetRemote(name)
		if !ok || missingRequiredPlatforms(locked.Platforms, platforms) {
			return true
		}
	}
	return false
}

func missingRequiredPlatforms(locked map[string]componenttypes.LockedPlatform, required []string) bool {
	for _, platform := range required {
		if _, hasPlatform := locked[platform]; !hasPlatform {
			return true
		}
	}
	return false
}
