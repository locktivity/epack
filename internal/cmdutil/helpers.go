// Package cmdutil provides shared CLI helpers for epack commands.
package cmdutil

import (
	"errors"
	"fmt"
	"os"
	"strings"

	epackerrors "github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/lockfile"
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
			Message: fmt.Sprintf("loading config: %v", err),
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
	// Wrap in our error type
	return &epackerrors.Error{
		Code:    epackerrors.InvalidInput,
		Exit:    exitcode.General,
		Message: err.Error(),
		Cause:   err,
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
// Components can be either collectors or tools - the function figures out which.
// Returns an error if any component is not found.
func FilterConfigComponents(cfg *config.JobConfig, names []string) (*config.JobConfig, error) {
	// First validate all names exist
	for _, name := range names {
		_, isCollector := cfg.Collectors[name]
		_, isTool := cfg.Tools[name]
		if !isCollector && !isTool {
			return nil, &epackerrors.Error{
				Code:    epackerrors.InvalidInput,
				Exit:    exitcode.General,
				Message: fmt.Sprintf("component %q not found in config (not a collector or tool)", name),
			}
		}
	}

	// Create filtered config
	result := *cfg
	result.Collectors = make(map[string]config.CollectorConfig)
	result.Tools = make(map[string]config.ToolConfig)

	for _, name := range names {
		if c, ok := cfg.Collectors[name]; ok {
			result.Collectors[name] = c
		}
		if t, ok := cfg.Tools[name]; ok {
			result.Tools[name] = t
		}
	}

	return &result, nil
}

// LockfileNeedsUpdate checks if the lockfile needs updating for the given config.
// This checks both collectors and tools.
func LockfileNeedsUpdate(cfg *config.JobConfig, lf *lockfile.LockFile, currentPlatform string) bool {
	// Determine required platforms
	platforms := cfg.Platforms
	if len(platforms) == 0 {
		platforms = []string{currentPlatform}
	}

	// Check each source collector
	for name, c := range cfg.Collectors {
		if c.Source == "" {
			continue // External binary, skip
		}

		locked, ok := lf.GetCollector(name)
		if !ok {
			return true // Collector not in lockfile
		}

		// Check if all required platforms are present
		for _, platform := range platforms {
			if _, hasPlatform := locked.Platforms[platform]; !hasPlatform {
				return true // Platform missing
			}
		}
	}

	// Check each source tool
	for name, t := range cfg.Tools {
		if t.Source == "" {
			continue // External binary, skip
		}

		locked, ok := lf.GetTool(name)
		if !ok {
			return true // Tool not in lockfile
		}

		// Check if all required platforms are present
		for _, platform := range platforms {
			if _, hasPlatform := locked.Platforms[platform]; !hasPlatform {
				return true // Platform missing
			}
		}
	}

	return false
}
