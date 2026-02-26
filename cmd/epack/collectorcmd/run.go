//go:build components

package collectorcmd

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/locktivity/epack/internal/collector"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/securityaudit"
	"github.com/locktivity/epack/internal/securitypolicy"
	"github.com/spf13/cobra"
)

var (
	runConfigPath              string
	runFrozen                  bool
	runOnly                    string
	runOutput                  string
	runInsecureAllowUnverified bool
	runInsecureAllowUnpinned   bool
	runTimeout                 time.Duration
)

func newRunCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run collectors and build evidence pack",
		Long: `Execute collectors defined in config and build an evidence pack.

This command:
  1. Loads collector configuration
  2. Verifies collector binaries (digest check before exec)
  3. Runs each collector to gather evidence
  4. Bundles evidence into an evidence pack

Modes:
  Default: Verify digests, run collectors
  --frozen: CI mode - strict verification, fail on any mismatch

The --frozen flag enables additional checks:
  - Lockfile must exist and align with config
  - All collectors must be installed
  - Digest verified immediately before each exec
  - Collectors installed with --insecure-skip-verify are rejected

By default, collectors installed with --insecure-skip-verify are rejected.
Use --insecure-allow-unverified to override (not recommended).

Examples:
  epack collector run --config epack.yaml
  epack collector run --frozen --config epack.yaml
  epack collector run --only github,aws --config epack.yaml`,
		RunE: runRun,
	}

	cmd.Flags().StringVarP(&runConfigPath, "config", "c", "epack.yaml",
		"path to epack config file")
	cmd.Flags().BoolVar(&runFrozen, "frozen", false,
		"fail on any mismatch (CI mode)")
	cmd.Flags().StringVar(&runOnly, "only", "",
		"run only these collectors (comma-separated)")
	cmd.Flags().StringVarP(&runOutput, "output", "o", "",
		"output pack file (default: evidence-<timestamp>.pack)")
	cmd.Flags().BoolVar(&runInsecureAllowUnverified, "insecure-allow-unverified", false,
		"allow running collectors installed with --insecure-skip-verify (NOT RECOMMENDED)")
	// Support env var for insecure-allow-unpinned
	runInsecureAllowUnpinned = componenttypes.InsecureAllowUnpinnedFromEnv()
	cmd.Flags().BoolVar(&runInsecureAllowUnpinned, "insecure-allow-unpinned", runInsecureAllowUnpinned,
		"allow running external collectors not pinned in lockfile (NOT RECOMMENDED)")
	cmd.Flags().DurationVar(&runTimeout, "timeout", time.Duration(limits.DefaultCollectorTimeout),
		"timeout per collector execution (e.g., 30s, 2m)")

	return cmd
}

func runRun(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	out := getOutput(cmd)

	if err := validateRunFlags(); err != nil {
		return handleCollectorError(err)
	}

	cfg, err := loadConfig(runConfigPath)
	if err != nil {
		return err
	}

	// Parse and validate --only flag
	only := parseCommaSeparated(runOnly)
	if err := validateCollectorNames(cfg, only); err != nil {
		return err
	}

	workDir, err := resolveWorkDir()
	if err != nil {
		return err
	}

	// Build options from flags
	opts := collector.RunAndBuildOpts{
		Secure: collector.SecureRunOptions{
			Frozen:  runFrozen,
			Only:    only,
			Timeout: runTimeout,
		},
		Unsafe: collector.UnsafeOverrides{
			AllowUnverifiedInstall: runInsecureAllowUnverified,
			AllowUnpinned:          runInsecureAllowUnpinned,
		},
		WorkDir:    workDir,
		OutputPath: runOutput,
	}

	// Print mode header
	if runFrozen {
		out.Print("Collecting evidence (frozen mode)...\n")
	} else {
		out.Print("Collecting evidence...\n")
	}

	// Run collectors
	result, err := collector.RunAndBuild(ctx, cfg, opts)

	// Print collector results regardless of error
	if result != nil {
		for _, r := range result.CollectorResults {
			if !r.Success {
				out.Print("  FAILED %s: %v\n", r.Collector, r.Error)
			} else {
				out.Print("  collected %s\n", r.Collector)
			}
		}
	}

	if err != nil {
		return handleCollectorError(err)
	}

	// Print success output
	out.Print("Building evidence pack...\n")

	if out.IsJSON() {
		absPath, _ := filepath.Abs(result.PackPath)
		return out.JSON(map[string]interface{}{
			"pack":       absPath,
			"stream":     result.Stream,
			"collectors": len(result.CollectorResults),
			"failures":   result.Failures,
		})
	}

	out.Print("\nEvidence pack written to %s\n", result.PackPath)
	return nil
}

func validateRunFlags() error {
	if err := (securitypolicy.ExecutionPolicy{
		Frozen:        runFrozen,
		AllowUnpinned: runInsecureAllowUnpinned,
	}).Enforce(); err != nil {
		return err
	}
	hasUnsafeOverrides := runInsecureAllowUnverified || runInsecureAllowUnpinned
	if err := securitypolicy.EnforceStrictProduction("collector_run_cli", hasUnsafeOverrides); err != nil {
		return err
	}
	if hasUnsafeOverrides {
		securityaudit.Emit(securityaudit.Event{
			Type:        securityaudit.EventInsecureBypass,
			Component:   "collector_run",
			Name:        "run",
			Description: "collector run command running with insecure execution override",
			Attrs: map[string]string{
				"allow_unverified_install": fmt.Sprintf("%t", runInsecureAllowUnverified),
				"allow_unpinned":           fmt.Sprintf("%t", runInsecureAllowUnpinned),
			},
		})
	}
	return nil
}
