//go:build components

package remotecmd

import (
	"io"
	"os"
	"path/filepath"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/lockprovenance"
	"github.com/locktivity/epack/internal/project"
	"github.com/locktivity/epack/internal/remote"
	"github.com/locktivity/epack/internal/securityaudit"
	"github.com/locktivity/epack/internal/securitypolicy"
	"github.com/spf13/cobra"
)

var (
	reportLockEnv                   string
	reportLockWorkspace             string
	reportLockReason                string
	reportLockOutcome               string
	reportLockFailureCode           string
	reportLockFailureMessage        string
	reportLockInsecureAllowUnpinned bool
)

func newReportLockCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report-lock <remote>",
		Short: "Report lockfile provenance to a remote",
		Long: `Report the current epack.lock.yaml to a remote without pushing a pack.

This command is intended for CI bootstrap and refresh flows. It sends the raw
lockfile, a SHA-256 hash, a normalized component summary, and runtime context
from the runner environment.

Examples:
  epack remote report-lock locktivity --reason bootstrap
  epack remote report-lock locktivity --reason refresh --env staging
  epack remote report-lock locktivity --reason frozen_check --outcome failure --failure-code lock_config_mismatch`,
		Args: cobra.ExactArgs(1),
		RunE: runReportLock,
	}

	cmd.Flags().StringVar(&reportLockEnv, "env", "", "environment to use (applies config from environments.<env>)")
	cmd.Flags().StringVar(&reportLockWorkspace, "workspace", "", "override target workspace")
	cmd.Flags().StringVar(&reportLockReason, "reason", lockprovenance.TriggerFrozenCheck, "report reason: bootstrap, refresh, or frozen_check")
	cmd.Flags().StringVar(&reportLockOutcome, "outcome", lockprovenance.OutcomeSuccess, "report outcome: success or failure")
	cmd.Flags().StringVar(&reportLockFailureCode, "failure-code", "", "stable failure code for failed reports")
	cmd.Flags().StringVar(&reportLockFailureMessage, "failure-message", "", "human-readable failure message for failed reports")
	reportLockInsecureAllowUnpinned = componenttypes.InsecureAllowUnpinnedFromEnv()
	cmd.Flags().BoolVar(&reportLockInsecureAllowUnpinned, "insecure-allow-unpinned", reportLockInsecureAllowUnpinned,
		"allow using adapters not pinned in lockfile (NOT RECOMMENDED)")

	return cmd
}

func runReportLock(cmd *cobra.Command, args []string) error {
	remoteName := args[0]
	out := outputWriter()
	ctx := cmdContext(cmd)

	projectRoot, cfg, remoteCfg, err := loadReportLockConfig(remoteName, reportLockEnv)
	if err != nil {
		return exitError("report-lock failed: %v", err)
	}
	if err := validateReportLockFlags(os.Stderr, remoteName, remoteCfg); err != nil {
		return exitError("report-lock failed: %v", err)
	}

	exec, caps, err := remote.PrepareAdapterExecutor(ctx, projectRoot, remoteName, cfg, remoteCfg, remote.AdapterExecutorOptions{
		Stderr: os.Stderr,
		Verification: remote.VerificationOptions{
			Unsafe: remote.VerificationUnsafeOverrides{
				AllowUnverifiedSource: reportLockInsecureAllowUnpinned,
			},
		},
	})
	if err != nil {
		return exitError("report-lock failed: %v", err)
	}
	defer exec.Close()

	if !caps.SupportsLockReport() {
		return exitError("report-lock failed: adapter does not support lock reports")
	}

	provenance, err := lockprovenance.Build(lockprovenance.Options{
		ProjectRoot:    projectRoot,
		TriggerKind:    reportLockReason,
		Outcome:        reportLockOutcome,
		FailureCode:    reportLockFailureCode,
		FailureMessage: reportLockFailureMessage,
	})
	if err != nil {
		return exitError("report-lock failed: %v", err)
	}

	resp, err := exec.ReportLock(ctx, &remote.LockReportRequest{
		Remote:         remoteName,
		Target:         buildReportLockTarget(remoteCfg),
		LockProvenance: *provenance,
	})
	if err != nil {
		return exitError("report-lock failed: %v", err)
	}

	if out.IsJSON() {
		return out.JSON(map[string]interface{}{
			"reported":        true,
			"remote":          remoteName,
			"status":          resp.Status,
			"outcome":         resp.Outcome,
			"lockfile_sha256": resp.LockfileSHA256,
			"revision_id":     resp.RevisionID,
		})
	}

	p := out.Palette()
	out.Print("%s Reported lockfile to %s\n", p.Green("✓"), p.Bold(remoteName))
	if resp.LockfileSHA256 != "" {
		out.Print("  SHA-256: %s\n", resp.LockfileSHA256)
	}
	if resp.Status != "" {
		out.Print("  Status:  %s\n", resp.Status)
	}
	return nil
}

func loadReportLockConfig(remoteName, envName string) (string, *config.JobConfig, *config.RemoteConfig, error) {
	projectRoot, err := project.FindRoot("")
	if err != nil {
		return "", nil, nil, err
	}
	cfg, err := config.Load(filepath.Join(projectRoot, project.ConfigFileName))
	if err != nil {
		return "", nil, nil, err
	}
	remoteCfg, err := remote.ResolveRemoteConfig(cfg, remoteName, envName)
	if err != nil {
		return "", nil, nil, err
	}
	return projectRoot, cfg, remoteCfg, nil
}

func buildReportLockTarget(remoteCfg *config.RemoteConfig) remote.TargetConfig {
	target := remote.TargetConfig{
		Workspace:   remoteCfg.Target.Workspace,
		Environment: remoteCfg.Target.Environment,
	}
	if reportLockWorkspace != "" {
		target.Workspace = reportLockWorkspace
	}
	return target
}

func validateReportLockFlags(stderr io.Writer, remoteName string, remoteCfg *config.RemoteConfig) error {
	hasUnsafeOverrides := reportLockInsecureAllowUnpinned
	attrs := map[string]string{}
	if reportLockInsecureAllowUnpinned {
		attrs["insecure_allow_unpinned"] = "true"
	}

	state, err := inspectRemoteInsecureState(remoteCfg)
	if err != nil {
		return err
	}
	warnRemoteCustomEndpoints(stderr, state.override)
	if state.override.Active() {
		hasUnsafeOverrides = true
		mergeAuditAttrs(attrs, state.attrs)
	}

	if err := securitypolicy.EnforceStrictProduction("report_lock_cli", hasUnsafeOverrides); err != nil {
		return err
	}
	if hasUnsafeOverrides {
		securityaudit.Emit(securityaudit.Event{
			Type:        securityaudit.EventInsecureBypass,
			Component:   "remote",
			Name:        remoteName,
			Description: "report-lock command running with insecure execution override",
			Attrs:       attrs,
		})
	}
	return nil
}
