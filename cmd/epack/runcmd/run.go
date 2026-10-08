//go:build components

// Package runcmd implements 'epack run': fetch a configuration from a remote
// when asked, then install, collect, run the tools, sign, and push.
package runcmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/locktivity/epack/cmd/epack/remotecmd"
	epackerrors "github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/broker"
	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/cmdutil"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/exitcode"
	"github.com/locktivity/epack/internal/project"
	"github.com/locktivity/epack/internal/redact"
	"github.com/locktivity/epack/internal/runflow"
	"github.com/locktivity/epack/internal/trustedpublishers"
	"github.com/locktivity/epack/sign"
	"github.com/spf13/cobra"
)

var (
	runRemote                string
	runOutput                string
	runKey                   string
	runBrowser               bool
	runOIDCToken             string
	runYes                   bool
	runForce                 bool
	runTrustPublishers       []string
	runCheck                 bool
	runInsecureAllowUnpinned bool
)

// NewCommand returns the run command (epack run).
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run [<name>]",
		Short: "Collect, sign, and send a pack in one command",
		Long: `Run the workflow a project describes, start to finish.

With a configuration name, the configuration is fetched from the remote you
last signed in to (or --remote) into a folder named after it, refreshed when
the folder exists, and the run happens there. Without a name, the run uses the
project in the current directory.

The stages, in order:
  1. Install the locked collectors, tools, and remote adapters
  2. Run the pre-collect hook
  3. Collect evidence into a pack; nothing unpinned runs
  4. Run the post-collect hook
  5. Run each configured tool on the pack
  6. Sign the pack; keyless by default, which opens your browser outside CI
  7. Push the pack to the remote

When a stage fails, the failure is reported to the remote with a stable code
so the run shows up there as well.

Examples:
  epack run northwind-production
  epack run northwind-production --remote locktivity
  epack run                                 # inside a project
  epack run --yes                           # in CI
  epack run --check                         # verify sign-in, lock, secrets, and publishers; collect nothing`,
		Args: cobra.MaximumNArgs(1),
		RunE: runRun,
	}

	cmd.Flags().StringVar(&runRemote, "remote", "", "with a name, the remote to fetch it from (default: the last one you signed in to); otherwise the remote to push to (default: the only one configured)")
	cmd.Flags().StringVarP(&runOutput, "output", "o", "", "pack file to build (default: evidence.epack in the project)")
	cmd.Flags().StringVar(&runKey, "key", "", "sign with a private key (PEM) instead of keyless signing")
	cmd.Flags().BoolVar(&runBrowser, "browser", false, "sign in your browser even when this machine has a key from 'epack key create'")
	cmd.Flags().StringVar(&runOIDCToken, "oidc-token", "", "OIDC token for keyless signing (or EPACK_OIDC_TOKEN env)")
	cmd.Flags().BoolVarP(&runYes, "yes", "y", false, "skip prompts")
	cmd.Flags().BoolVar(&runForce, "force", false, "when fetching, replace files you have edited")
	cmd.Flags().BoolVar(&runCheck, "check", false,
		"sign in, verify the lock, secrets, credentials, and publishers, report the result, and collect nothing (or set EPACK_CHECK=1)")
	cmd.Flags().StringArrayVar(&runTrustPublishers, "trust-publisher", nil,
		"trust a publisher (GitHub owner) for this run only; EPACK_TRUSTED_PUBLISHERS does the same in a job (repeatable)")
	runInsecureAllowUnpinned = componenttypes.InsecureAllowUnpinnedFromEnv()
	cmd.Flags().BoolVar(&runInsecureAllowUnpinned, "insecure-allow-unpinned", runInsecureAllowUnpinned,
		"allow components and adapters not pinned in lockfile (NOT RECOMMENDED)")

	return cmd
}

func runRun(cmd *cobra.Command, args []string) error {
	out := cmdutil.GetOutput(cmd)
	ctx := cmd.Context()
	ui := newStageUI(out)

	// The key a run signs with is also the key it signs in to the credential broker with.
	if runKey != "" {
		if err := os.Setenv(broker.SigningKeyEnvVar, runKey); err != nil {
			return err
		}
	}

	workDir, err := locateProject(ctx, out, ui, args)
	if err != nil {
		return err
	}

	pushRemote := runRemote
	if len(args) > 0 {
		pushRemote = ""
	}

	if runCheck || checkRequestedByEnv() {
		return runCheckOnly(ctx, out, ui, workDir, pushRemote)
	}

	signing, err := resolveRunKey(ctx, out, ui, workDir, pushRemote)
	if err != nil {
		ui.fail()
		return cmdutil.HandleError(err)
	}

	startedAt := time.Now()
	result, err := runflow.Run(ctx, runflow.Options{
		WorkDir:         workDir,
		Remote:          pushRemote,
		PackPath:        packPath(workDir),
		AllowUnpinned:   runInsecureAllowUnpinned,
		NonInteractive:  runYes,
		TrustPublishers: runTrustPublishers,
		PromptTrustPublisher: func(req trustedpublishers.Requirement) bool {
			return ui.promptTrustPublisher(req, !runYes)
		},
		Sign:             signOptions(signing.keyPath),
		Unsigned:         signing.unsigned,
		Stdout:           os.Stdout,
		Stderr:           os.Stderr,
		OnStage:          ui.onStage,
		OnStep:           ui.onStep,
		OnNote:           ui.onNote,
		OnCollectorEvent: ui.onCollectorEvent,
		OnUploadProgress: ui.onProgress,
		PromptInstallAdapter: func(remoteName, adapterName string) bool {
			return ui.promptInstallAdapter(remoteName, adapterName, !runYes)
		},
	})
	if err != nil {
		ui.fail()
		printCollectors(out, result)
		if result != nil && result.FailureReported {
			out.Error("Reported the failure to %s", result.Remote)
		}
		return cmdutil.HandleError(err)
	}
	printCollectors(out, result)
	return printRunResult(out, result, time.Since(startedAt))
}

// A GitLab pipeline run by hand can set EPACK_CHECK=1 in the run form, so
// the committed job checks itself without a script change.
func checkRequestedByEnv() bool {
	value := strings.TrimSpace(os.Getenv("EPACK_CHECK"))
	return value == "1" || strings.EqualFold(value, "true")
}

func runCheckOnly(ctx context.Context, out *output.Writer, ui *stageUI, workDir, pushRemote string) error {
	keyPath, _ := localRunKey(workDir, pushRemote)
	result, err := runflow.Check(ctx, runflow.Options{
		WorkDir:         workDir,
		Remote:          pushRemote,
		AllowUnpinned:   runInsecureAllowUnpinned,
		NonInteractive:  runYes,
		TrustPublishers: runTrustPublishers,
		Sign:            signOptions(keyPath),
		Stdout:          os.Stdout,
		Stderr:          os.Stderr,
		OnStep:          ui.onStep,
		PromptInstallAdapter: func(remoteName, adapterName string) bool {
			return ui.promptInstallAdapter(remoteName, adapterName, !runYes)
		},
		PromptTrustPublisher: func(req trustedpublishers.Requirement) bool {
			return ui.promptTrustPublisher(req, !runYes)
		},
	})
	if err != nil {
		ui.fail()
		return cmdutil.HandleError(err)
	}
	ui.stopSpinner()
	printCheckResult(out, result)
	if !result.OK() {
		return &epackerrors.Error{
			Code:    epackerrors.InvalidInput,
			Exit:    exitcode.General,
			Message: fmt.Sprintf("the run would be missing %d %s", len(result.Findings), plural(len(result.Findings), "thing", "things")),
			Hint:    "Fix the lines above, then run the check again",
		}
	}
	return nil
}

func printCheckResult(out *output.Writer, result *runflow.CheckResult) {
	if out.IsJSON() {
		payload := map[string]interface{}{
			"ok":                 result.OK(),
			"remote":             result.Remote,
			"signed_in_as":       result.SignedInAs,
			"lock_present":       result.LockPresent,
			"lock_current":       result.LockCurrent,
			"env_present":        result.EnvPresent,
			"env_total":          result.EnvTotal,
			"env_missing":        result.EnvMissing,
			"env_covered":        result.EnvCovered,
			"signing":            result.Signing,
			"publishers_trusted": result.PublishersTrusted,
			"findings":           result.Findings,
			"reported":           result.Reported,
		}
		if page := remotecmd.PipelinePage(result.PipelineURL); page != "" {
			payload["pipeline_url"] = page
		}
		_ = out.JSON(payload)
		return
	}
	p := out.Palette()
	if result.OK() {
		out.Print("\n%s The run has everything it needs.\n", p.Green("✓"))
	} else {
		out.Print("\n%s The run would be missing %d %s.\n", p.Red("✗"), len(result.Findings), plural(len(result.Findings), "thing", "things"))
	}
	if result.Remote != "" {
		if result.SignedInAs != "" {
			out.Print("  Sign-in:     %s as %s\n", result.Remote, output.Printable(result.SignedInAs))
		} else {
			out.Print("  Sign-in:     %s\n", result.Remote)
		}
	}
	switch {
	case !result.LockPresent:
		out.Print("  Lock:        none yet\n")
	case result.LockCurrent:
		out.Print("  Lock:        current\n")
	default:
		out.Print("  Lock:        behind epack.yaml\n")
	}
	switch {
	case result.EnvTotal > 0 && len(result.EnvCovered) > 0:
		out.Print("  Variables:   %d of %d set; your sign-in covers %s\n", result.EnvPresent, result.EnvTotal, strings.Join(result.EnvCovered, ", "))
	case result.EnvTotal > 0:
		out.Print("  Variables:   %d of %d set\n", result.EnvPresent, result.EnvTotal)
	case len(result.EnvCovered) > 0:
		out.Print("  Variables:   none needed; your sign-in covers %s\n", strings.Join(result.EnvCovered, ", "))
	}
	if result.Signing != "" {
		out.Print("  Signing:     %s\n", output.Printable(result.Signing))
	}
	for _, c := range result.Credentials {
		if c.Resolved {
			out.Print("  Credentials: %s resolved\n", c.Component)
		} else {
			out.Print("  Credentials: %s %s\n", c.Component, p.Red("failed"))
		}
	}
	if result.PublishersTrusted {
		out.Print("  Publishers:  trusted\n")
	}
	for _, finding := range result.Findings {
		out.Print("  %s %s\n", p.Red("✗"), finding)
	}
	if result.Reported {
		out.Print("\nReported to %s; the pipeline page shows this check.\n", result.Remote)
		remotecmd.PrintPipelinePage(out, result.PipelineURL)
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func locateProject(ctx context.Context, out *output.Writer, ui *stageUI, args []string) (string, error) {
	if len(args) == 0 {
		root, err := project.FindRoot("")
		if err != nil {
			return "", &epackerrors.Error{
				Code:    epackerrors.InvalidInput,
				Exit:    exitcode.General,
				Message: "not in an epack project",
				Hint:    "Run 'epack run <name>' to fetch a configuration, or cd into a project",
			}
		}
		return root, nil
	}

	target, err := remotecmd.ResolveConfigTarget(args[0], runRemote)
	if err != nil {
		return "", err
	}
	clone, err := remotecmd.CloneConfig(ctx, target, remotecmd.CloneOptions{
		Force:         runForce,
		AllowUnpinned: runInsecureAllowUnpinned,
		Step:          ui.onStep,
		PromptInstall: func(remoteName, adapterName string) bool {
			return ui.promptInstallAdapter(remoteName, adapterName, !runYes)
		},
	})
	if err != nil {
		ui.fail()
		return "", err
	}
	ui.fetched(clone)
	return clone.Dir, nil
}

func packPath(workDir string) string {
	if runOutput == "" {
		return ""
	}
	if filepath.IsAbs(runOutput) {
		return runOutput
	}
	return filepath.Join(workDir, runOutput)
}

func signOptions(keyPath string) sign.SignPackOptions {
	return sign.SignPackOptions{
		KeyPath:     keyPath,
		OIDCToken:   runOIDCToken,
		Interactive: !usingExplicitOIDCToken() && !hasAmbientGitHubActionsOIDC(),
	}
}

func usingExplicitOIDCToken() bool {
	return runOIDCToken != "" || strings.TrimSpace(os.Getenv("EPACK_OIDC_TOKEN")) != ""
}

func hasAmbientGitHubActionsOIDC() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("GITHUB_ACTIONS")), "true") &&
		strings.TrimSpace(os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")) != "" &&
		strings.TrimSpace(os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")) != ""
}

func printCollectors(out *output.Writer, result *runflow.Result) {
	if result == nil || result.Collect == nil || out.IsJSON() {
		return
	}
	for _, r := range result.Collect.CollectorResults {
		if r.Success {
			out.Print("  collected %s\n", r.Collector)
		} else {
			out.Print("  FAILED %s: %s\n", r.Collector, output.Printable(redact.Error(fmt.Sprint(r.Error))))
		}
	}
}

func printRunResult(out *output.Writer, result *runflow.Result, duration time.Duration) error {
	if out.IsJSON() {
		payload := map[string]interface{}{
			"pack":        result.PackPath,
			"remote":      result.Remote,
			"tools":       result.Tools,
			"signed":      result.Signed,
			"pushed":      result.Push != nil,
			"duration_ms": duration.Milliseconds(),
		}
		if result.Collect != nil {
			payload["collectors"] = len(result.Collect.CollectorResults)
		}
		if result.Push != nil {
			payload["release_id"] = result.Push.Release.ReleaseID
			payload["links"] = result.Push.Links
		}
		return out.JSON(payload)
	}

	p := out.Palette()
	out.Print("\n%s Done in %s\n", p.Green("✓"), formatDuration(duration))
	out.Print("  Pack:    %s\n", result.PackPath)
	if len(result.Tools) > 0 {
		out.Print("  Tools:   %s\n", strings.Join(result.Tools, ", "))
	}
	if result.Signed {
		out.Print("  Signed:  yes\n")
	} else {
		out.Print("  Signed:  no\n")
	}
	switch {
	case result.Push != nil:
		out.Print("  Release: %s\n", output.Printable(result.Push.Release.ReleaseID))
		if view, ok := result.Push.Links["view"]; ok {
			out.Print("\nView: %s\n", output.Printable(view))
		}
	case result.Remote == "":
		out.Print("\nNo remote is configured, so the pack stayed local.\n")
	}
	if result.LockedNow {
		out.Print("\nA lockfile was created. Commit %s if this folder lives in a repository.\n", lockfile.FileName)
	}
	return nil
}

func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
}
