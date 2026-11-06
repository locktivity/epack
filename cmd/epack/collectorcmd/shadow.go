//go:build components

package collectorcmd

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/safefile"
	"github.com/locktivity/epack/internal/shadow"
	"github.com/spf13/cobra"
)

var (
	shadowConfigPath string
	shadowVersion    string
	shadowBinary     string
	shadowOutput     string
	shadowValues     string
	shadowNoValues   bool
	shadowTimeout    time.Duration
)

// shadowValuesShown is the most values the terminal shows for one field.
const shadowValuesShown = 3

// NewShadowCommand returns 'epack shadow'.
func NewShadowCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "shadow <collector>",
		Short: "Preview what a new collector version would change",
		Long: `Run a candidate version of a collector beside the locked one and show
what would change, before you upgrade.

Shadow runs the locked version, then the candidate, then the locked version
again, each with the collector's config and secrets from epack.yaml. A field
that also differs between the two locked runs, such as a timestamp, is
noise and is listed apart. The candidate is locked, installed, and verified
in a throwaway project, so your lockfile does not change and no pack is
built. A local build (--binary) runs with the collector's credentials but is
not pinned in your lockfile, so strict production mode refuses it, as it
refuses an unpinned binary in epack collect.

At a terminal, the report shows each changed field with a few of its
values, from the locked run to the candidate's. It shows none in CI or when
its output goes to a file or a pipe. The report file (-o) never holds
values from your account: fields are named by pattern, files by a name a
build file declares, errors by code, and call counts by range, so it is
safe to share. --values writes every changed value to a
file of its own, which stays on this machine.

Examples:
  epack shadow aws --version v0.7.0
  epack shadow aws --binary ./bin/epack-collector-aws
  epack shadow aws --version v0.7.0 --no-values -o shadow-aws.json`,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf(`missing collector name argument

Usage: epack shadow <collector> --version <release>
       epack shadow <collector> --binary <path>

Examples:
  epack shadow aws --version v0.7.0
  epack shadow aws --binary ./bin/epack-collector-aws`)
			}
			if len(args) > 1 {
				return fmt.Errorf("too many arguments: expected 1, got %d", len(args))
			}
			return nil
		},
		RunE: runShadow,
	}
	cmd.Flags().StringVarP(&shadowConfigPath, "config", "c", "epack.yaml", "path to epack config file")
	cmd.Flags().StringVar(&shadowVersion, "version", "", "release of the collector's source to run as the candidate")
	cmd.Flags().StringVar(&shadowBinary, "binary", "", "local collector binary to run as the candidate")
	cmd.Flags().StringVarP(&shadowOutput, "output", "o", "", "report file, which holds no values (default: shadow-<collector>-<version>.json)")
	cmd.Flags().StringVar(&shadowValues, "values", "", "also write every changed value to this file, which stays on this machine")
	cmd.Flags().BoolVar(&shadowNoValues, "no-values", false, "show no values in the terminal (values never show in CI or when output is piped)")
	cmd.Flags().DurationVar(&shadowTimeout, "timeout", time.Duration(limits.DefaultCollectorTimeout), "timeout for each run")
	return cmd
}

func runShadow(cmd *cobra.Command, args []string) error {
	out := getOutput(cmd)
	name := args[0]
	cfg, err := loadConfig(shadowConfigPath)
	if err != nil {
		return err
	}
	workDir, err := resolveWorkDirFromConfigPath(shadowConfigPath)
	if err != nil {
		return err
	}
	rep, preview, err := shadow.Run(cmd.Context(), cfg, shadow.Options{
		WorkDir:   workDir,
		Collector: name,
		Version:   shadowVersion,
		Binary:    shadowBinary,
		Timeout:   shadowTimeout,
		Stderr:    cmd.ErrOrStderr(),
	})
	if err != nil {
		return handleCollectorError(err)
	}

	reportPath := shadowOutput
	if reportPath == "" {
		reportPath = defaultShadowReportPath(name, shadowVersion)
	}
	if err := writeShadowJSON(reportPath, rep, false); err != nil {
		return err
	}
	if shadowValues != "" {
		if err := writeShadowJSON(shadowValues, preview, true); err != nil {
			return err
		}
	}
	if out.IsJSON() {
		return out.JSON(map[string]any{"report": rep, "report_path": reportPath})
	}
	printShadowReport(out, rep, preview, shadowShowsValues(out, shadowNoValues))
	out.Print("\nReport written to %s. It holds no values from your account.\n", reportPath)
	if shadowValues != "" {
		out.Print("Values written to %s. Keep it on this machine.\n", shadowValues)
	}
	return nil
}

// shadowShowsValues reports whether the terminal report shows values from
// the account. It shows them only at a terminal outside CI, since logs and
// pipes keep what they are given.
func shadowShowsValues(out *output.Writer, noValues bool) bool {
	return !noValues && out.IsTTY() && !out.IsCI()
}

func defaultShadowReportPath(collector, version string) string {
	if version == "" {
		version = "local"
	}
	return fmt.Sprintf("shadow-%s-%s.json", collector, strings.ReplaceAll(version, "/", "-"))
}

// writeShadowJSON writes v to path. The values file is private, since it
// holds values from the account.
func writeShadowJSON(path string, v any, private bool) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	write := safefile.WriteFile
	if private {
		write = safefile.WriteFilePrivate
	}
	return write(filepath.Dir(abs), filepath.Base(abs), append(data, '\n'))
}

func printShadowReport(out *output.Writer, rep *shadow.Report, preview *shadow.Preview, showValues bool) {
	out.Print("Shadow run of %s at %s: locked %s, candidate %s\n", rep.Collector, rep.Level, rep.Locked.Version, rep.Candidate.Version)
	runs := make([]string, len(rep.Locked.Runs))
	for i, r := range rep.Locked.Runs {
		runs[i] = fmt.Sprintf("run %d %s", i+1, outcomeText(r))
	}
	out.Print("  locked     %s\n", strings.Join(runs, ", "))
	out.Print("  candidate  %s\n", outcomeText(rep.Candidate.Outcome))

	if len(rep.Kinds) > 0 {
		out.Print("\nKinds\n")
		for _, k := range rep.Kinds {
			out.Print("  %-16s %s\n", k.Kind, kindText(k))
		}
	}
	if len(rep.Fields) > 0 {
		out.Print("\nFields\n")
		for _, f := range rep.Fields {
			line := fmt.Sprintf("  %-9s %s %s", f.Change, f.Kind, f.Pointer)
			if f.Level != "" {
				line += "   now " + f.Level + " level"
			}
			out.Print("%s\n", line)
			if showValues {
				printValues(out, preview, f)
			}
		}
	}
	if len(rep.Noise) > 0 {
		out.Print("\nNoise, left out because the two locked runs also differ\n")
		for _, n := range rep.Noise {
			if n.Pointer == "" {
				out.Print("  %s %s, the whole file\n", n.Kind, n.File)
				continue
			}
			out.Print("  %s %s\n", n.Kind, n.Pointer)
		}
	}
	if len(rep.Gaps) > 0 || len(rep.GapNoise) > 0 {
		out.Print("\nGaps\n")
		for _, g := range rep.Gaps {
			change := "new"
			if g.Change == "removed" {
				change = "gone"
			}
			out.Print("  %-4s %s at %s %s\n", change, g.Code, g.Kind, g.Pointer)
			if g.MissingPermission != "" {
				out.Print("       needs %s\n", g.MissingPermission)
			}
		}
		if len(rep.GapNoise) > 0 {
			out.Print("  Left out because the two locked runs also differ:\n")
			for _, g := range rep.GapNoise {
				out.Print("       %s at %s %s\n", g.Code, g.Kind, g.Pointer)
			}
		}
	}
	if len(rep.Operations) > 0 {
		out.Print("\nOperations\n")
		for _, o := range rep.Operations {
			line := fmt.Sprintf("  %-9s %s", operationText(o.Change), o.Name)
			if len(o.Codes) > 0 {
				line += " with " + strings.Join(o.Codes, ", ")
			}
			if o.Permission != "" {
				line += "   needs " + o.Permission
			}
			out.Print("%s\n", line)
		}
	}
	if rep.Calls != nil {
		out.Print("\nCalls: locked %s, candidate %s\n", rep.Calls.Locked, rep.Calls.Candidate)
	}
	printControls(out, rep, preview, showValues)
	if len(rep.Kinds) > 0 && len(rep.Fields) == 0 && len(rep.Gaps) == 0 && len(rep.Operations) == 0 {
		out.Print("\nNo field, gap, or call changes.\n")
	}
}

func printControls(out *output.Writer, rep *shadow.Report, preview *shadow.Preview, showValues bool) {
	if rep.ControlsSkipped != "" {
		out.Print("\nControls: not checked, since %s\n", rep.ControlsSkipped)
		return
	}
	out.Print("\nControls\n")
	if len(rep.Controls) == 0 {
		out.Print("  No control changes its result.\n")
	}
	for _, c := range rep.Controls {
		out.Print("  %s %s: %s -> %s\n", c.ID, c.Name, controlStatus(c.From), controlStatus(c.To))
		if !showValues {
			continue
		}
		for _, v := range preview.Controls {
			if v.ID == c.ID && (v.From != nil || v.To != nil) {
				out.Print("              read %s -> %s\n", anyText(v.From), anyText(v.To))
			}
		}
	}
	if len(rep.ControlNoise) > 0 {
		out.Print("  Left out because the two locked runs also differ: %s\n", strings.Join(rep.ControlNoise, ", "))
	}
}

// controlStatus names a validator status the way the app does.
func controlStatus(status string) string {
	switch status {
	case "pass":
		return "Met"
	case "fail":
		return "Needs attention"
	case "unknown":
		return "Not collected"
	case "manual":
		return "Manual"
	case "":
		return "(not in the profile)"
	}
	return status
}

func anyText(v any) string {
	if v == nil {
		return "(none)"
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(raw)
}

func printValues(out *output.Writer, preview *shadow.Preview, f shadow.FieldChange) {
	shown, more := 0, 0
	for _, v := range preview.Values {
		if v.Kind != f.Kind || v.Field != f.Pointer {
			continue
		}
		if shown == shadowValuesShown {
			more++
			continue
		}
		shown++
		out.Print("              %s: %s -> %s\n", v.Pointer, valueText(v.From), valueText(v.To))
	}
	if more > 0 {
		out.Print("              and %d more, in --values\n", more)
	}
}

func valueText(v string) string {
	if v == "" {
		return "(none)"
	}
	return v
}

func outcomeText(o shadow.Outcome) string {
	if o.Code != "" {
		return fmt.Sprintf("%s (%s)", o.Status, o.Code)
	}
	return o.Status
}

func kindText(k shadow.KindChange) string {
	schema := func(id string) string {
		if id == "" {
			return "its own file"
		}
		return id
	}
	switch k.Change {
	case "left out":
		return "not collected: collect leaves it out"
	case "added":
		return "new: " + schema(k.Candidate)
	case "removed":
		return "no longer written"
	case "schema changed":
		return schema(k.Locked) + " -> " + schema(k.Candidate)
	}
	return schema(k.Candidate) + ", unchanged"
}

func operationText(change string) string {
	switch change {
	case "added":
		return "new"
	case "removed":
		return "gone"
	}
	return change
}
