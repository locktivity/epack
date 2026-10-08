//go:build components

package remotecmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/project"
	"github.com/locktivity/epack/internal/remote"
	"github.com/locktivity/epack/internal/remoteconfig"
	"github.com/locktivity/epack/internal/userconfig"
	"github.com/spf13/cobra"
)

var (
	cloneRemote                string
	cloneForce                 bool
	cloneInsecureAllowUnpinned bool
)

func newCloneCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "clone <name> [dir]",
		Short: "Fetch a configuration from a remote into a folder",
		Long: `Fetch a named configuration from a remote and write it into a folder.

The remote is the one you last signed in to, or --remote. It hands over the
files a project is made of: epack.yaml, the hooks, any profile files, and the
lock when the remote has one. The folder defaults to the configuration's name.

Run it again to pick up a newer revision. Files you have edited are left
alone unless you pass --force, and hook scripts are never overwritten.

Examples:
  epack remote clone northwind-production
  epack remote clone northwind-production ./compliance
  epack remote clone northwind-production --remote locktivity
  epack remote clone northwind-production --force`,
		Args: cobra.RangeArgs(1, 2),
		RunE: runClone,
	}

	cmd.Flags().StringVar(&cloneRemote, "remote", "", "remote to fetch from (default: the last one you signed in to)")
	cmd.Flags().BoolVar(&cloneForce, "force", false, "replace files you have edited and write into folders no clone created")
	cloneInsecureAllowUnpinned = componenttypes.InsecureAllowUnpinnedFromEnv()
	cmd.Flags().BoolVar(&cloneInsecureAllowUnpinned, "insecure-allow-unpinned", cloneInsecureAllowUnpinned,
		"allow using adapters not pinned in lockfile (NOT RECOMMENDED)")

	return cmd
}

func runClone(cmd *cobra.Command, args []string) error {
	target, err := ResolveConfigTarget(args[0], cloneRemote)
	if err != nil {
		return err
	}
	dir := ""
	if len(args) > 1 {
		dir = args[1]
	}
	out := getOutput(cmd)
	ctx := cmdContext(cmd)
	ui := newCommandUI(out, "", "", "Clone failed")

	result, err := CloneConfig(ctx, target, CloneOptions{
		Dir:           dir,
		Force:         cloneForce,
		AllowUnpinned: cloneInsecureAllowUnpinned,
		Step:          ui.onStep,
		PromptInstall: func(remoteName, adapterName string) bool {
			return ui.promptInstallAdapter(remoteName, adapterName, true)
		},
	})
	if err != nil {
		ui.fail()
		return err
	}
	return printCloneResult(out, target, result)
}

// ConfigTarget names a configuration on a remote.
type ConfigTarget struct {
	Remote string
	Name   string
}

// ResolveConfigTarget pairs a configuration name with the remote it lives
// on: the --remote flag, else the remote the last login recorded, else the
// only remote the current project names.
func ResolveConfigTarget(name, remoteName string) (ConfigTarget, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return ConfigTarget{}, exitError("a configuration name is needed, as in northwind-production")
	}
	if before, after, found := strings.Cut(name, ":"); found {
		if before != "" && after != "" {
			return ConfigTarget{}, exitError("the remote is chosen with --remote: epack run %s --remote %s", after, before)
		}
		return ConfigTarget{}, exitError("the remote is chosen with --remote, as in epack run northwind-production --remote locktivity")
	}
	if err := remoteconfig.ValidateFolderName(name); err != nil {
		return ConfigTarget{}, exitError("%v", err)
	}
	if remoteName == "" {
		var err error
		remoteName, err = defaultRemote()
		if err != nil {
			return ConfigTarget{}, err
		}
	}
	if err := config.ValidateRemoteName(remoteName); err != nil {
		return ConfigTarget{}, exitError("%v", err)
	}
	return ConfigTarget{Remote: remoteName, Name: name}, nil
}

func defaultRemote() (string, error) {
	name, err := userconfig.DefaultRemote()
	if err != nil {
		return "", exitError("reading the default remote: %v", err)
	}
	if name != "" {
		return name, nil
	}
	if projectRoot, err := project.FindRoot(""); err == nil {
		cfg, err := config.Load(filepath.Join(projectRoot, project.ConfigFileName))
		if err == nil && len(cfg.Remotes) == 1 {
			for remoteName := range cfg.Remotes {
				return remoteName, nil
			}
		}
	}
	return "", exitError("no remote chosen. Run 'epack remote login <remote>' once, or pass --remote")
}

// CloneOptions controls a clone.
type CloneOptions struct {
	Dir           string
	Force         bool
	AllowUnpinned bool
	Step          remote.StepCallback
	PromptInstall remote.PromptInstallFunc
}

// CloneResult is what a clone fetched and wrote, with what the written
// configuration will run. Changes is set when the folder held an earlier
// revision.
type CloneResult struct {
	*remoteconfig.Result
	Config  remote.ConfigPullResult
	Summary *remoteconfig.Summary
	Changes *remoteconfig.Changes
}

// CloneConfig fetches the configuration from the remote and writes it into
// the folder, creating or refreshing it.
func CloneConfig(ctx context.Context, target ConfigTarget, opts CloneOptions) (*CloneResult, error) {
	prepared, err := PrepareRemote(ctx, target.Remote, PrepareOptions{
		AllowUnpinned: opts.AllowUnpinned,
		Step:          opts.Step,
		PromptInstall: opts.PromptInstall,
		Stderr:        os.Stderr,
	})
	if err != nil {
		return nil, exitError("clone failed: %v", err)
	}
	defer prepared.Close()

	if !prepared.Caps.SupportsConfigPull() {
		return nil, exitError("clone failed: the %s adapter cannot hand over configurations", target.Remote)
	}

	step := opts.Step
	if step == nil {
		step = func(string, bool) {}
	}
	step(fmt.Sprintf("Fetching %s from %s", target.Name, target.Remote), true)
	resp, err := prepared.Exec.ConfigPull(ctx, target.Remote, prepared.Target, target.Name)
	if err != nil {
		return nil, exitError("clone failed: %v", adapterMessage(err))
	}
	step("Fetched "+describeConfig(resp.Config), false)

	dir := opts.Dir
	if dir == "" {
		dir = target.Name
	}
	var before *remoteconfig.Summary
	if state, _ := remoteconfig.LoadState(dir); state != nil {
		before, _ = remoteconfig.Summarize(dir, nil)
	}
	if err := remote.ValidateFilesDir(prepared.Caps.FilesDir); err != nil {
		err = fmt.Errorf("the %s adapter declared a files folder epack cannot accept: %w", target.Remote, err)
		return nil, exitError("clone failed: %v", err)
	}
	result, err := remoteconfig.Write(resp.Config, target.Remote, remoteconfig.Options{Dir: dir, Force: opts.Force, FilesDir: prepared.Caps.FilesDir})
	if err != nil {
		var hidden *remoteconfig.HiddenPathError
		if errors.As(err, &hidden) && hidden.FilesDir == "" {
			return nil, outdatedAdapterError(target.Remote, prepared, hidden)
		}
		return nil, exitError("clone failed: %v", err)
	}
	summary, err := remoteconfig.Summarize(result.Dir, nil)
	if err != nil {
		return nil, exitError("the fetched configuration does not load: %v", err)
	}
	clone := &CloneResult{Result: result, Config: resp.Config, Summary: summary}
	if before != nil && !result.Current() {
		clone.Changes = remoteconfig.Diff(before, summary)
	}
	return clone, nil
}

// PrintFetched shows what a freshly written or updated configuration will
// run: everything on the first fetch, only the differences on a later one.
func PrintFetched(out *output.Writer, clone *CloneResult) {
	if out.IsQuiet() || out.IsJSON() || clone.Current() && !clone.Created {
		return
	}
	if clone.Changes != nil {
		printChanges(out, clone.Changes)
		return
	}
	printSummary(out, clone.Summary)
}

func printSummary(out *output.Writer, s *remoteconfig.Summary) {
	printComponents(out, "Collects with", s.Collectors)
	printComponents(out, "Tools", s.Tools)
	printComponents(out, "Sends to", s.Remotes)
	if len(s.Env) > 0 {
		out.Print("  %-14s %s\n", "Reads", envList(s.Env))
	}
	templates := []string{}
	for _, hook := range s.Hooks {
		if hook.Template {
			templates = append(templates, strings.TrimPrefix(hook.Path, ".epack/hooks/"))
		}
	}
	if len(templates) > 0 {
		out.Print("  %-14s %s %s\n", "Hooks", strings.Join(templates, ", "), pluralVerb(len(templates))+" the remote's template and will not run until you edit them")
	}
	if s.Locked {
		out.Print("  %-14s %s\n", "Lock", "provided by the remote")
	} else {
		out.Print("  %-14s %s\n", "Lock", "none yet; the first run locks and verifies the components")
	}
}

func printChanges(out *output.Writer, c *remoteconfig.Changes) {
	if c.Empty() {
		out.Print("  %-14s %s\n", "Changes", "none that affect what runs")
		return
	}
	if len(c.Added) > 0 {
		out.Print("  %-14s %s\n", "Added", strings.Join(remoteconfig.PublisherGroups(c.Added), "; "))
	}
	if len(c.Removed) > 0 {
		names := make([]string, 0, len(c.Removed))
		for _, component := range c.Removed {
			names = append(names, component.Name)
		}
		out.Print("  %-14s %s\n", "Removed", strings.Join(names, ", "))
	}
	for _, change := range c.Changed {
		out.Print("  %-14s %s to %s\n", "Changed", change.From, strings.TrimPrefix(change.To, change.Name+" "))
	}
	if len(c.NewEnv) > 0 {
		out.Print("  %-14s %s\n", "Now reads", envList(c.NewEnv))
	}
}

func printComponents(out *output.Writer, label string, components []remoteconfig.Component) {
	if len(components) == 0 {
		return
	}
	out.Print("  %-14s %s\n", label, strings.Join(remoteconfig.PublisherGroups(components), "; "))
}

func envList(vars []remoteconfig.EnvVar) string {
	parts := make([]string, 0, len(vars))
	for _, v := range vars {
		if v.Set {
			parts = append(parts, v.Name+" (set)")
		} else {
			parts = append(parts, v.Name)
		}
	}
	return strings.Join(parts, ", ")
}

func pluralVerb(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}

func describeConfig(cfg remote.ConfigPullResult) string {
	title := output.Printable(cfg.Title)
	if title == "" {
		title = output.Printable(cfg.Name)
	}
	if cfg.Revision > 0 {
		return title + " (revision " + itoa(cfg.Revision) + ")"
	}
	return title
}

func itoa(n int) string {
	return strconv.Itoa(n)
}

// adapterMessage renders an adapter's own message without the protocol
// prefix, and tells the person to sign in when that is what is missing.
func adapterMessage(err error) string {
	var adapterErr *remote.AdapterError
	if !errors.As(err, &adapterErr) {
		return err.Error()
	}
	if adapterErr.IsAuthRequired() {
		return adapterErr.Message + ". Run 'epack remote login " + adapterErr.AdapterName + "' first."
	}
	return adapterErr.Message
}

func printCloneResult(out *output.Writer, target ConfigTarget, result *CloneResult) error {
	relDir := result.Dir
	if cwd, err := os.Getwd(); err == nil {
		if rel, err := filepath.Rel(cwd, result.Dir); err == nil && !strings.HasPrefix(rel, "..") {
			relDir = rel
		}
	}

	if out.IsJSON() {
		return out.JSON(map[string]interface{}{
			"remote":   target.Remote,
			"name":     result.Config.Name,
			"title":    result.Config.Title,
			"dir":      result.Dir,
			"revision": result.Config.Revision,
			"created":  result.Created,
			"written":  result.Written,
			"kept":     result.Kept,
			"summary":  result.Summary,
			"changes":  result.Changes,
		})
	}

	p := out.Palette()
	switch {
	case result.Created:
		out.Print("\n%s Cloned %s into %s\n", p.Green("✓"), describeConfig(result.Config), p.Bold(relDir))
	case result.Current():
		out.Print("\n%s %s is already current in %s\n", p.Green("✓"), describeConfig(result.Config), p.Bold(relDir))
	default:
		out.Print("\n%s Updated %s to %s\n", p.Green("✓"), p.Bold(relDir), describeConfig(result.Config))
	}
	for _, path := range result.Written {
		out.Verbose("  wrote %s\n", path)
	}
	if !result.Current() {
		out.Print("  %d file(s) written\n", len(result.Written))
	}
	PrintFetched(out, result)
	out.Print("\n%s\n", p.Dim("Next:"))
	out.Print("%s  cd %s && epack run\n", p.Dim("  •"), relDir)
	return nil
}
