//go:build components

package cmd

import (
	"os"

	"github.com/locktivity/epack/internal/updatenotice"
	"github.com/locktivity/epack/internal/version"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// updateCheck is the check started for the running command, if any.
var updateCheck *updatenotice.Check

// updateCheckOptions are what a check starts with; tests replace them.
var updateCheckOptions = func() updatenotice.Options {
	return updatenotice.Options{
		Version:  version.Version,
		Terminal: term.IsTerminal(int(os.Stderr.Fd())),
	}
}

// startUpdateCheck begins the daily check for a newer epack while cmd runs.
func startUpdateCheck(cmd *cobra.Command) {
	if out.IsQuiet() || !notifiesUpdates(cmd) {
		return
	}
	opts := updateCheckOptions()
	opts.CI = out.IsCI()
	updateCheck = updatenotice.Start(cmd.Context(), opts)
}

func finishUpdateCheck() {
	if line := updateCheck.Wait(); line != "" {
		outputWriter().Notice("%s\n", line)
	}
	updateCheck = nil
}

// notifiesUpdates is false for the quickstart bare epack prints, help,
// version, and completion, and for hooks and context, which generated
// runners call.
func notifiesUpdates(cmd *cobra.Command) bool {
	if !cmd.HasParent() {
		return false
	}
	switch cmd.Name() {
	case "help", "version", "completion", cobra.ShellCompRequestCmd:
		return false
	}
	top := cmd
	for top.Parent().HasParent() {
		top = top.Parent()
	}
	switch top.Name() {
	case "hooks", "context":
		return false
	}
	return true
}
