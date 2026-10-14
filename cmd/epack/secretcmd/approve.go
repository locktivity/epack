//go:build components

package secretcmd

import (
	"github.com/locktivity/epack/internal/cmdutil"
	"github.com/spf13/cobra"
)

func newApproveCommand() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "approve [<NAME>]",
		Short: "Review what changed for a stored secret and approve it",
		Long: `Show what changed for the components that read a stored secret since it
was approved, say what that means, and record the approval on a yes. Without
a name, every secret that needs approval is shown in turn.

--yes approves without asking and is meant for someone who has read the
check's findings.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runApprove(cmd, args, yes)
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "approve without asking")
	return cmd
}

func runApprove(cmd *cobra.Command, args []string, yes bool) error {
	s, err := open(cmd, yes)
	if err != nil {
		return err
	}
	pending, err := s.service.Pending(s.scope, s.conf, args, s.interactive)
	if err != nil {
		return cmdutil.HandleError(err)
	}
	if len(pending) == 0 {
		if len(args) == 1 {
			s.out.Print("%s needs no approval for %s.\n", args[0], s.scope)
		} else {
			s.out.Print("Nothing needs approval for %s.\n", s.scope)
		}
		return nil
	}
	approved := 0
	for i, item := range pending {
		if i > 0 {
			s.out.Print("\n")
		}
		printChanges(s.out, item, s.scope)
		if !yes && !s.confirm(approveQuestion(item.Name, s.scope)) {
			s.out.Print("Left unapproved; the run will not use it.\n")
			continue
		}
		if err := s.service.Approve(s.scope, item.Name, s.conf, s.interactive); err != nil {
			return cmdutil.HandleError(err)
		}
		s.out.Print("Approved.\n")
		approved++
	}
	if approved < len(pending) {
		return userError(itoa(len(pending)-approved)+" left unapproved", "Run epack secret approve again when you are ready")
	}
	return nil
}
