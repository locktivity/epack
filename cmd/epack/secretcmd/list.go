//go:build components

package secretcmd

import (
	"github.com/locktivity/epack/internal/cmdutil"
	"github.com/locktivity/epack/internal/secrets"
	"github.com/spf13/cobra"
)

func newListCommand() *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Show the secrets stored for this configuration",
		Long: `Show each stored secret's name, readers, when it was stored, and whether it
is approved for the configuration as it is now. Values are never shown.

--all lists every configuration on this machine with stored secrets, for
cleanup after a pipeline is gone.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runList(cmd, all)
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "list every configuration on this machine")
	return cmd
}

func runList(cmd *cobra.Command, all bool) error {
	if all {
		return listAll(cmd)
	}
	s, err := open(cmd, true)
	if err != nil {
		return err
	}
	entries, err := s.service.List(s.scope, s.conf)
	if err != nil {
		return cmdutil.HandleError(err)
	}
	if s.out.IsJSON() {
		return s.out.JSON(map[string]any{"scope": s.scope.Key(), "configuration": s.scope.Label, "remote": s.scope.Remote, "secrets": entries})
	}
	if len(entries) == 0 {
		s.out.Print("No secrets stored for %s.\n", s.scope)
		return nil
	}
	s.out.Print("Secrets for %s, in your keychain:\n", s.scope)
	for _, entry := range entries {
		s.out.Print("  %-24s read by %-20s since %s   %s\n", entry.Name, readerNames(entry.Readers), sinceDate(entry.StoredAt), approvalLabel(entry))
	}
	return nil
}

func approvalLabel(entry secrets.Entry) string {
	switch {
	case entry.NeedsApproval:
		return "needs approval: " + entry.Reason
	case entry.ApprovedRevision > 0:
		return "approved at revision " + itoa(entry.ApprovedRevision)
	default:
		return "approved"
	}
}

func listAll(cmd *cobra.Command) error {
	out := newOutput(cmd)
	paths, err := newPaths()
	if err != nil {
		return err
	}
	service := &secrets.Service{Paths: paths, Store: newStore()}
	scopes, err := service.ListAll()
	if err != nil {
		return cmdutil.HandleError(err)
	}
	if out.IsJSON() {
		return out.JSON(map[string]any{"scopes": scopes})
	}
	if len(scopes) == 0 {
		out.Print("No secrets stored on this machine.\n")
		return nil
	}
	for _, entry := range scopes {
		out.Print("%s (%s)\n", entry.Scope, entry.Scope.Key())
		for _, name := range entry.Names {
			out.Print("  %s\n", name)
		}
	}
	return nil
}
