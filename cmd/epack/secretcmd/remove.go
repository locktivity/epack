//go:build components

package secretcmd

import (
	"strings"

	"github.com/locktivity/epack/internal/cmdutil"
	"github.com/locktivity/epack/internal/secrets"
	"github.com/spf13/cobra"
)

func newRemoveCommand() *cobra.Command {
	var scopeKey string
	cmd := &cobra.Command{
		Use:     "remove <NAME>",
		Aliases: []string{"rm"},
		Short:   "Erase one stored secret",
		Long: `Erase one value from your keychain and forget its approval.

--scope names another configuration, as 'epack secret list --all' prints
it, for cleanup after a pipeline is gone.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRemove(cmd, args[0], scopeKey)
		},
	}
	cmd.Flags().StringVar(&scopeKey, "scope", "", "the configuration to erase from, as remote:configuration")
	return cmd
}

func runRemove(cmd *cobra.Command, name, scopeKey string) error {
	if err := secrets.ValidateName(name); err != nil {
		return userError(err.Error(), "")
	}
	if scopeKey != "" {
		remote, configuration, ok := strings.Cut(scopeKey, ":")
		if !ok || remote == "" || configuration == "" {
			return userError("--scope must be remote:configuration", "Find it with epack secret list --all")
		}
		out := newOutput(cmd)
		paths, err := newPaths()
		if err != nil {
			return err
		}
		service := &secrets.Service{Paths: paths, Store: newStore()}
		scope := secrets.Scope{Remote: remote, Configuration: configuration}
		if err := service.Remove(scope, name, !out.IsCI() && stderrIsTerminal()); err != nil {
			return cmdutil.HandleError(err)
		}
		out.Print("Removed %s from your keychain for %s.\n", name, scope)
		return nil
	}
	s, err := open(cmd, false)
	if err != nil {
		return err
	}
	if err := s.service.Remove(s.scope, name, s.interactive); err != nil {
		return cmdutil.HandleError(err)
	}
	s.out.Print("Removed %s from your keychain for %s.\n", name, s.scope)
	return nil
}
