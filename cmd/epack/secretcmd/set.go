//go:build components

package secretcmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/cmdutil"
	"github.com/locktivity/epack/internal/remoteconfig"
	"github.com/locktivity/epack/internal/secrets"
	"github.com/spf13/cobra"
)

func newSetCommand() *cobra.Command {
	var (
		fromStdin bool
		fromFile  string
		unlisted  bool
		yes       bool
	)
	cmd := &cobra.Command{
		Use:   "set <NAME>",
		Short: "Store one value in your keychain for this configuration",
		Long: `Store one value and approve it for the components that read it now.
Nothing else's approval changes.

In a terminal the value is read hidden at a prompt. --stdin reads it to the
end of input, for a pipe; --from-file reads a file, for a key or a JSON
credential. Exactly one trailing newline is stripped. A value given as an
argument is refused, since it would land in shell history.

Examples:
  epack secret set AZURE_CLIENT_SECRET
  epack secret set OKTA_PRIVATE_KEY --from-file ~/Downloads/okta.pem
  op read op://Vault/item/field | epack secret set SENTRY_AUTH_TOKEN --stdin`,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) > 1 {
				return userError("secret values are not accepted as arguments", "Use --stdin or --from-file, or paste the value at the prompt")
			}
			if len(args) != 1 {
				return userError("a variable name is required", "epack secret set <NAME>")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSet(cmd, args[0], fromStdin, fromFile, unlisted, yes)
		},
	}
	cmd.Flags().BoolVar(&fromStdin, "stdin", false, "read the value from standard input, to the end")
	cmd.Flags().StringVar(&fromFile, "from-file", "", "read the value from a file")
	cmd.Flags().BoolVar(&unlisted, "unlisted", false, "store a name no component in the configuration lists")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "never prompt")
	return cmd
}

func runSet(cmd *cobra.Command, name string, fromStdin bool, fromFile string, unlisted, yes bool) error {
	if err := secrets.ValidateName(name); err != nil {
		return userError(err.Error(), "")
	}
	s, err := open(cmd, yes)
	if err != nil {
		return err
	}
	value, err := s.readValue(name, fromStdin, fromFile)
	if err != nil {
		return err
	}
	readers, err := s.service.Set(s.scope, name, value, s.conf, s.interactive, unlisted)
	var notListed *secrets.UnlistedError
	if errors.As(err, &notListed) {
		return s.notListedError(notListed)
	}
	if err != nil {
		return cmdutil.HandleError(err)
	}
	if len(readers) == 0 {
		s.out.Print("Kept in your keychain for %s. No component reads it yet.\n", s.scope)
		return nil
	}
	s.out.Print("Kept in your keychain for %s and approved for %s.\n", s.scope, readerNames(readers))
	s.printStillNeeded()
	return nil
}

func (s *session) notListedError(err *secrets.UnlistedError) error {
	state, _ := remoteconfig.LoadState(s.workDir)
	if state == nil || state.Name == "" || state.Remote == "" {
		return cmdutil.HandleError(err)
	}
	held := output.Printable(state.Name)
	if state.Revision > 0 {
		held = fmt.Sprintf("revision %d of %s", state.Revision, held)
	}
	return userError(
		fmt.Sprintf("no component in %s lists %s", held, err.Name),
		fmt.Sprintf("This folder may be behind the current revision. Run 'epack remote clone' %s to update it, then run this command again. If the current revision does not list %s either, pass --unlisted to store it anyway", s.cloneLocation(), err.Name),
	)
}

// cloneLocation is where to run a bare 'epack remote clone', which reads the
// pull record from the working directory only.
func (s *session) cloneLocation() string {
	if cwd, err := os.Getwd(); err == nil && cwd == s.workDir {
		return "in this folder"
	}
	return "in " + s.workDir
}

func (s *session) readValue(name string, fromStdin bool, fromFile string) (string, error) {
	switch {
	case fromFile != "":
		value, err := secrets.ReadValue(fromFile, nil)
		if err != nil {
			return "", fmt.Errorf("reading %s: %w", fromFile, err)
		}
		return value, nil
	case fromStdin:
		if stdinIsTerminal() {
			return "", userError("refusing to read a value from the terminal with --stdin", "Paste it at the prompt without --stdin, or pipe it in")
		}
		return secrets.ReadValue("", readAllStdin)
	case stdinIsTerminal() && s.interactive:
		readers := secrets.ReadersOf(s.conf.Config, name)
		label := name
		if len(readers) > 0 {
			label += ", read by " + readersLabel(readers)
		}
		return s.promptHidden(label + " (hidden): ")
	default:
		return "", userError("no terminal to read the value from", "Pass --stdin to read it from a pipe, or --from-file <path>")
	}
}
