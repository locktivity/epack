//go:build components

package secretcmd

import (
	"strconv"
	"strings"

	"github.com/locktivity/epack/internal/cmdutil"
	"github.com/locktivity/epack/internal/secrets"
	"github.com/spf13/cobra"
)

func newSetupCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "setup",
		Short: "Walk through every missing and unapproved secret",
		Long: `Walk through the secrets this configuration needs: each one the keychain
lacks is asked for, hidden, and stored; each one that needs approval again is
shown with what changed and approved on a yes. Enter skips a value.

For a key or a JSON credential, skip it here and run
epack secret set NAME --from-file <path> afterwards.

This is the one command meant to be interactive. 'epack run' and
'epack run --check' never prompt.`,
		Args: cobra.NoArgs,
		RunE: runSetup,
	}
}

func runSetup(cmd *cobra.Command, _ []string) error {
	s, err := open(cmd, false)
	if err != nil {
		return err
	}
	if !s.interactive || !stdinIsTerminal() {
		return userError("epack secret setup needs a terminal", "Use 'epack secret set NAME --stdin' or '--from-file' without one")
	}
	resolution, err := s.resolution()
	if err != nil {
		return cmdutil.HandleError(err)
	}
	s.out.Print("Secrets for %s", s.scope)
	if s.scope.Revision > 0 {
		s.out.Print(", revision %d", s.scope.Revision)
	}
	s.out.Print(".\n")
	switch resolution.Store.Status {
	case secrets.StoreLocked, secrets.StoreUnavailable:
		return userError(resolution.Store.Message, "Unlock the keychain or set the variables in the environment")
	}
	stored, approved := 0, 0
	var skipped, unapproved []string
	for _, row := range resolution.Rows {
		switch row.Status {
		case secrets.StatusMissing:
			kept, err := s.setupMissing(row)
			if err != nil {
				return err
			}
			if kept {
				stored++
			} else {
				skipped = append(skipped, row.Name)
			}
		case secrets.StatusApprovalNeeded:
			ok, err := s.setupApproval(row.Name)
			if err != nil {
				return err
			}
			if ok {
				approved++
			} else {
				unapproved = append(unapproved, row.Name)
			}
		}
	}
	if stored+approved+len(skipped)+len(unapproved) == 0 {
		s.out.Print("Everything is in place. Next: epack run --check\n")
		return nil
	}
	s.out.Print("\nStored %d, approved %d, skipped %d.\n", stored, approved, len(skipped)+len(unapproved))
	if len(skipped) > 0 {
		example := skipped[0]
		if len(skipped) > 1 {
			example = "<NAME>"
		}
		s.out.Print("Skipped: %s. For a file, run epack secret set %s --from-file <path>.\n", strings.Join(skipped, ", "), example)
	}
	if len(unapproved) > 0 {
		s.out.Print("Left unapproved: %s. Run epack secret approve when you are ready.\n", strings.Join(unapproved, ", "))
	}
	s.out.Print("Next: epack run --check\n")
	return nil
}

func (s *session) setupMissing(row secrets.Row) (bool, error) {
	readers := secrets.ReadersOf(s.conf.Config, row.Name)
	s.out.Print("\n%s   read by %s\n", row.Name, readersLabel(readers))
	s.out.Print("  Paste the value (hidden) or press Enter to skip. For a file, use epack secret set %s --from-file <path> afterwards.\n", row.Name)
	value, err := s.promptHidden("  Value: ")
	if err != nil {
		return false, err
	}
	if value == "" {
		s.out.Print("  Skipped.\n")
		return false, nil
	}
	if _, err := s.service.Set(s.scope, row.Name, value, s.conf, true, false); err != nil {
		return false, cmdutil.HandleError(err)
	}
	s.out.Print("  Kept in your keychain and approved for %s.\n", readerNames(readers))
	return true, nil
}

func (s *session) setupApproval(name string) (bool, error) {
	pending, err := s.service.Pending(s.scope, s.conf, []string{name}, true)
	if err != nil {
		return false, cmdutil.HandleError(err)
	}
	if len(pending) == 0 {
		return true, nil
	}
	s.out.Print("\n")
	printChanges(s.out, pending[0], s.scope)
	if !s.confirm(approveQuestion(name, s.scope)) {
		s.out.Print("  Left unapproved; the run will not use it.\n")
		return false, nil
	}
	if err := s.service.Approve(s.scope, name, s.conf, true); err != nil {
		return false, cmdutil.HandleError(err)
	}
	s.out.Print("  Approved.\n")
	return true, nil
}

func approveQuestion(name string, scope secrets.Scope) string {
	if scope.Revision > 0 {
		return "Approve " + name + " for revision " + itoa(scope.Revision) + "?"
	}
	return "Approve " + name + " for this configuration?"
}

func itoa(n int) string {
	return strconv.Itoa(n)
}
