//go:build components

package secretcmd

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	epackerrors "github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/cmdutil"
	"github.com/locktivity/epack/internal/exitcode"
	"github.com/locktivity/epack/internal/project"
	"github.com/locktivity/epack/internal/runflow"
	"github.com/locktivity/epack/internal/secrets"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// newStore is the store the commands use; tests replace it.
var newStore = func() secrets.Store { return secrets.NewKeychain() }

// newOutput is the writer the commands print to; tests replace it.
var newOutput = cmdutil.GetOutput

// newPaths is where epack keeps what it knows about stored secrets; tests
// replace it.
var newPaths = secrets.DefaultPaths

// stdinIsTerminal and stderrIsTerminal are what decides whether a command
// may prompt; tests replace them.
var (
	stdinIsTerminal  = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
	stderrIsTerminal = func() bool { return term.IsTerminal(int(os.Stderr.Fd())) }
	readHidden       = func() ([]byte, error) { return term.ReadPassword(int(os.Stdin.Fd())) }
	readAllStdin     = func() ([]byte, error) { return io.ReadAll(os.Stdin) }
)

// session is everything a secret command needs: the folder's configuration,
// its scope, the service, and whether the command may interact.
type session struct {
	out         *output.Writer
	workDir     string
	conf        *secrets.Configuration
	scope       secrets.Scope
	service     *secrets.Service
	interactive bool
}

func open(cmd *cobra.Command, yes bool) (*session, error) {
	out := newOutput(cmd)
	workDir, err := project.FindRoot("")
	if err != nil {
		return nil, &epackerrors.Error{
			Code:    epackerrors.InvalidInput,
			Exit:    exitcode.General,
			Message: "not in an epack project",
			Hint:    "cd into the folder 'epack remote clone' created",
		}
	}
	conf, err := secrets.LoadConfiguration(workDir)
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}
	remoteName, _ := runflow.ResolveRemote(conf.Config, "")
	scope, err := secrets.ScopeFor(workDir, remoteName, os.Getenv)
	if err != nil {
		return nil, fmt.Errorf("reading the pull record: %w", err)
	}
	if scope.Zero() {
		return nil, &epackerrors.Error{
			Code:    epackerrors.InvalidInput,
			Exit:    exitcode.General,
			Message: "this folder has no pull record, so it has no place to keep secrets",
			Hint:    "Run 'epack remote clone <name>' and work in the folder it creates, or set the variables in the environment",
		}
	}
	paths, err := newPaths()
	if err != nil {
		return nil, err
	}
	return &session{
		out:         out,
		workDir:     workDir,
		conf:        conf,
		scope:       scope,
		service:     &secrets.Service{Paths: paths, Store: newStore()},
		interactive: !yes && !out.IsCI() && stderrIsTerminal(),
	}, nil
}

// resolution reads every listed variable the way a check does, through the
// store when the command may interact.
func (s *session) resolution() (*secrets.Resolution, error) {
	resolver := secrets.Resolver{Paths: s.service.Paths, Store: s.service.Store, Env: os.Getenv, Interactive: s.interactive}
	return resolver.Resolve(s.conf.Config, s.scope, nil)
}

// printStillNeeded says which required variables the configuration still
// lacks after a change, or that the next step is the check.
func (s *session) printStillNeeded() {
	resolver := secrets.Resolver{Paths: s.service.Paths, Store: s.service.Store, Env: os.Getenv}
	resolution, err := resolver.Resolve(s.conf.Config, s.scope, nil)
	if err != nil {
		return
	}
	var names []string
	for _, row := range resolution.Blocking() {
		names = append(names, row.Name)
	}
	if len(names) > 0 {
		s.out.Print("Still needed: %s.\n", strings.Join(names, ", "))
		return
	}
	s.out.Print("Everything the configuration lists is in place. Next: epack run --check\n")
}

// confirm asks a yes-or-no question whose default is no.
func (s *session) confirm(question string) bool {
	if !s.interactive || !stdinIsTerminal() {
		return false
	}
	answer, err := s.out.Prompt(question + " [y/N] ")
	if err != nil {
		return false
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes"
}

// promptHidden reads one line without echo.
func (s *session) promptHidden(label string) (string, error) {
	if !s.interactive || !stdinIsTerminal() {
		return "", output.ErrNotInteractive
	}
	_, _ = fmt.Fprint(os.Stderr, label)
	value, err := readHidden()
	_, _ = fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(value), "\r\n"), nil
}

func readersLabel(readers []secrets.Reader) string {
	labels := make([]string, 0, len(readers))
	for _, reader := range readers {
		labels = append(labels, reader.Label())
	}
	return strings.Join(labels, ", ")
}

func readerNames(readers []secrets.Reader) string {
	names := make([]string, 0, len(readers))
	for _, reader := range readers {
		names = append(names, reader.Name)
	}
	return strings.Join(names, ", ")
}

func sinceDate(stamp string) string {
	parsed, err := time.Parse(time.RFC3339, stamp)
	if err != nil {
		return stamp
	}
	return parsed.Format("Jan 2, 2006")
}

func userError(message, hint string) error {
	return &epackerrors.Error{Code: epackerrors.InvalidInput, Exit: exitcode.General, Message: message, Hint: hint}
}

func printChanges(out *output.Writer, pending secrets.Pending, scope secrets.Scope) {
	switch {
	case pending.ApprovedRevision > 0 && scope.Revision > 0:
		out.Print("%s, approved at revision %d, now at revision %d.\n", pending.Name, pending.ApprovedRevision, scope.Revision)
	case pending.ApprovedRevision > 0:
		out.Print("%s, approved at revision %d.\n", pending.Name, pending.ApprovedRevision)
	default:
		out.Print("%s, not approved yet.\n", pending.Name)
	}
	for _, change := range pending.Changes {
		if len(change.Lines) > 0 {
			out.Print("  %s changed:\n", change.Reader.Label())
			for _, line := range change.Lines {
				if strings.HasPrefix(line, " ") {
					continue
				}
				out.Print("    %s\n", output.Printable(line))
			}
		}
		out.Print("  What this means: %s.\n", output.Printable(change.Summary))
	}
}
