//go:build components

package remotecmd

import (
	stderrors "errors"
	"fmt"
	"os"
	"strings"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/exitcode"
	"github.com/locktivity/epack/internal/redact"
	"github.com/locktivity/epack/internal/remoteconfig"
	"github.com/locktivity/epack/internal/userconfig"
	"github.com/locktivity/epack/internal/userremote"
	"github.com/spf13/cobra"
)

func newUpdateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "update [remote]",
		Short: "Update the adapter you signed in with",
		Long: `Update the adapter installed for you to the newest release the catalog lists.

The adapter you signed in with is pinned in ~/.epack/remotes.lock and never
moves on its own. This moves it to the newest release of the same repository,
verified the same way as the first install. The new release is installed and
started before the pin moves, so a release that fails leaves the old one in
place.

A project that names the remote pins its own adapter in epack.lock.yaml; this
command does not change that pin.

Examples:
  epack remote update
  epack remote update locktivity`,
		Args: cobra.MaximumNArgs(1),
		RunE: runUpdate,
	}
}

func runUpdate(cmd *cobra.Command, args []string) error {
	out := getOutput(cmd)
	ctx := cmdContext(cmd)
	ui := newCommandUI(out, "", "", "Update failed")

	remoteName := ""
	if len(args) > 0 {
		remoteName = strings.TrimSpace(args[0])
	}
	if remoteName == "" {
		remoteName, _ = userconfig.DefaultRemote()
	}
	if remoteName == "" {
		return exitError("say which remote, as in: epack remote update locktivity")
	}

	resolver, err := userremote.New()
	if err != nil {
		return exitError("update failed: %v", err)
	}
	resolver.Stderr = os.Stderr
	resolver.Step = ui.onStep
	result, err := resolver.Update(ctx, remoteName)
	if err != nil {
		ui.fail()
		var typed *errors.Error
		if stderrors.As(err, &typed) {
			return err
		}
		return exitError("update failed: %v", err)
	}

	if out.IsJSON() {
		return out.JSON(map[string]interface{}{
			"remote":   remoteName,
			"previous": result.Previous,
			"version":  result.Version,
			"updated":  result.Updated,
		})
	}
	if result.Updated {
		out.Print("Updated the %s adapter from %s to %s\n", remoteName, output.Printable(result.Previous), output.Printable(result.Version))
	} else {
		out.Print("The %s adapter is current (%s)\n", remoteName, output.Printable(result.Version))
	}
	if _, cfg := currentProject(); cfg != nil {
		if _, pinned := cfg.Remotes[remoteName]; pinned {
			out.Print("This project pins its own %s adapter in epack.lock.yaml, which this does not change.\n", remoteName)
		}
	}
	return nil
}

// outdatedAdapterError explains a pull refused because the adapter declared
// no folder for its own files, which is how an adapter from before files_dir
// looks.
func outdatedAdapterError(remoteName string, prepared *PreparedRemote, hidden *remoteconfig.HiddenPathError) error {
	adapter := "the " + remoteName + " adapter"
	if prepared.Caps != nil && prepared.Caps.Version != "" {
		adapter += " " + output.Printable(prepared.Caps.Version)
	}
	message := fmt.Sprintf("clone failed: the configuration includes %s, and %s declared no folder for its own files, so epack refused it",
		output.Printable(hidden.Path), adapter)
	hint := fmt.Sprintf("Adapters released before this epack declare none. Update yours with 'epack remote update %s', then run this again", remoteName)
	if prepared.ProjectRoot != "" {
		hint = fmt.Sprintf("This project pins its own %s adapter in epack.lock.yaml. Run 'epack remote update %s', then run this from outside the project so your adapter does the fetch", remoteName, remoteName)
	}
	return &errors.Error{Code: errors.InvalidInput, Exit: exitcode.General, Message: redact.Error(message), Hint: hint}
}
