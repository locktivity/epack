//go:build !components

package cmd

import (
	"fmt"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/exitcode"
	"github.com/spf13/cobra"
)

// registerToolCommands adds a stub tool command that explains
// how to get the full version with tool support.
func registerToolCommands(root *cobra.Command) {
	root.AddCommand(&cobra.Command{
		Use:   "tool",
		Short: "Run tools on evidence packs (not available in this build)",
		Long: `Tool commands are not available in epack-core.

The tool feature allows you to run tools that operate on signed evidence packs
and produce derived outputs. Tools are standalone binaries that implement the
epack tool protocol.

For tool support, install 'epack' (full version).
See: https://github.com/locktivity/epack#installation`,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Error: tool commands are not available in epack-core.")
			_, _ = fmt.Fprintln(cmd.ErrOrStderr())
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "For tool support, install 'epack' (full version).")
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "See: https://github.com/locktivity/epack#installation")
			return &errors.Error{Code: errors.InvalidInput, Exit: exitcode.General, Message: "tool commands not available"}
		},
	})
}
