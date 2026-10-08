//go:build components

package remotecmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/cli/browser"
	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/cmdutil"
	"github.com/locktivity/epack/internal/exitcode"
	"github.com/locktivity/epack/internal/redact"
	"github.com/spf13/cobra"
)

// cmdContext returns the context from a cobra.Command, or context.Background() if cmd is nil.
func cmdContext(cmd *cobra.Command) context.Context {
	if cmd == nil {
		return context.Background()
	}
	return cmd.Context()
}

// exitError returns an Error with the general error code.
func exitError(format string, args ...interface{}) error {
	msg := fmt.Sprintf(format, args...)
	msg = redact.Error(msg)
	return &errors.Error{
		Code:    errors.InvalidInput,
		Exit:    exitcode.General,
		Message: msg,
	}
}

// exitErrorWithCode returns an Error with the specified exit code.
func exitErrorWithCode(code int, format string, args ...interface{}) error {
	msg := fmt.Sprintf(format, args...)
	msg = redact.Error(msg)
	return &errors.Error{
		Code:    errors.InvalidInput,
		Exit:    code,
		Message: msg,
	}
}

// ExitMalformedPack is the exit code for malformed pack errors.
const ExitMalformedPack = 2

// getOutput returns an output writer configured from the root flags that
// writes where the command writes.
func getOutput(cmd *cobra.Command) *output.Writer {
	return output.New(cmd.OutOrStdout(), cmd.ErrOrStderr(), cmdutil.OutputOptions(cmd))
}

// PipelinePage is the pipeline page link a remote sent, or empty when it is
// not an http or https URL. The link comes from a server, so nothing else is
// shown or passed on.
func PipelinePage(link string) string {
	if browser.Validate(link) != nil {
		return ""
	}
	return strings.TrimSpace(link)
}

// PrintPipelinePage points the person at the pipeline page when the remote
// sent a link PipelinePage keeps.
func PrintPipelinePage(out *output.Writer, link string) {
	if page := PipelinePage(link); page != "" {
		out.Print("See it on the pipeline page: %s\n", output.Printable(page))
	}
}
