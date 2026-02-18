//go:build components

package remotecmd

import (
	"context"
	"fmt"
	"os"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/cli/output"
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

// out is the shared output writer, initialized lazily.
var out *output.Writer

// outputWriter returns the current output writer, initializing if needed.
// This is used when there's no command context available.
func outputWriter() *output.Writer {
	if out == nil {
		out = output.New(os.Stdout, os.Stderr, output.Options{})
	}
	return out
}
