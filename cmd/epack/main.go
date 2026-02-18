// Command epack is a CLI for creating, signing, and verifying evidence packs.
//
// For usage information, run:
//
//	epack --help
package main

import (
	"fmt"
	"os"

	"github.com/locktivity/epack/cmd/epack/cmd"
	"github.com/locktivity/epack/internal/cli/exitmap"
)

func main() {
	if err := cmd.Execute(); err != nil {
		// Single error rendering boundary: use exitmap.ToExit for all errors.
		// This:
		// - Preserves full error context (Message + Cause + Hint) via err.Error()
		// - Sanitizes via redact.Error() to remove secrets
		// - Extracts proper exit code from *errors.Error or defaults to 1
		msg, code := exitmap.ToExit(err)
		if msg != "" {
			fmt.Fprintf(os.Stderr, "Error: %s\n", msg)
		}
		os.Exit(code)
	}
}
