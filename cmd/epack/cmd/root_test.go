package cmd

import (
	"bytes"
	"testing"

	"github.com/locktivity/epack/internal/cli/output"
)

func TestQuickstart_Golden(t *testing.T) {
	var buf bytes.Buffer
	var errBuf bytes.Buffer
	out = output.New(&buf, &errBuf, output.Options{
		Quiet:   false,
		JSON:    false,
		NoColor: true,
		Verbose: false,
	})

	// Set the command's output to our buffer (printQuickstart uses cmd.OutOrStdout)
	rootCmd.SetOut(&buf)
	defer rootCmd.SetOut(nil)

	// Simulate running epack with no subcommand
	printQuickstart(rootCmd)

	got := buf.String()
	assertGolden(t, goldenPath("quickstart"), got)
}
