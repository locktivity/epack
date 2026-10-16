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

	// Use different golden file based on build type
	goldenFile := "quickstart"
	if ComponentsEnabled {
		goldenFile = "quickstart_components"
	}

	got := buf.String()
	assertGolden(t, goldenPath(goldenFile), got)
}

// ciVariables are the CI systems' variables, listed apart from ciEnvVars so
// a name dropped from that list fails these tests.
var ciVariables = []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "CODEBUILD_BUILD_ID", "JENKINS_URL", "BUILDKITE", "TF_BUILD"}

func TestInCI_RecognizesEachCISystem(t *testing.T) {
	for _, name := range ciVariables {
		getenv := func(key string) string {
			if key == name {
				return "true"
			}
			return ""
		}
		if !inCI(getenv) {
			t.Errorf("%s set should turn on CI mode", name)
		}
	}
	if inCI(func(string) string { return "" }) {
		t.Error("no CI variable set should leave CI mode off")
	}
}
