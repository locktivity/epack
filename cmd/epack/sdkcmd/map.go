//go:build components

package sdkcmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/safefile"
	"github.com/locktivity/epack/internal/tracemap"
	"github.com/spf13/cobra"
)

var (
	mapOut     string
	mapCheck   bool
	mapVerbose bool
)

func newMapCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "map [directory]",
		Short: "Write a collector's trace map",
		Long: `Write the trace map of the collector in directory, the current one by default.

The map links each field of the collector's artifacts to the operations whose
failure leaves the field out or changes it, to the source lines behind it,
and to the lines that record its gaps. The command runs the module's tests
with COLLECTORTEST_MAP set, so each collectortest suite writes what its fault
matrix found, merges the suites, and adds the lines static analysis of the
module's source finds. It fails when the tests fail, and when an operation a
suite lists feeds no field unless the suite lists it in Suite.Insensitive.
It prints a warning for each field that operations feed but that has no code.
The warning does not change the exit code.

Commit the map beside the collector's schema and pass it, embedded with
go:embed, as CollectorSpec.TraceMap: the SDK writes it into the build file
of every pack. Collector CI runs the command with --check, which fails when
the committed map differs from the one the code gives.

Examples:
  epack sdk map
  epack sdk map --check
  epack sdk map --out docs/schema/trace-map.json ../epack-collector-okta`,
		Args: cobra.MaximumNArgs(1),
		RunE: runMap,
	}
	cmd.Flags().StringVar(&mapOut, "out", tracemap.DefaultFile, "where the map goes, relative to the module root")
	cmd.Flags().BoolVar(&mapCheck, "check", false, "fail if the committed map is stale, without writing it")
	cmd.Flags().BoolVarP(&mapVerbose, "verbose", "v", false, "show the output of the test run")
	return cmd
}

func runMap(cmd *cobra.Command, args []string) error {
	out := getOutput(cmd)
	p := out.Palette()
	dir := "."
	if len(args) == 1 {
		dir = args[0]
	}
	rel := filepath.Clean(filepath.FromSlash(mapOut))
	if filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("--out %s must be a path inside the module", mapOut)
	}
	var testOutput io.Writer
	if mapVerbose {
		testOutput = cmd.ErrOrStderr()
	}
	out.Print("%s Running the collectortest suites...\n", p.Cyan("→"))
	m, root, err := tracemap.Build(cmd.Context(), tracemap.Options{Dir: dir, Output: testOutput})
	if err != nil {
		return err
	}
	warnUncoded(cmd.ErrOrStderr(), m)
	shown := filepath.ToSlash(rel)
	if mapCheck {
		if err := checkMap(root, rel, m); err != nil {
			return err
		}
		out.Print("%s %s is current: %s\n", p.Green("✓"), shown, m.Summary())
		return nil
	}
	encoded, err := tracemap.Encode(m)
	if err != nil {
		return err
	}
	if err := safefile.WriteFile(root, rel, encoded); err != nil {
		return fmt.Errorf("writing %s: %w", shown, err)
	}
	out.Print("%s Wrote %s: %s\n", p.Green("✓"), shown, m.Summary())
	return nil
}

// warnUncoded writes to w each field of m that operations feed but that has
// no code. It does not go through the output writer, because redaction would
// replace some pointers, such as a long camelCase one, with [REDACTED].
func warnUncoded(w io.Writer, m *tracemap.Map) {
	uncoded := m.Uncoded()
	if len(uncoded) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "warning: the trace map has no code for %d of the fields that operations feed:\n", len(uncoded))
	for _, field := range uncoded {
		_, _ = fmt.Fprintf(w, "  %s\n", field)
	}
}

// checkMap compares the map committed at rel, beneath root, with m, the one
// the code gives.
func checkMap(root, rel string, m *tracemap.Map) error {
	const fix = "run `epack sdk map` and commit the map it writes"
	shown := filepath.ToSlash(rel)
	encoded, err := tracemap.Encode(m)
	if err != nil {
		return err
	}
	committed, err := safefile.ReadFileBeneath(root, rel, limits.Artifact)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("there is no trace map at %s; %s", shown, fix)
	}
	if err != nil {
		return fmt.Errorf("reading %s: %w", shown, err)
	}
	if string(committed) == string(encoded) {
		return nil
	}
	var old tracemap.Map
	if err := json.Unmarshal(committed, &old); err != nil {
		return fmt.Errorf("%s is not a trace map (%v); %s", shown, err, fix)
	}
	diff := tracemap.Diff(&old, m)
	if diff == "" {
		diff = "its formatting differs"
	}
	return fmt.Errorf("%s is stale (%s); %s", shown, diff, fix)
}
