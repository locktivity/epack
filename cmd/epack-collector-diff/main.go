// Command epack-collector-diff compares two trees of collectortest scenario
// output, such as the tree COLLECTORTEST_OUT gets at a collector's last
// release and the one it gets at a pull request. For each scenario it reports
// the artifacts added or removed and each JSON value that changed. With a
// profile and an epack-tool-validate binary, it also packs and validates
// both sides of each scenario and reports each requirement whose status or
// severity changed.
//
// Usage:
//
//	epack-collector-diff --base DIR --head DIR [--profile FILE --validate BIN]
//	    [--markdown FILE] [--json FILE] [--max-rows N]
//
// The Markdown report goes to stdout unless --markdown names a file. The
// command exits 0 whether or not anything changed, 1 when it cannot write a
// report, and 2 for bad input.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

const (
	exitOK       = 0
	exitFailure  = 1
	exitBadInput = 2
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

type options struct {
	base     string
	head     string
	profile  string
	validate string
	markdown string
	json     string
	maxRows  int
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	opts, err := parseFlags(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	if err != nil {
		return exitBadInput
	}
	report, err := buildReport(ctx, opts, stderr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "epack-collector-diff: %v\n", err)
		return exitBadInput
	}
	if err := writeReports(report, opts, stdout); err != nil {
		_, _ = fmt.Fprintf(stderr, "epack-collector-diff: %v\n", err)
		return exitFailure
	}
	return exitOK
}

// parseFlags prints its own errors and usage, so the caller only maps the
// error to an exit code.
func parseFlags(args []string, stderr io.Writer) (options, error) {
	fs := flag.NewFlagSet("epack-collector-diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o options
	fs.StringVar(&o.base, "base", "", "COLLECTORTEST_OUT tree to compare against, such as the last release's")
	fs.StringVar(&o.head, "head", "", "COLLECTORTEST_OUT tree to compare, such as a pull request's")
	fs.StringVar(&o.profile, "profile", "", "profile to validate both trees against (needs --validate)")
	fs.StringVar(&o.validate, "validate", "", "epack-tool-validate binary (needs --profile)")
	fs.StringVar(&o.markdown, "markdown", "", "file for the Markdown report (default stdout)")
	fs.StringVar(&o.json, "json", "", "file for the full report as JSON")
	fs.IntVar(&o.maxRows, "max-rows", 50, "most rows in the Markdown table")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "Usage: epack-collector-diff --base DIR --head DIR [--profile FILE --validate BIN] [--markdown FILE] [--json FILE] [--max-rows N]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	var err error
	switch {
	case fs.NArg() > 0:
		err = fmt.Errorf("unexpected argument %q", fs.Arg(0))
	case o.base == "" || o.head == "":
		err = errors.New("--base and --head are required")
	case (o.profile == "") != (o.validate == ""):
		err = errors.New("--profile and --validate must be given together")
	case o.maxRows < 0:
		err = errors.New("--max-rows must be 0 or more")
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "epack-collector-diff: %v\n", err)
		fs.Usage()
	}
	return o, err
}

func buildReport(ctx context.Context, opts options, stderr io.Writer) (*report, error) {
	base, err := loadTree(opts.base)
	if err != nil {
		return nil, fmt.Errorf("reading --base: %w", err)
	}
	head, err := loadTree(opts.head)
	if err != nil {
		return nil, fmt.Errorf("reading --head: %w", err)
	}
	r := compareTrees(base, head)
	r.ControlsCompared = opts.profile != ""
	if r.ControlsCompared {
		if !base.hasSchema() && !head.hasSchema() {
			_, _ = fmt.Fprintln(stderr, "epack-collector-diff: warning: no scenarios.json gives an artifact schema, so the validator has no artifact to evaluate")
		}
		if err := addControls(ctx, r, base, head, opts); err != nil {
			return nil, err
		}
	}
	r.summarize()
	return r, nil
}

func writeReports(r *report, opts options, stdout io.Writer) error {
	markdown := renderMarkdown(r, opts.maxRows)
	if opts.markdown == "" {
		if _, err := io.WriteString(stdout, markdown); err != nil {
			return fmt.Errorf("writing the Markdown report: %w", err)
		}
	} else if err := os.WriteFile(opts.markdown, []byte(markdown), 0o644); err != nil {
		return fmt.Errorf("writing the Markdown report: %w", err)
	}
	if opts.json == "" {
		return nil
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding the JSON report: %w", err)
	}
	if err := os.WriteFile(opts.json, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("writing the JSON report: %w", err)
	}
	return nil
}
