//go:build conformance

// Command epack-conformance tests component conformance against the epack component spec.
//
// Usage:
//
//	epack-conformance collector ./path/to/collector
//	epack-conformance tool ./path/to/tool
//	epack-conformance remote ./path/to/adapter
//	epack-conformance utility ./path/to/utility
//
// Build with:
//
//	go build -tags conformance ./cmd/epack-conformance
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/locktivity/epack/internal/componentconf"
	"github.com/locktivity/epack/internal/componenttypes"
)

func main() {
	if len(os.Args) < 3 {
		printUsage()
		os.Exit(1)
	}

	componentType := os.Args[1]
	binaryPath := os.Args[2]

	var ct componenttypes.ComponentKind
	switch componentType {
	case "collector":
		ct = componenttypes.KindCollector
	case "tool":
		ct = componenttypes.KindTool
	case "remote":
		ct = componenttypes.KindRemote
	case "utility":
		ct = componenttypes.KindUtility
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown component type %q\n", componentType)
		fmt.Fprintf(os.Stderr, "Valid types: collector, tool, remote, utility\n")
		os.Exit(1)
	}

	// Verify binary exists
	if _, err := os.Stat(binaryPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error: binary not found: %s\n", binaryPath)
		os.Exit(1)
	}

	// Parse optional flags
	jsonOutput := false
	level := "standard" // minimal, standard, full
	timeout := 30 * time.Second

	for i := 3; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--json":
			jsonOutput = true
		case "--level":
			if i+1 < len(os.Args) {
				level = os.Args[i+1]
				i++
			}
		case "--timeout":
			if i+1 < len(os.Args) {
				d, err := time.ParseDuration(os.Args[i+1])
				if err == nil {
					timeout = d
				}
				i++
			}
		}
	}

	// Run conformance tests
	runner := componentconf.NewRunner(binaryPath, ct)
	runner.Timeout = timeout

	ctx := context.Background()
	report, err := runner.Run(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Output results
	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(report)
	} else {
		printReport(report)
	}

	// Exit code based on conformance level
	exitCode := 0
	switch level {
	case "minimal":
		if report.Summary.Must.Fail > 0 {
			exitCode = 1
		}
	case "standard":
		if report.Summary.Must.Fail > 0 || report.Summary.Should.Fail > 0 {
			exitCode = 1
		}
	case "full":
		if report.Summary.Must.Fail > 0 || report.Summary.Should.Fail > 0 || report.Summary.May.Fail > 0 {
			exitCode = 1
		}
	}

	os.Exit(exitCode)
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "epack-conformance - Test component conformance")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  epack-conformance <type> <binary> [flags]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Types:")
	fmt.Fprintln(os.Stderr, "  collector  Test a collector binary")
	fmt.Fprintln(os.Stderr, "  tool       Test a tool binary")
	fmt.Fprintln(os.Stderr, "  remote     Test a remote adapter binary")
	fmt.Fprintln(os.Stderr, "  utility    Test a utility binary")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Flags:")
	fmt.Fprintln(os.Stderr, "  --json            Output JSON report")
	fmt.Fprintln(os.Stderr, "  --level <level>   Required conformance level (minimal, standard, full)")
	fmt.Fprintln(os.Stderr, "  --timeout <dur>   Test timeout (e.g., 30s, 1m)")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Examples:")
	fmt.Fprintln(os.Stderr, "  epack-conformance collector ./my-collector")
	fmt.Fprintln(os.Stderr, "  epack-conformance tool ./my-tool --json")
	fmt.Fprintln(os.Stderr, "  epack-conformance remote ./my-adapter --level minimal")
}

func printReport(report *componentconf.Report) {
	fmt.Printf("Conformance Report: %s (%s)\n", report.Component, report.Type)
	fmt.Printf("Level: %s\n\n", report.Level)

	// Summary
	fmt.Println("Summary:")
	fmt.Printf("  MUST:   %d pass, %d fail, %d skip\n",
		report.Summary.Must.Pass, report.Summary.Must.Fail, report.Summary.Must.Skip)
	fmt.Printf("  SHOULD: %d pass, %d fail, %d skip\n",
		report.Summary.Should.Pass, report.Summary.Should.Fail, report.Summary.Should.Skip)
	fmt.Printf("  MAY:    %d pass, %d fail, %d skip\n",
		report.Summary.May.Pass, report.Summary.May.Fail, report.Summary.May.Skip)
	fmt.Println()

	// Failed tests
	var failures []componentconf.TestResult
	for _, r := range report.Results {
		if r.Status == componentconf.StatusFail {
			failures = append(failures, r)
		}
	}

	if len(failures) > 0 {
		fmt.Println("Failures:")
		for _, f := range failures {
			fmt.Printf("  %s [%s] %s\n", f.ID, f.Level, f.Message)
		}
		fmt.Println()
	}

	// Skipped tests (only show MUST/SHOULD)
	var skipped []componentconf.TestResult
	for _, r := range report.Results {
		if r.Status == componentconf.StatusSkip && (r.Level == componentconf.LevelMust || r.Level == componentconf.LevelShould) {
			skipped = append(skipped, r)
		}
	}

	if len(skipped) > 0 {
		fmt.Println("Skipped (MUST/SHOULD):")
		for _, s := range skipped {
			fmt.Printf("  %s [%s] %s\n", s.ID, s.Level, s.Reason)
		}
	}
}
