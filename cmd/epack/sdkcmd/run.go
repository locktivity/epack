//go:build components

package sdkcmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/locktivity/epack/internal/componentsdk"
	"github.com/spf13/cobra"
)

var (
	runTrust bool
	runWatch bool
)

func newRunCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run <binary|directory> [args...]",
		Short: "Run a local component binary for development",
		Long: `Run a local component binary without installation or verification.

This command is for component authors to test their binaries during development.
Unlike 'epack utility <name>' or 'epack tool <name>', this runs an unverified
local binary directly.

The binary must respond to --capabilities with valid JSON to confirm it's
a valid epack component.

WATCH MODE

Use --watch to automatically rebuild and rerun when source files change.
In watch mode, pass a directory (Go project) instead of a binary:

  epack sdk run --watch .
  epack sdk run --watch ./my-component -- pack.pack

The binary name is inferred from the directory name.

Examples:
  epack sdk run ./epack-utility-viewer pack.pack
  epack sdk run ./epack-tool-scanner --pack evidence.pack
  epack sdk run --trust ./my-component args...
  epack sdk run --watch . -- --capabilities

By default, you'll be prompted before running unverified binaries.
Use --trust to skip the prompt, or set 'component.trust_local: true'
in ~/.epack/config.yaml to permanently disable prompts.`,
		Args:               cobra.MinimumNArgs(1),
		RunE:               runRun,
		DisableFlagParsing: false,
	}

	cmd.Flags().BoolVar(&runTrust, "trust", false, "skip the confirmation prompt")
	cmd.Flags().BoolVar(&runWatch, "watch", false, "watch for changes and rebuild automatically")

	// Stop parsing flags after the binary path - everything else is passed through
	cmd.Flags().SetInterspersed(false)

	return cmd
}

func runRun(cmd *cobra.Command, args []string) error {
	out := getOutput(cmd)
	targetPath := args[0]
	binaryArgs := args[1:]

	// Resolve to absolute path
	absPath, err := filepath.Abs(targetPath)
	if err != nil {
		return fmt.Errorf("resolving path: %w", err)
	}

	// Check target exists
	info, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("path not found: %s", targetPath)
		}
		return fmt.Errorf("checking path: %w", err)
	}

	// Handle watch mode
	if runWatch {
		return runWatchMode(cmd, absPath, info, binaryArgs)
	}

	// Normal mode: expect a binary
	if info.IsDir() {
		return fmt.Errorf("path is a directory, not a binary: %s\n\nUse --watch for directory mode, or specify the binary path", targetPath)
	}

	// Check it's executable
	if info.Mode()&0111 == 0 {
		return fmt.Errorf("binary is not executable: %s\n\nRun: chmod +x %s", targetPath, targetPath)
	}

	// Verify it's a valid component by checking --capabilities
	caps, err := componentsdk.GetCapabilities(absPath)
	if err != nil {
		return fmt.Errorf("not a valid epack component: %w\n\nEnsure the binary responds to --capabilities with valid JSON", err)
	}

	// Check trust settings
	shouldPrompt := !runTrust && !isTrustLocalEnabled()

	// Always show warning banner
	p := out.Palette()
	out.Print("%s Running unverified local binary: %s\n", p.Yellow("!"), targetPath)
	if caps.Name != "" && caps.Kind != "" {
		out.Print("  Component: %s (%s)\n", caps.Name, caps.Kind)
	}

	// Prompt if needed
	if shouldPrompt {
		if !promptConfirm(out, "  Run? [y/N] ") {
			return fmt.Errorf("aborted")
		}
	}

	out.Print("\n")

	// Execute the binary
	exitCode, err := componentsdk.Run(cmd.Context(), componentsdk.RunOptions{
		BinaryPath: absPath,
		Args:       binaryArgs,
		Stdin:      os.Stdin,
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
	})
	if err != nil {
		return fmt.Errorf("executing component: %w", err)
	}

	if exitCode != 0 {
		os.Exit(exitCode)
	}

	return nil
}

func runWatchMode(cmd *cobra.Command, absPath string, info os.FileInfo, binaryArgs []string) error {
	out := getOutput(cmd)
	p := out.Palette()

	// Infer project directory and binary path
	var projectDir, binaryPath string
	if info.IsDir() {
		projectDir = absPath
		binaryPath = filepath.Join(projectDir, filepath.Base(projectDir))
	} else {
		projectDir = filepath.Dir(absPath)
		binaryPath = absPath
	}

	// Check for go.mod
	if !componentsdk.IsGoProject(projectDir) {
		return fmt.Errorf("watch mode requires a Go project (go.mod not found in %s)", projectDir)
	}

	// Prompt once before starting watch mode
	if !runTrust && !isTrustLocalEnabled() {
		out.Print("%s Watch mode will automatically build and run unverified code\n", p.Yellow("!"))
		out.Print("  Project: %s\n", projectDir)
		if !promptConfirm(out, "  Continue? [y/N] ") {
			return fmt.Errorf("aborted")
		}
		out.Print("\n")
	}

	out.Print("%s Watch mode started in %s\n", p.Cyan("→"), projectDir)
	out.Print("%s Watching for .go file changes\n\n", p.Dim("·"))

	return componentsdk.Watch(context.Background(), componentsdk.WatchOptions{
		ProjectDir: projectDir,
		BinaryPath: binaryPath,
		Args:       binaryArgs,
		OnBuildStart: func() {
			out.Print("%s Building...\n", p.Cyan("→"))
		},
		OnBuildSuccess: func() {
			out.Print("%s Build succeeded\n", p.Green("✓"))
		},
		OnBuildFailed: func(err error) {
			out.Print("%s Build failed: %v\n", p.Red("✗"), err)
		},
		OnRunStart: func(caps *componentsdk.Capabilities) {
			out.Print("%s Running %s (%s)...\n\n", p.Cyan("→"), caps.Name, caps.Kind)
		},
		OnRunExit: func(code int, err error) {
			if code != 0 {
				out.Print("\n%s Process exited with code %d\n", p.Yellow("!"), code)
			} else {
				out.Print("\n%s Process exited successfully\n", p.Dim("·"))
			}
		},
		OnWaiting: func() {
			out.Print("%s Watching for changes... (Ctrl+C to exit)\n", p.Dim("·"))
		},
		OnChange: func() {
			out.Print("\n%s Change detected, rebuilding...\n", p.Cyan("→"))
		},
		OnShutdown: func() {
			out.Print("\n%s Shutting down...\n", p.Yellow("!"))
		},
	})
}
