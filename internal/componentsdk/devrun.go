package componentsdk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Capabilities represents the JSON from --capabilities.
type Capabilities struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Version     string `json:"version"`
	Description string `json:"description"`
}

// GetCapabilities runs --capabilities on a binary and parses the output.
func GetCapabilities(binaryPath string) (*Capabilities, error) {
	cmd := exec.Command(binaryPath, "--capabilities")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("running --capabilities: %w", err)
	}

	var caps Capabilities
	if err := json.Unmarshal(output, &caps); err != nil {
		return nil, fmt.Errorf("parsing capabilities JSON: %w", err)
	}

	if caps.Kind == "" {
		return nil, fmt.Errorf("missing 'kind' in capabilities")
	}

	return &caps, nil
}

// RunOptions configures how to run a local component.
type RunOptions struct {
	// BinaryPath is the path to the component binary.
	BinaryPath string

	// Args are the arguments to pass to the binary.
	Args []string

	// Stdin is the input for the binary.
	Stdin io.Reader

	// Stdout is the output for the binary.
	Stdout io.Writer

	// Stderr is the error output for the binary.
	Stderr io.Writer
}

// Run executes a component binary and returns its exit code.
func Run(ctx context.Context, opts RunOptions) (int, error) {
	cmd := exec.CommandContext(ctx, opts.BinaryPath, opts.Args...)
	cmd.Stdin = opts.Stdin
	cmd.Stdout = opts.Stdout
	cmd.Stderr = opts.Stderr

	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), nil
		}
		return 1, err
	}

	return 0, nil
}

// WatchOptions configures watch mode for component development.
type WatchOptions struct {
	// ProjectDir is the Go project directory to watch.
	ProjectDir string

	// BinaryPath is where to build the binary.
	BinaryPath string

	// Args are the arguments to pass to the binary on each run.
	Args []string

	// OnBuildStart is called when a build starts.
	OnBuildStart func()

	// OnBuildSuccess is called when a build succeeds.
	OnBuildSuccess func()

	// OnBuildFailed is called when a build fails.
	OnBuildFailed func(err error)

	// OnRunStart is called when the component starts running.
	OnRunStart func(caps *Capabilities)

	// OnRunExit is called when the component exits.
	OnRunExit func(code int, err error)

	// OnWaiting is called when waiting for changes.
	OnWaiting func()

	// OnChange is called when a file change is detected.
	OnChange func()

	// OnShutdown is called when shutting down.
	OnShutdown func()
}

// Watch runs the component in watch mode, rebuilding and rerunning on changes.
// It blocks until interrupted.
func Watch(ctx context.Context, opts WatchOptions) error {
	// Validate project directory
	goModPath := filepath.Join(opts.ProjectDir, "go.mod")
	if _, err := os.Stat(goModPath); os.IsNotExist(err) {
		return fmt.Errorf("not a Go project (go.mod not found in %s)", opts.ProjectDir)
	}

	// Set up file watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("creating file watcher: %w", err)
	}
	defer func() { _ = watcher.Close() }()

	// Watch all directories with .go files
	if err := watchGoFiles(watcher, opts.ProjectDir); err != nil {
		return fmt.Errorf("setting up file watch: %w", err)
	}

	// Set up signal handling
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Track the running process
	var currentCmd *exec.Cmd
	var cmdMu sync.Mutex

	killCurrent := func() {
		cmdMu.Lock()
		defer cmdMu.Unlock()
		if currentCmd != nil && currentCmd.Process != nil {
			_ = currentCmd.Process.Signal(syscall.SIGTERM)
			done := make(chan struct{})
			go func() {
				_ = currentCmd.Wait()
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				_ = currentCmd.Process.Kill()
			}
			currentCmd = nil
		}
	}

	buildAndRun := func() {
		killCurrent()

		// Build
		if opts.OnBuildStart != nil {
			opts.OnBuildStart()
		}

		buildCmd := exec.CommandContext(ctx, "go", "build", "-o", opts.BinaryPath, ".")
		buildCmd.Dir = opts.ProjectDir
		buildCmd.Stdout = os.Stdout
		buildCmd.Stderr = os.Stderr

		if err := buildCmd.Run(); err != nil {
			if opts.OnBuildFailed != nil {
				opts.OnBuildFailed(err)
			}
			if opts.OnWaiting != nil {
				opts.OnWaiting()
			}
			return
		}

		if opts.OnBuildSuccess != nil {
			opts.OnBuildSuccess()
		}

		// Verify it's a valid component
		caps, err := GetCapabilities(opts.BinaryPath)
		if err != nil {
			if opts.OnBuildFailed != nil {
				opts.OnBuildFailed(fmt.Errorf("invalid component: %w", err))
			}
			if opts.OnWaiting != nil {
				opts.OnWaiting()
			}
			return
		}

		// Run
		if opts.OnRunStart != nil {
			opts.OnRunStart(caps)
		}

		cmdMu.Lock()
		currentCmd = exec.CommandContext(ctx, opts.BinaryPath, opts.Args...)
		currentCmd.Stdin = os.Stdin
		currentCmd.Stdout = os.Stdout
		currentCmd.Stderr = os.Stderr
		cmdMu.Unlock()

		go func() {
			err := currentCmd.Run()
			cmdMu.Lock()
			currentCmd = nil
			cmdMu.Unlock()

			if ctx.Err() != nil {
				return // Context cancelled
			}

			exitCode := 0
			if err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok {
					exitCode = exitErr.ExitCode()
				}
			}

			if opts.OnRunExit != nil {
				opts.OnRunExit(exitCode, err)
			}
			if opts.OnWaiting != nil {
				opts.OnWaiting()
			}
		}()
	}

	// Initial build and run
	buildAndRun()

	// Debounce timer
	var debounceTimer *time.Timer
	debounceMu := sync.Mutex{}
	debounceDelay := 100 * time.Millisecond

	triggerRebuild := func() {
		debounceMu.Lock()
		defer debounceMu.Unlock()
		if debounceTimer != nil {
			debounceTimer.Stop()
		}
		debounceTimer = time.AfterFunc(debounceDelay, func() {
			if opts.OnChange != nil {
				opts.OnChange()
			}
			buildAndRun()
		})
	}

	// Watch loop
	for {
		select {
		case <-sigChan:
			if opts.OnShutdown != nil {
				opts.OnShutdown()
			}
			killCurrent()
			return nil

		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if strings.HasSuffix(event.Name, ".go") {
				if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
					triggerRebuild()
				}
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			// Log but don't fail
			fmt.Fprintf(os.Stderr, "watch error: %v\n", err)
		}
	}
}

// watchGoFiles recursively watches all directories containing .go files.
func watchGoFiles(watcher *fsnotify.Watcher, root string) error {
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			name := d.Name()
			if strings.HasPrefix(name, ".") || name == "vendor" || name == "node_modules" || name == "testdata" {
				return filepath.SkipDir
			}
			if err := watcher.Add(path); err != nil {
				return fmt.Errorf("watching %s: %w", path, err)
			}
		}

		return nil
	})
}

// InferBinaryPath returns the inferred binary path for a Go project.
// If the path is a directory, the binary name is the directory name.
// If the path is a file, it's returned as-is.
func InferBinaryPath(path string) (projectDir, binaryPath string, err error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", "", fmt.Errorf("resolving path: %w", err)
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return "", "", fmt.Errorf("checking path: %w", err)
	}

	if info.IsDir() {
		projectDir = absPath
		binaryPath = filepath.Join(projectDir, filepath.Base(projectDir))
	} else {
		projectDir = filepath.Dir(absPath)
		binaryPath = absPath
	}

	return projectDir, binaryPath, nil
}

// IsGoProject checks if a directory contains a go.mod file.
func IsGoProject(dir string) bool {
	goModPath := filepath.Join(dir, "go.mod")
	_, err := os.Stat(goModPath)
	return err == nil
}
