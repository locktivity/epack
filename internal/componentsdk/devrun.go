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
	"github.com/locktivity/epack/internal/procexec"
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
	output, err := procexec.Output(context.Background(), procexec.Spec{
		Path: binaryPath,
		Args: []string{"--capabilities"},
	})
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
	err := procexec.Run(ctx, procexec.Spec{
		Path:   opts.BinaryPath,
		Args:   opts.Args,
		Stdin:  opts.Stdin,
		Stdout: opts.Stdout,
		Stderr: opts.Stderr,
	})
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
	if err := validateWatchProject(opts.ProjectDir); err != nil {
		return err
	}

	watcher, err := newGoFileWatcher(opts.ProjectDir)
	if err != nil {
		return err
	}
	defer func() { _ = watcher.Close() }()

	ctx, cancel, sigChan := newWatchContext(ctx)
	defer cancel()

	var currentCmd *exec.Cmd
	var cmdMu sync.Mutex

	killCurrent := func() { killRunningCommand(&currentCmd, &cmdMu) }
	buildAndRun := func() { buildAndRunComponent(ctx, opts, &currentCmd, &cmdMu, killCurrent) }
	buildAndRun()

	triggerRebuild := newDebouncedRebuildTrigger(opts, buildAndRun)
	return runWatchLoop(watcher, sigChan, opts, killCurrent, triggerRebuild)
}

func validateWatchProject(projectDir string) error {
	goModPath := filepath.Join(projectDir, "go.mod")
	if _, err := os.Stat(goModPath); os.IsNotExist(err) {
		return fmt.Errorf("not a Go project (go.mod not found in %s)", projectDir)
	}
	return nil
}

func newGoFileWatcher(projectDir string) (*fsnotify.Watcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("creating file watcher: %w", err)
	}
	if err := watchGoFiles(watcher, projectDir); err != nil {
		_ = watcher.Close()
		return nil, fmt.Errorf("setting up file watch: %w", err)
	}
	return watcher, nil
}

func newWatchContext(parent context.Context) (context.Context, context.CancelFunc, chan os.Signal) {
	ctx, cancel := context.WithCancel(parent)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	return ctx, cancel, sigChan
}

func killRunningCommand(currentCmd **exec.Cmd, cmdMu *sync.Mutex) {
	cmdMu.Lock()
	defer cmdMu.Unlock()
	if *currentCmd == nil || (*currentCmd).Process == nil {
		return
	}
	_ = (*currentCmd).Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func(cmd *exec.Cmd) {
		_ = cmd.Wait()
		close(done)
	}(*currentCmd)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		_ = (*currentCmd).Process.Kill()
	}
	*currentCmd = nil
}

func buildAndRunComponent(ctx context.Context, opts WatchOptions, currentCmd **exec.Cmd, cmdMu *sync.Mutex, killCurrent func()) {
	killCurrent()
	if !buildComponentBinary(ctx, opts) {
		return
	}
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
	if opts.OnRunStart != nil {
		opts.OnRunStart(caps)
	}
	startComponentProcess(ctx, opts, currentCmd, cmdMu)
	go watchComponentExit(ctx, opts, currentCmd, cmdMu)
}

func buildComponentBinary(ctx context.Context, opts WatchOptions) bool {
	if opts.OnBuildStart != nil {
		opts.OnBuildStart()
	}
	if err := procexec.Run(ctx, procexec.Spec{
		Path:   "go",
		Args:   []string{"build", "-o", opts.BinaryPath, "."},
		Dir:    opts.ProjectDir,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}); err != nil {
		if opts.OnBuildFailed != nil {
			opts.OnBuildFailed(err)
		}
		if opts.OnWaiting != nil {
			opts.OnWaiting()
		}
		return false
	}
	if opts.OnBuildSuccess != nil {
		opts.OnBuildSuccess()
	}
	return true
}

func startComponentProcess(ctx context.Context, opts WatchOptions, currentCmd **exec.Cmd, cmdMu *sync.Mutex) {
	cmd, cancel, err := procexec.CommandChecked(ctx, procexec.Spec{
		Path:             opts.BinaryPath,
		Args:             opts.Args,
		Stdin:            os.Stdin,
		Stdout:           os.Stdout,
		Stderr:           os.Stderr,
		EnforceDirPolicy: true,
		AllowedDirRoots:  []string{opts.ProjectDir},
	})
	if err != nil {
		if opts.OnBuildFailed != nil {
			opts.OnBuildFailed(fmt.Errorf("building component process command: %w", err))
		}
		return
	}
	_ = cancel // No timeout set; cancel is a no-op.
	cmdMu.Lock()
	*currentCmd = cmd
	cmdMu.Unlock()
}

func watchComponentExit(ctx context.Context, opts WatchOptions, currentCmd **exec.Cmd, cmdMu *sync.Mutex) {
	cmdMu.Lock()
	cmd := *currentCmd
	cmdMu.Unlock()
	if cmd == nil {
		return
	}
	err := cmd.Run()
	cmdMu.Lock()
	*currentCmd = nil
	cmdMu.Unlock()

	if ctx.Err() != nil {
		return
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
}

func newDebouncedRebuildTrigger(opts WatchOptions, buildAndRun func()) func() {
	var debounceTimer *time.Timer
	debounceMu := sync.Mutex{}
	debounceDelay := 100 * time.Millisecond

	return func() {
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
}

func runWatchLoop(watcher *fsnotify.Watcher, sigChan chan os.Signal, opts WatchOptions, killCurrent func(), triggerRebuild func()) error {
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
			if strings.HasSuffix(event.Name, ".go") && event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				triggerRebuild()
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
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
