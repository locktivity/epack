// Package detach provides background process management for CLI operations.
//
// This package handles the orchestration of detached/background operations,
// separating the application-level concerns (job tracking, process lifecycle)
// from the CLI presentation layer.
package detach

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/locktivity/epack/internal/jobs"
	"github.com/locktivity/epack/internal/procexec"
	"github.com/locktivity/epack/internal/project"
)

// DefaultJobTimeout is the maximum duration a background job can run before
// being marked as timed out. This prevents goroutine leaks from hung processes.
const DefaultJobTimeout = 24 * time.Hour

// Options configures a detached operation.
type Options struct {
	// Command is the CLI command name (e.g., "push", "pull").
	Command string

	// Args are the command arguments (e.g., remote name, pack path).
	Args []string

	// Flags are additional flags to pass to the background command.
	// These should NOT include --detach (would cause infinite loop).
	Flags []string

	// WorkingDir is the working directory for the background process.
	// If empty, uses the project root or current directory.
	WorkingDir string

	// JobsDir is the directory for job storage.
	// If empty, uses .epack/jobs under project root.
	JobsDir string
}

// Result contains the result of spawning a detached process.
type Result struct {
	// JobID is the unique job identifier.
	JobID string

	// PID is the process ID of the background process.
	PID int

	// LogPath is the path to the job log file.
	LogPath string

	// Job is the created job record.
	Job *jobs.Job
}

// Spawn starts a background process for the given command.
//
//  1. Resolves the working directory and jobs storage location
//  2. Generates a unique job ID
//  3. Creates a log file for the background process
//  4. Spawns the background process with the given command/flags
//  5. Creates a job record for tracking
//  6. Starts a goroutine to update job status when the process exits
//
// The caller should ensure that --detach is NOT included in Flags
// to avoid infinite recursion.
func Spawn(opts Options) (*Result, error) {
	if opts.Command == "" {
		return nil, fmt.Errorf("command is required")
	}

	// Resolve working directory
	workDir := opts.WorkingDir
	if workDir == "" {
		projectRoot, err := project.FindRoot("")
		if err != nil {
			workDir, _ = os.Getwd()
		} else {
			workDir = projectRoot
		}
	}

	// Resolve jobs directory
	jobsDir := opts.JobsDir
	if jobsDir == "" {
		jobsDir = filepath.Join(workDir, ".epack", "jobs")
	}

	// Create job manager
	mgr := jobs.NewManager(jobsDir)

	// Generate job ID
	jobID := jobs.GenerateID()

	// Create log file
	logFile, err := mgr.CreateLogFile(jobID)
	if err != nil {
		return nil, fmt.Errorf("creating log file: %w", err)
	}

	// Get the current executable path
	executable, err := os.Executable()
	if err != nil {
		_ = logFile.Close()
		return nil, fmt.Errorf("getting executable path: %w", err)
	}

	// Build command arguments
	execArgs := []string{opts.Command}
	execArgs = append(execArgs, opts.Args...)
	execArgs = append(execArgs, opts.Flags...)

	// Create the background command
	bgCmd, cmdCancel, err := procexec.CommandChecked(context.Background(), procexec.Spec{
		Path:             executable,
		Args:             execArgs,
		Dir:              workDir,
		Stdout:           logFile,
		Stderr:           logFile,
		EnforceDirPolicy: true,
		AllowedDirRoots:  []string{workDir},
	})
	if err != nil {
		_ = logFile.Close()
		return nil, fmt.Errorf("building background process command: %w", err)
	}
	defer cmdCancel()

	// Start the background process
	if err := bgCmd.Start(); err != nil {
		_ = logFile.Close()
		return nil, fmt.Errorf("starting background process: %w", err)
	}

	// Create job record
	job, err := mgr.Create(jobID, opts.Command, opts.Args, bgCmd.Process.Pid)
	if err != nil {
		// Process started but we couldn't track it
		// Log file will be closed by goroutine
		go func() {
			_ = bgCmd.Wait()
			_ = logFile.Close()
		}()
		return nil, fmt.Errorf("creating job record: %w", err)
	}

	// Start goroutine to update job status when process exits.
	// Uses a timeout to prevent goroutine leaks if the process hangs.
	go func() {
		defer func() { _ = logFile.Close() }()

		// Wait for process in a separate goroutine so we can apply a timeout
		done := make(chan error, 1)
		go func() {
			done <- bgCmd.Wait()
		}()

		select {
		case err := <-done:
			// Process completed normally
			exitCode := 0
			if err != nil {
				exitCode = 1
				if bgCmd.ProcessState != nil {
					exitCode = bgCmd.ProcessState.ExitCode()
				}
			}
			_ = mgr.Complete(jobID, exitCode, nil)

		case <-time.After(DefaultJobTimeout):
			// Job timed out - kill the process and mark as failed
			_ = bgCmd.Process.Kill()
			_ = mgr.Fail(jobID, fmt.Sprintf("job timed out after %v", DefaultJobTimeout))
		}
	}()

	return &Result{
		JobID:   jobID,
		PID:     bgCmd.Process.Pid,
		LogPath: job.LogPath,
		Job:     job,
	}, nil
}

// BuildPushFlags builds the flag list for a detached push command.
// Centralizes push option → CLI flag conversion for use by CLI and tests.
func BuildPushFlags(env, workspace, notes string, labels, runsPaths []string, noRuns, nonInteractive bool) []string {
	var flags []string

	if env != "" {
		flags = append(flags, "--env", env)
	}
	if workspace != "" {
		flags = append(flags, "--workspace", workspace)
	}
	for _, label := range labels {
		flags = append(flags, "--label", label)
	}
	if notes != "" {
		flags = append(flags, "--notes", notes)
	}
	for _, runsPath := range runsPaths {
		flags = append(flags, "--runs-path", runsPath)
	}
	if noRuns {
		flags = append(flags, "--no-runs")
	}

	// Always add --yes in detached mode to avoid prompts
	flags = append(flags, "--yes")

	// Add --ci for clean log output
	flags = append(flags, "--ci")

	return flags
}

// BuildPullFlags builds the flag list for a detached pull command.
// Centralizes pull option → CLI flag conversion for use by CLI and tests.
func BuildPullFlags(env, workspace, output, digest, releaseID, version string, force, verify bool) []string {
	var flags []string

	if env != "" {
		flags = append(flags, "--env", env)
	}
	if workspace != "" {
		flags = append(flags, "--workspace", workspace)
	}
	if output != "" {
		flags = append(flags, "--output", output)
	}
	if digest != "" {
		flags = append(flags, "--digest", digest)
	}
	if releaseID != "" {
		flags = append(flags, "--release", releaseID)
	}
	if version != "" {
		flags = append(flags, "--version", version)
	}
	if force {
		flags = append(flags, "--force")
	}
	if !verify {
		flags = append(flags, "--verify=false")
	}

	// Add --ci for clean log output
	flags = append(flags, "--ci")

	return flags
}
