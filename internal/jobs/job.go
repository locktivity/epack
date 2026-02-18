// Package jobs provides background job tracking for CLI operations.
package jobs

import "time"

// Status represents the current state of a job.
type Status string

const (
	StatusRunning   Status = "running"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
)

// Job represents a background job.
type Job struct {
	// ID is the unique job identifier.
	ID string `json:"id"`

	// Command is the CLI command being run.
	Command string `json:"command"`

	// Args are the command arguments.
	Args []string `json:"args"`

	// Status is the current job status.
	Status Status `json:"status"`

	// PID is the process ID of the background process.
	PID int `json:"pid"`

	// StartedAt is when the job started.
	StartedAt time.Time `json:"started_at"`

	// CompletedAt is when the job completed (if finished).
	CompletedAt *time.Time `json:"completed_at,omitempty"`

	// ExitCode is the process exit code (if finished).
	ExitCode *int `json:"exit_code,omitempty"`

	// LogPath is the path to the job log file.
	LogPath string `json:"log_path"`

	// Error contains any error message (if failed).
	Error string `json:"error,omitempty"`

	// Result contains job-specific result data (if completed).
	Result map[string]interface{} `json:"result,omitempty"`
}
