package jobs

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// jobIDRegex validates job IDs to prevent path traversal.
// Job IDs must be alphanumeric with underscores only (e.g., "job_20240101_120000_1234").
var jobIDRegex = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

// validateJobID ensures a job ID is safe for use in file paths.
func validateJobID(id string) error {
	if id == "" {
		return fmt.Errorf("job ID cannot be empty")
	}
	if len(id) > 64 {
		return fmt.Errorf("job ID too long (max 64 characters)")
	}
	if !jobIDRegex.MatchString(id) {
		return fmt.Errorf("job ID contains invalid characters")
	}
	return nil
}

// Store handles job persistence to the filesystem.
// This is the infrastructure layer for job storage.
type Store struct {
	// BaseDir is the base directory for job data.
	BaseDir string
}

// NewStore creates a new job store.
func NewStore(baseDir string) *Store {
	return &Store{BaseDir: baseDir}
}

// Save persists a job to disk.
func (s *Store) Save(job *Job) error {
	if err := validateJobID(job.ID); err != nil {
		return fmt.Errorf("invalid job ID: %w", err)
	}

	if err := os.MkdirAll(s.BaseDir, 0755); err != nil {
		return fmt.Errorf("creating jobs directory: %w", err)
	}

	path := filepath.Join(s.BaseDir, job.ID+".json")
	data, err := json.MarshalIndent(job, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling job: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("writing job file: %w", err)
	}
	return nil
}

// Load loads a job by ID.
func (s *Store) Load(id string) (*Job, error) {
	if err := validateJobID(id); err != nil {
		return nil, fmt.Errorf("invalid job ID: %w", err)
	}

	path := filepath.Join(s.BaseDir, id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("job %q not found", id)
		}
		return nil, fmt.Errorf("reading job file: %w", err)
	}

	var job Job
	if err := json.Unmarshal(data, &job); err != nil {
		return nil, fmt.Errorf("parsing job file: %w", err)
	}

	return &job, nil
}

// List returns all jobs, optionally filtered by status.
func (s *Store) List(status Status) ([]*Job, error) {
	entries, err := os.ReadDir(s.BaseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading jobs directory: %w", err)
	}

	var jobs []*Job
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		id := entry.Name()[:len(entry.Name())-5] // Remove .json
		job, err := s.Load(id)
		if err != nil {
			continue // Skip invalid job files
		}

		if status == "" || job.Status == status {
			jobs = append(jobs, job)
		}
	}

	return jobs, nil
}

// Delete removes a job file and optionally its log file.
func (s *Store) Delete(id string, deleteLog bool) error {
	if err := validateJobID(id); err != nil {
		return fmt.Errorf("invalid job ID: %w", err)
	}

	job, err := s.Load(id)
	if err != nil {
		return err
	}

	// Remove job file
	jobPath := filepath.Join(s.BaseDir, id+".json")
	if err := os.Remove(jobPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing job file: %w", err)
	}

	// Remove log file if requested
	if deleteLog && job.LogPath != "" {
		_ = os.Remove(job.LogPath) // Ignore errors for log file
	}

	return nil
}

// LogPath returns the path for a job's log file.
// Returns empty string if the job ID is invalid.
func (s *Store) LogPath(jobID string) string {
	if err := validateJobID(jobID); err != nil {
		return ""
	}
	return filepath.Join(s.BaseDir, jobID+".log")
}

// CreateLogFile creates and returns a log file for a job.
func (s *Store) CreateLogFile(jobID string) (*os.File, error) {
	if err := validateJobID(jobID); err != nil {
		return nil, fmt.Errorf("invalid job ID: %w", err)
	}

	if err := os.MkdirAll(s.BaseDir, 0755); err != nil {
		return nil, fmt.Errorf("creating jobs directory: %w", err)
	}

	logPath := s.LogPath(jobID)
	logFile, err := os.Create(logPath)
	if err != nil {
		return nil, fmt.Errorf("creating log file: %w", err)
	}
	return logFile, nil
}

// CleanOld removes completed/failed job files older than the given duration.
// Returns the number of jobs removed.
func (s *Store) CleanOld(olderThan time.Duration) (int, error) {
	jobs, err := s.List("")
	if err != nil {
		return 0, err
	}

	cutoff := time.Now().Add(-olderThan)
	removed := 0

	for _, job := range jobs {
		if job.Status == StatusRunning {
			continue // Don't remove running jobs
		}

		var jobTime time.Time
		if job.CompletedAt != nil {
			jobTime = *job.CompletedAt
		} else {
			jobTime = job.StartedAt
		}

		if jobTime.Before(cutoff) {
			if err := s.Delete(job.ID, true); err == nil {
				removed++
			}
		}
	}

	return removed, nil
}
