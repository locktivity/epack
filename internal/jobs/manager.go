package jobs

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// Manager handles job lifecycle operations.
// This is the application layer that uses the Store for persistence.
//
// Manager is safe for concurrent use. All operations that modify job state
// are protected by a mutex to prevent data races during concurrent access.
type Manager struct {
	store *Store
	mu    sync.Mutex // protects concurrent job operations
}

// NewManager creates a new job manager.
func NewManager(baseDir string) *Manager {
	if baseDir == "" {
		baseDir = ".epack/jobs"
	}
	return &Manager{
		store: NewStore(baseDir),
	}
}


// Create creates a new job record.
// Create is safe for concurrent use.
func (m *Manager) Create(id, command string, args []string, pid int) (*Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	logPath := m.store.LogPath(id)
	job := &Job{
		ID:        id,
		Command:   command,
		Args:      args,
		Status:    StatusRunning,
		PID:       pid,
		StartedAt: time.Now().UTC(),
		LogPath:   logPath,
	}

	if err := m.store.Save(job); err != nil {
		return nil, err
	}

	return job, nil
}

// Load loads a job by ID.
func (m *Manager) Load(id string) (*Job, error) {
	return m.store.Load(id)
}

// List returns all jobs, optionally filtered by status.
func (m *Manager) List(status Status) ([]*Job, error) {
	return m.store.List(status)
}

// Save persists a job to disk.
// Save is safe for concurrent use.
func (m *Manager) Save(job *Job) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.store.Save(job)
}

// Complete marks a job as completed.
// Complete is safe for concurrent use.
func (m *Manager) Complete(id string, exitCode int, result map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	job, err := m.store.Load(id)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	job.CompletedAt = &now
	job.ExitCode = &exitCode

	if exitCode == 0 {
		job.Status = StatusCompleted
		job.Result = result
	} else {
		job.Status = StatusFailed
	}

	return m.store.Save(job)
}

// Fail marks a job as failed with an error message.
// Fail is safe for concurrent use.
func (m *Manager) Fail(id string, errMsg string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	job, err := m.store.Load(id)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	job.CompletedAt = &now
	job.Status = StatusFailed
	job.Error = errMsg
	exitCode := 1
	job.ExitCode = &exitCode

	return m.store.Save(job)
}

// Clean removes old completed/failed job files older than the given duration.
// Clean is safe for concurrent use.
func (m *Manager) Clean(olderThan time.Duration) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.store.CleanOld(olderThan)
}

// CreateLogFile creates and returns a log file for a job.
func (m *Manager) CreateLogFile(jobID string) (*os.File, error) {
	return m.store.CreateLogFile(jobID)
}

// GenerateID generates a unique job ID.
func GenerateID() string {
	return fmt.Sprintf("job_%s_%d", time.Now().Format("20060102_150405"), os.Getpid())
}
