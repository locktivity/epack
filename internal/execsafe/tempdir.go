//go:build !windows

package execsafe

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"
)

// umaskMu protects umask operations which are process-global.
var umaskMu sync.Mutex

// SecureTempDir creates a temporary directory with restrictive permissions.
// Uses umask to ensure the directory is CREATED with 0700 permissions,
// eliminating the race window between MkdirTemp and Chmod.
func SecureTempDir(prefix string) (string, func(), error) {
	// Prefer XDG_RUNTIME_DIR when available - it's a tmpfs with user-only access
	baseDir := ""
	if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); runtimeDir != "" {
		info, err := os.Stat(runtimeDir)
		if err == nil && info.IsDir() {
			if stat, ok := info.Sys().(*unix.Stat_t); ok {
				if stat.Uid == uint32(os.Getuid()) && info.Mode().Perm() == 0700 {
					baseDir = runtimeDir
				}
			}
		}
	}

	// Set umask to 0077 so directory is created with 0700.
	// Mutex protects the process-global umask state.
	umaskMu.Lock()
	oldMask := unix.Umask(0077)
	tmpDir, err := os.MkdirTemp(baseDir, prefix)
	unix.Umask(oldMask)
	umaskMu.Unlock()

	if err != nil {
		return "", nil, fmt.Errorf("creating secure temp dir: %w", err)
	}

	cleanup := func() {
		_ = os.RemoveAll(tmpDir)
	}

	return tmpDir, cleanup, nil
}

// WriteSecureConfigFile writes config data to a secure temporary JSON file.
// This is the standard pattern for passing config to collectors and tools.
//
// SECURITY: Uses SecureTempDir for race-free restrictive permissions.
// The returned cleanup function removes both the file and its parent directory.
//
// Returns empty string and nil cleanup if config is empty.
func WriteSecureConfigFile(config map[string]interface{}, prefix string) (string, func(), error) {
	if len(config) == 0 {
		return "", nil, nil
	}

	// Create secure temp directory
	tmpDir, dirCleanup, err := SecureTempDir(prefix)
	if err != nil {
		return "", nil, err
	}

	// Clean up on any error after this point
	success := false
	defer func() {
		if !success && dirCleanup != nil {
			dirCleanup()
		}
	}()

	// Marshal config to JSON
	data, err := json.Marshal(config)
	if err != nil {
		return "", nil, fmt.Errorf("marshaling config: %w", err)
	}

	// Write file with restrictive permissions (0600)
	// Parent directory is already 0700, so this is safe
	configPath := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return "", nil, fmt.Errorf("writing config file: %w", err)
	}

	success = true
	return configPath, dirCleanup, nil
}
