//go:build windows

package execsafe

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// SecureTempDir creates a temporary directory.
// On Windows, this uses standard MkdirTemp (permissions enforced by NTFS ACLs).
// TODO: Implement proper Windows ACL restrictions when Windows support is added.
func SecureTempDir(prefix string) (string, func(), error) {
	tmpDir, err := os.MkdirTemp("", prefix)
	if err != nil {
		return "", nil, fmt.Errorf("creating temp dir: %w", err)
	}

	cleanup := func() {
		os.RemoveAll(tmpDir)
	}

	return tmpDir, cleanup, nil
}

// WriteSecureConfigFile writes config data to a temporary JSON file.
// On Windows, this uses standard temp file creation.
// TODO: Implement proper Windows ACL restrictions when Windows support is added.
func WriteSecureConfigFile(config map[string]interface{}, prefix string) (string, func(), error) {
	if len(config) == 0 {
		return "", nil, nil
	}

	tmpDir, dirCleanup, err := SecureTempDir(prefix)
	if err != nil {
		return "", nil, err
	}

	success := false
	defer func() {
		if !success && dirCleanup != nil {
			dirCleanup()
		}
	}()

	data, err := json.Marshal(config)
	if err != nil {
		return "", nil, fmt.Errorf("marshaling config: %w", err)
	}

	configPath := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return "", nil, fmt.Errorf("writing config file: %w", err)
	}

	success = true
	return configPath, dirCleanup, nil
}
