package project

import (
	"fmt"
	"os"
	"path/filepath"
)

// ConfigFileName is the name of the epack configuration file.
const ConfigFileName = "epack.yaml"

// FindRoot searches upward from dir for epack.yaml.
// Returns the directory containing epack.yaml, or error if not found.
//
// Security: Uses os.Lstat to detect symlinks. Symlinked epack.yaml files are
// rejected to prevent TOCTOU attacks where an attacker could redirect the
// config file to a malicious location between discovery and load.
func FindRoot(dir string) (string, error) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}

	for {
		configPath := filepath.Join(absDir, ConfigFileName)
		// Use Lstat to detect symlinks - os.Stat follows symlinks which could
		// allow an attacker to redirect epack.yaml to a malicious config file.
		info, err := os.Lstat(configPath)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return "", fmt.Errorf("epack.yaml is a symlink at %s (not allowed for security reasons)", absDir)
			}
			return absDir, nil
		}

		parent := filepath.Dir(absDir)
		if parent == absDir {
			// Reached filesystem root
			return "", fmt.Errorf("epack.yaml not found (searched from %s to root)", dir)
		}
		absDir = parent
	}
}
