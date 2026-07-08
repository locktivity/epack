// Package stagedartifact centralizes collector artifact data-vs-file rules.
package stagedartifact

import (
	"fmt"
	"path/filepath"
)

// Entry is the protocol-constrained part of an artifact entry.
// Callers compute HasData because SDK and runner detect presence differently.
type Entry struct {
	HasData bool
	File    string
	Path    string
}

// Validate enforces exactly one payload source and normalizes file paths.
func (e Entry) Validate() (string, error) {
	switch {
	case e.File != "":
		if e.HasData {
			return "", fmt.Errorf("'file' and 'data' are mutually exclusive")
		}
		if e.Path == "" {
			return "", fmt.Errorf("'file' requires an explicit 'path'")
		}
		if err := LocalPath(e.File); err != nil {
			return "", err
		}
		return filepath.ToSlash(e.File), nil
	case !e.HasData:
		return "", fmt.Errorf("artifact must carry either 'file' or 'data'")
	default:
		return "", nil
	}
}

// LocalPath rejects empty, absolute, and traversing paths.
func LocalPath(p string) error {
	if p == "" {
		return fmt.Errorf("path is required")
	}
	if filepath.IsAbs(p) || !filepath.IsLocal(p) {
		return fmt.Errorf("path %q must be relative and stay within the staging directory", p)
	}
	return nil
}
