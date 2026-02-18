package sync

import (
	"fmt"
	"path/filepath"
)

// SanitizeAssetName validates and extracts just the base filename from an asset name.
// This prevents path traversal attacks via malicious release asset names.
// Returns an error if the asset name is empty, contains path separators, or is unsafe.
func SanitizeAssetName(assetName string) (string, error) {
	if assetName == "" {
		return "", fmt.Errorf("asset name cannot be empty")
	}

	// Get just the base name - this strips any directory components
	base := filepath.Base(assetName)

	// Reject if Base returned "." (input was empty or all slashes)
	if base == "." || base == ".." {
		return "", fmt.Errorf("invalid asset name %q: resolves to unsafe path", assetName)
	}

	// Reject if the original contained path separators (even if Base extracted safely)
	// This catches explicit traversal attempts like "../../../etc/passwd"
	if containsAny(assetName, "/\\") {
		return "", fmt.Errorf("invalid asset name %q: contains path separators", assetName)
	}

	// Reject if it starts with a dot (hidden files, and catches ".." that slipped through)
	if len(base) > 0 && base[0] == '.' {
		return "", fmt.Errorf("invalid asset name %q: hidden files not allowed", assetName)
	}

	return base, nil
}

// containsAny returns true if s contains any character from chars.
func containsAny(s, chars string) bool {
	for _, c := range chars {
		for _, sc := range s {
			if sc == c {
				return true
			}
		}
	}
	return false
}
