// Package packpath defines path constants and validation for evidence packs.
//
// This package centralizes artifact path validation to ensure consistent
// enforcement across both builder (pack creation) and manifest (pack parsing)
// code paths. Using this package prevents divergence that could lead to
// path traversal vulnerabilities or integrity ambiguity.
//
// # Security Properties
//
//   - Validates paths are within artifacts/ directory
//   - Delegates to ziputil.ValidatePath for comprehensive safety checks
//   - Returns collision keys for Windows path collision detection
//   - Single source of truth for artifact path validation
//
// # Usage
//
//	if err := packpath.ValidateArtifactPath(path); err != nil {
//	    return err
//	}
//
//	// For collision detection during manifest validation:
//	key, err := packpath.ValidateArtifactPathAndCollisionKey(path)
//	if err != nil {
//	    return err
//	}
//	if _, exists := seen[key]; exists {
//	    return errors.New("duplicate path")
//	}
//	seen[key] = true
package packpath

import (
	"fmt"
	"strings"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/ziputil"
)

const (
	// Manifest is the manifest file path at pack root.
	Manifest = "manifest.json"
	// ArtifactsDir is the artifacts directory prefix.
	ArtifactsDir = "artifacts/"
	// Attestations is the attestations directory prefix.
	Attestations = "attestations/"
	// SigstoreExt is the file extension for Sigstore bundles.
	SigstoreExt = ".sigstore.json"
)

// ValidateArtifactPath checks that a path is valid for an embedded artifact.
// This is the primary validation function for artifact paths.
//
// Requirements:
//   - Must start with "artifacts/"
//   - Must have content after "artifacts/" (not just the directory)
//   - Must pass all ziputil.ValidatePath safety checks
//
// SECURITY: Use this function for ALL artifact path validation to ensure
// consistent enforcement between builder and manifest validation.
func ValidateArtifactPath(path string) error {
	// Must start with artifacts/
	if !strings.HasPrefix(path, ArtifactsDir) {
		return errors.E(errors.InvalidPath,
			fmt.Sprintf("embedded artifact path must start with 'artifacts/': %s", path), nil)
	}

	// Must have content after artifacts/
	if path == ArtifactsDir {
		return errors.E(errors.InvalidPath,
			fmt.Sprintf("embedded artifact path cannot be just '%s'", ArtifactsDir), nil)
	}

	// Validate path safety (traversal, reserved names, encoding, etc.)
	if err := ziputil.ValidatePath(path); err != nil {
		return errors.E(errors.InvalidPath, "invalid artifact path", err)
	}

	return nil
}

// ValidateArtifactPathAndCollisionKey validates an artifact path and returns
// its Windows-canonical collision key.
//
// The collision key is used to detect paths that would collide on Windows
// due to case-insensitivity and trailing dot/space stripping:
//   - "report" and "REPORT" both become "report"
//   - "file." and "file" both become "file"
//   - "artifact " and "artifact" both become "artifact"
//
// SECURITY: Use this function when building manifest artifact maps to detect
// collisions that would cause integrity ambiguity on Windows.
//
// Example usage:
//
//	seen := make(map[string]int) // collision key -> first index
//	for i, artifact := range artifacts {
//	    key, err := packpath.ValidateArtifactPathAndCollisionKey(artifact.Path)
//	    if err != nil {
//	        return err
//	    }
//	    if firstIdx, exists := seen[key]; exists {
//	        return fmt.Errorf("collision at index %d with index %d", i, firstIdx)
//	    }
//	    seen[key] = i
//	}
func ValidateArtifactPathAndCollisionKey(path string) (collisionKey string, err error) {
	if err := ValidateArtifactPath(path); err != nil {
		return "", err
	}

	return ziputil.WindowsCanonicalPath(path), nil
}

// IsArtifactPath returns true if the path is under the artifacts/ directory.
// This is a quick check that doesn't perform full validation.
func IsArtifactPath(path string) bool {
	return strings.HasPrefix(path, ArtifactsDir) && path != ArtifactsDir
}

// IsAttestationPath returns true if the path is under the attestations/ directory.
func IsAttestationPath(path string) bool {
	return strings.HasPrefix(path, Attestations) && path != Attestations
}
