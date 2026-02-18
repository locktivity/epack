package sync

import (
	"os"
	"path/filepath"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/exitcode"
	"github.com/locktivity/epack/internal/safefile"
)

// insecureMarkerFile is the filename for the insecure install marker.
const insecureMarkerFile = ".insecure-install"

// HasInsecureMarker checks if the given install directory has the insecure marker.
func HasInsecureMarker(installDir string) bool {
	markerPath := filepath.Join(installDir, insecureMarkerFile)
	_, err := os.Stat(markerPath)
	return err == nil
}

// ClearInsecureMarker removes the insecure install marker from the given directory.
// This is called after a secure verification to remove stale markers.
// Errors are ignored since the marker may not exist.
func ClearInsecureMarker(installDir string) {
	markerPath := filepath.Join(installDir, insecureMarkerFile)
	_ = os.Remove(markerPath) // ignore error - marker may not exist
}

// WriteInsecureMarker creates the insecure install marker in the given directory.
// Uses safefile.WriteFilePrivate to refuse to follow symlinks (O_NOFOLLOW).
//
// SECURITY: All errors are returned, not just symlink errors.
// If the marker cannot be written (disk full, permissions, etc.), the caller
// must not proceed with the insecure installation, otherwise the install will
// appear legitimate to HasInsecureMarker() checks later.
func WriteInsecureMarker(installDir string) error {
	content := []byte("installed with --insecure-skip-verify\n")
	return safefile.WriteFilePrivate(installDir, insecureMarkerFile, content)
}

// CheckInsecureMarkerAllowed checks if executing a component with an insecure marker is allowed.
// Returns nil if allowed, or an error if the marker exists and execution is disallowed.
//
// Policy:
//   - In frozen mode: never allowed (security requirement)
//   - In non-frozen mode: requires allowInsecure=true
func CheckInsecureMarkerAllowed(name string, kind componenttypes.ComponentKind, binaryPath string, frozen, allowInsecure bool) error {
	installDir := filepath.Dir(binaryPath)
	if !HasInsecureMarker(installDir) {
		return nil
	}

	kindStr := kind.String()
	if frozen {
		return errors.WithHint(errors.InsecureInstall, exitcode.General,
			kindStr+" \""+name+"\" was installed with --insecure-skip-verify",
			"Run 'epack sync' without --insecure-skip-verify", nil)
	}
	if !allowInsecure {
		return errors.WithHint(errors.InsecureInstall, exitcode.General,
			kindStr+" \""+name+"\" was installed with --insecure-skip-verify",
			"Run 'epack sync' without --insecure-skip-verify, or use --insecure-allow-unverified", nil)
	}
	return nil
}
