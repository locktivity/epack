package packpath

import "strings"

// PackExtension is the standard file extension for evidence packs.
const PackExtension = ".epack"

// SidecarSuffix is the suffix used for pack sidecar directories.
// Sidecar directories contain tool runs and other pack-local derived data.
const SidecarSuffix = ".runs"

// SidecarDir returns the sidecar directory path for a pack.
// It strips the .epack extension (if present) before adding the .runs suffix.
//
// Examples:
//
//	sample.epack -> sample.runs
//	evidence     -> evidence.runs
//	/path/to/vendor.epack -> /path/to/vendor.runs
func SidecarDir(packPath string) string {
	base := strings.TrimSuffix(packPath, PackExtension)
	return base + SidecarSuffix
}
