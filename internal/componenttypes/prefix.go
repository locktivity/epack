// Package componenttypes defines shared types for component management.
// This file defines binary name prefixes per C-001 naming convention.
package componenttypes

import "os"

// Binary name prefixes per C-001 naming convention.
// All component binaries must use these prefixes for discovery.
const (
	// CollectorBinaryPrefix is the prefix for collector binaries.
	CollectorBinaryPrefix = "epack-collector-"

	// ToolBinaryPrefix is the prefix for tool binaries.
	ToolBinaryPrefix = "epack-tool-"

	// RemoteBinaryPrefix is the prefix for remote adapter binaries.
	RemoteBinaryPrefix = "epack-remote-"

	// UtilityBinaryPrefix is the prefix for utility binaries.
	UtilityBinaryPrefix = "epack-util-"
)

// BinaryPrefix returns the binary name prefix for the given component kind.
func BinaryPrefix(kind ComponentKind) string {
	switch kind {
	case KindCollector:
		return CollectorBinaryPrefix
	case KindTool:
		return ToolBinaryPrefix
	case KindRemote:
		return RemoteBinaryPrefix
	case KindUtility:
		return UtilityBinaryPrefix
	default:
		return "epack-" + string(kind) + "-"
	}
}

// BinaryName returns the full binary name for a component.
func BinaryName(kind ComponentKind, name string) string {
	return BinaryPrefix(kind) + name
}

// InsecureAllowUnpinnedEnvVar is the environment variable that allows
// unpinned component execution when set to "true" or "1".
const InsecureAllowUnpinnedEnvVar = "EPACK_INSECURE_ALLOW_UNPINNED"

// InsecureAllowUnpinnedFromEnv returns true if the environment variable
// EPACK_INSECURE_ALLOW_UNPINNED is set to "true" or "1".
func InsecureAllowUnpinnedFromEnv() bool {
	v := os.Getenv(InsecureAllowUnpinnedEnvVar)
	return v == "true" || v == "1"
}
