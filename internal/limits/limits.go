// Package limits defines resource bounds that prevent denial-of-service attacks.
//
// # Size Limits
//
// Size limits use the typed [SizeLimit] type to provide compile-time safety.
// Use the pre-defined limits for parsing operations:
//
//	safejson.Unmarshal(data, limits.ConfigFile, &cfg)
//	safeyaml.Unmarshal(data, limits.LockFile, &lock)
//	safejson.DecodeReader(resp.Body, "api", limits.JSONResponse, &result)
//
// All limits are derived from the evidence pack spec Section 7.2 and are
// designed to bound memory usage, prevent zip bombs, and limit subprocess output.
// Adjust with caution: relaxing limits may create resource exhaustion vectors.
package limits

import (
	"os"
	"time"
)

// SizeLimit is a typed size limit for parsing operations.
// Using a distinct type prevents accidentally passing arbitrary int64 values.
type SizeLimit int64

// Bytes returns the limit as an int64 for use with APIs that require it.
func (s SizeLimit) Bytes() int64 {
	return int64(s)
}

// Size limit constants for parsing operations.
// These are the ONLY valid values for safejson/safeyaml/safefile functions.
var (
	// ConfigFile is the limit for epack.yaml and similar config files (1 MB).
	ConfigFile SizeLimit = 1 * 1024 * 1024

	// LockFile is the limit for epack.lock.yaml (10 MB).
	// Lockfiles can be larger due to multi-platform digests.
	LockFile SizeLimit = 10 * 1024 * 1024

	// JSONResponse is the limit for JSON API responses (10 MB).
	// Use for HTTP responses, adapter outputs, etc.
	JSONResponse SizeLimit = 10 * 1024 * 1024

	// Manifest is the limit for manifest.json in packs (10 MB).
	Manifest SizeLimit = 10 * 1024 * 1024

	// Artifact is the limit for a single artifact (100 MB).
	Artifact SizeLimit = 100 * 1024 * 1024

	// Attestation is the limit for Sigstore attestation bundles (1 MB).
	Attestation SizeLimit = 1 * 1024 * 1024

	// Catalog is the limit for component catalog files (5 MB).
	Catalog SizeLimit = 5 * 1024 * 1024

	// CatalogMeta is the limit for catalog.json.meta (64 KB).
	CatalogMeta SizeLimit = 64 * 1024

	// ToolResult is the limit for tool result.json (10 MB).
	// SECURITY: Tool output is untrusted.
	ToolResult SizeLimit = 10 * 1024 * 1024

	// CollectorOutput is the limit for a single collector's stdout (64 MB).
	CollectorOutput SizeLimit = 64 * 1024 * 1024

	// AssetDownload is the limit for downloaded assets from GitHub (500 MB).
	AssetDownload SizeLimit = 500 * 1024 * 1024
)

// File permission constants for secure file operations.
// Use these instead of raw octal values.
const (
	// PrivateDirMode for directories only the owner should access (0700).
	PrivateDirMode os.FileMode = 0700

	// StandardDirMode for directories with standard access (0755).
	StandardDirMode os.FileMode = 0755

	// PrivateFileMode for files only the owner should read/write (0600).
	PrivateFileMode os.FileMode = 0600

	// StandardFileMode for files with standard read access (0644).
	StandardFileMode os.FileMode = 0644
)

// Pack size limits (not typed - used for streaming/comparison).
const (
	// MaxPackSizeBytes is the maximum total pack size (2 GB).
	MaxPackSizeBytes int64 = 2 * 1024 * 1024 * 1024

	// MaxArtifactCount is the maximum number of artifacts in a pack.
	MaxArtifactCount int = 10000

	// MaxCompressionRatio is the maximum allowed compression ratio (100:1).
	// This helps detect zip bombs.
	MaxCompressionRatio int = 100

	// MaxZipEntries is the maximum number of entries in a zip archive.
	// This prevents DoS via central directory bloat.
	MaxZipEntries int = 15000

	// MaxAttestationJSONDepth is the maximum nesting depth for attestation JSON.
	// Prevents stack overflow during parsing of maliciously nested structures.
	MaxAttestationJSONDepth int = 32
)

// Count limits for DoS prevention.
const (
	// MaxCollectorCount is the maximum number of collectors in a config/lockfile.
	MaxCollectorCount int = 1000

	// MaxToolCount is the maximum number of tools in a config/lockfile.
	MaxToolCount int = 1000

	// MaxRemoteCount is the maximum number of remotes in a config.
	MaxRemoteCount int = 100

	// MaxUtilityCount is the maximum number of utilities in a user lockfile.
	MaxUtilityCount int = 100

	// MaxPlatformCount is the maximum number of platforms per collector.
	MaxPlatformCount int = 100

	// MaxCatalogComponentCount is the maximum number of components in a catalog.
	MaxCatalogComponentCount int = 10000

	// MaxYAMLAliasExpansion is the maximum ratio of expanded size to input size.
	// YAML alias bombs can expand small inputs into huge outputs.
	MaxYAMLAliasExpansion int = 10
)

// Execution limits for DoS prevention.
const (
	// MaxAggregateOutputBytes is the maximum total bytes retained across all collector outputs (256 MB).
	MaxAggregateOutputBytes int64 = 256 * 1024 * 1024

	// DefaultSigningMemoryLimit is the default maximum memory for signing operations (256 MB).
	DefaultSigningMemoryLimit int64 = 256 * 1024 * 1024
)

// Timeout limits for network and execution operations.
// These use time.Duration for natural Go ergonomics.
const (
	// DefaultHTTPTimeout is the default timeout for HTTP requests (30 seconds).
	DefaultHTTPTimeout = 30 * time.Second

	// DefaultCollectorTimeout is the default timeout for collector execution (10 minutes).
	DefaultCollectorTimeout = 10 * time.Minute

	// DefaultToolTimeout is the default timeout for tool execution (5 minutes).
	DefaultToolTimeout = 5 * time.Minute

	// MaxHTTPRedirects is the maximum number of HTTP redirects to follow.
	MaxHTTPRedirects = 10
)

// Recursion and depth limits for DoS prevention.
const (
	// MaxRecursionDepth is the maximum depth for recursive operations.
	MaxRecursionDepth = 100

	// MaxMergeNestingDepth is the maximum nesting depth for merged packs.
	MaxMergeNestingDepth = 10
)
