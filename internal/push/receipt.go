package push

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/locktivity/epack/internal/remote"
	"github.com/locktivity/epack/internal/safefile"
	"github.com/locktivity/epack/internal/validate"
	"github.com/locktivity/epack/internal/version"
)

// Receipt records the result of a push operation for audit purposes.
type Receipt struct {
	// ReceiptVersion is the receipt format version.
	ReceiptVersion int `json:"receipt_version"`

	// CreatedAt is when the receipt was created.
	CreatedAt time.Time `json:"created_at"`

	// Remote is the remote name used for the push.
	Remote string `json:"remote"`

	// Target contains the workspace/environment.
	Target remote.TargetConfig `json:"target"`

	// Pack contains pack metadata.
	Pack PackReceipt `json:"pack"`

	// Release contains the release information from the remote.
	Release ReleaseReceipt `json:"release"`

	// Links contains URLs returned by the remote.
	Links map[string]string `json:"links,omitempty"`

	// Runs contains run syncing results.
	Runs RunsReceipt `json:"runs"`

	// Client contains epack client metadata.
	Client ClientReceipt `json:"client"`
}

// PackReceipt contains pack metadata in the receipt.
type PackReceipt struct {
	Path      string `json:"path"`
	Digest    string `json:"digest"`
	SizeBytes int64  `json:"size_bytes"`
}

// ReleaseReceipt contains release information in the receipt.
type ReleaseReceipt struct {
	ReleaseID    string    `json:"release_id"`
	PackDigest   string    `json:"pack_digest"`
	CreatedAt    time.Time `json:"created_at"`
	CanonicalRef string    `json:"canonical_ref"`
}

// RunsReceipt contains run syncing results in the receipt.
type RunsReceipt struct {
	Synced []string `json:"synced"`
	Failed []string `json:"failed"`
}

// ClientReceipt contains epack client metadata in the receipt.
type ClientReceipt struct {
	EpackVersion string `json:"epack_version"`
	OS           string `json:"os"`
	Arch         string `json:"arch"`
}

// ReceiptWriter writes push receipts to disk.
type ReceiptWriter struct {
	// BaseDir is the base directory for receipts.
	// Defaults to .epack/receipts/push if empty.
	BaseDir string
}

// Write writes a receipt to disk.
// Returns the path to the written receipt file.
//
// SECURITY: This function validates the remote name to prevent path traversal attacks
// and uses TOCTOU-safe file operations to prevent symlink attacks.
func (w *ReceiptWriter) Write(receipt *Receipt) (string, error) {
	baseDir := w.BaseDir
	if baseDir == "" {
		baseDir = ".epack/receipts/push"
	}

	// SECURITY: Validate remote name to prevent path traversal.
	// Remote names come from user configuration and could contain "../" sequences.
	if err := validate.PathComponent(receipt.Remote); err != nil {
		return "", fmt.Errorf("invalid remote name %q: %w", receipt.Remote, err)
	}

	// Ensure base directory exists (this is trusted, created by us)
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return "", fmt.Errorf("creating receipt base directory: %w", err)
	}

	// Generate filename: <timestamp>_<shortdigest>.json
	timestamp := receipt.CreatedAt.Format("20060102_150405")
	shortDigest := shortDigestSuffix(receipt.Pack.Digest)
	filename := fmt.Sprintf("%s_%s.json", timestamp, shortDigest)

	// Build full path: <baseDir>/<remote>/<filename>
	remoteDir := filepath.Join(baseDir, receipt.Remote)
	path := filepath.Join(remoteDir, filename)

	// Marshal receipt to JSON
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshaling receipt: %w", err)
	}

	// SECURITY: Use safefile.WriteFile for TOCTOU-safe directory creation
	// and file writing. This prevents symlink attacks where an attacker swaps
	// a directory for a symlink between MkdirAll and WriteFile.
	if err := safefile.WriteFile(baseDir, path, data); err != nil {
		return "", fmt.Errorf("writing receipt: %w", err)
	}

	return path, nil
}

// shortDigestSuffix extracts a short suffix from a digest for filename use.
// Example: "sha256:abc123def456..." -> "abc123de"
func shortDigestSuffix(digest string) string {
	// Remove algorithm prefix if present
	if idx := len("sha256:"); len(digest) > idx && digest[:idx] == "sha256:" {
		digest = digest[idx:]
	}
	// Take first 8 characters
	if len(digest) > 8 {
		return digest[:8]
	}
	return digest
}

// NewReceipt creates a new receipt from push result data.
func NewReceipt(
	remoteName string,
	target remote.TargetConfig,
	packPath string,
	packDigest string,
	packSize int64,
	release *remote.ReleaseResult,
	links map[string]string,
	syncedRuns []string,
	failedRuns []string,
) *Receipt {
	return &Receipt{
		ReceiptVersion: 1,
		CreatedAt:      time.Now().UTC(),
		Remote:         remoteName,
		Target:         target,
		Pack: PackReceipt{
			Path:      packPath,
			Digest:    packDigest,
			SizeBytes: packSize,
		},
		Release: ReleaseReceipt{
			ReleaseID:    release.ReleaseID,
			PackDigest:   release.PackDigest,
			CreatedAt:    release.CreatedAt,
			CanonicalRef: release.CanonicalRef,
		},
		Links: links,
		Runs: RunsReceipt{
			Synced: syncedRuns,
			Failed: failedRuns,
		},
		Client: ClientReceipt{
			EpackVersion: version.Version,
			OS:           runtime.GOOS,
			Arch:         runtime.GOARCH,
		},
	}
}
