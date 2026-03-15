package pull

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"runtime"
	"time"

	"github.com/locktivity/epack/internal/remote"
	"github.com/locktivity/epack/internal/safefile"
	"github.com/locktivity/epack/internal/validate"
	"github.com/locktivity/epack/internal/version"
)

// Receipt records the result of a pull operation for audit purposes.
type Receipt struct {
	// ReceiptVersion is the receipt format version.
	ReceiptVersion int `json:"receipt_version"`

	// CreatedAt is when the receipt was created.
	CreatedAt time.Time `json:"created_at"`

	// Remote is the remote name used for the pull.
	Remote string `json:"remote"`

	// Target contains the workspace/environment.
	Target remote.TargetConfig `json:"target"`

	// Pack contains pack metadata.
	Pack PackReceipt `json:"pack"`

	// Verified indicates whether the pack was verified after download.
	Verified bool `json:"verified"`

	// Client contains epack client metadata.
	Client ClientReceipt `json:"client"`
}

// PackReceipt contains pack metadata in the receipt.
type PackReceipt struct {
	OutputPath string    `json:"output_path"`
	Digest     string    `json:"digest"`
	SizeBytes  int64     `json:"size_bytes"`
	Stream     string    `json:"stream"`
	CreatedAt  time.Time `json:"created_at"`
	ReleaseID  string    `json:"release_id,omitempty"`
	Version    string    `json:"version,omitempty"`
	Labels     []string  `json:"labels,omitempty"`
}

// ClientReceipt contains epack client metadata in the receipt.
type ClientReceipt struct {
	EpackVersion string `json:"epack_version"`
	OS           string `json:"os"`
	Arch         string `json:"arch"`
}

// ReceiptWriter writes pull receipts to disk.
type ReceiptWriter struct {
	// BaseDir is the base directory for receipts.
	// Defaults to .epack/receipts/pull if empty.
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
		baseDir = ".epack/receipts/pull"
	}
	if err := safefile.EnsureBaseDir(baseDir); err != nil {
		return "", fmt.Errorf("ensuring receipt base directory: %w", err)
	}

	// SECURITY: Validate remote name to prevent path traversal.
	// Remote names come from user configuration and could contain "../" sequences.
	if err := validate.PathComponent(receipt.Remote); err != nil {
		return "", fmt.Errorf("invalid remote name %q: %w", receipt.Remote, err)
	}

	// Generate filename: <timestamp>_<shortdigest>.json
	timestamp := receipt.CreatedAt.Format("20060102_150405")
	shortDigest := shortDigestSuffix(receipt.Pack.Digest)
	filename := fmt.Sprintf("%s_%s.json", timestamp, shortDigest)

	// Build relative and absolute paths: <baseDir>/<remote>/<filename>
	relPath := filepath.Join(receipt.Remote, filename)
	path := filepath.Join(baseDir, relPath)

	// Marshal receipt to JSON
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshaling receipt: %w", err)
	}

	// SECURITY: Use safefile.WriteFile for TOCTOU-safe directory creation
	// and file writing. This prevents symlink attacks where an attacker swaps
	// a directory for a symlink between MkdirAll and WriteFile.
	if err := safefile.WriteFile(baseDir, relPath, data); err != nil {
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

// NewReceipt creates a new receipt from pull result data.
func NewReceipt(
	remoteName string,
	target remote.TargetConfig,
	outputPath string,
	packMeta *remote.PackMetadata,
	verified bool,
) *Receipt {
	return &Receipt{
		ReceiptVersion: 1,
		CreatedAt:      time.Now().UTC(),
		Remote:         remoteName,
		Target:         target,
		Pack: PackReceipt{
			OutputPath: outputPath,
			Digest:     packMeta.Digest,
			SizeBytes:  packMeta.SizeBytes,
			Stream:     packMeta.Stream,
			CreatedAt:  packMeta.CreatedAt,
			ReleaseID:  packMeta.ReleaseID,
			Version:    packMeta.Version,
			Labels:     packMeta.Labels,
		},
		Verified: verified,
		Client: ClientReceipt{
			EpackVersion: version.Version,
			OS:           runtime.GOOS,
			Arch:         runtime.GOARCH,
		},
	}
}
