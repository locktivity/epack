package sign

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/digest"
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/packpath"
	"github.com/locktivity/epack/internal/safefile"
	"github.com/locktivity/epack/internal/ziputil"
	"github.com/locktivity/epack/pack"
)

// MemoryLimitOptions configures memory limits for signing operations.
// This is separate from SignPackOptions which configures authentication.
type MemoryLimitOptions struct {
	// MaxMemoryBytes limits memory for in-memory snapshot.
	// Defaults to DefaultSigningMemoryLimit (256 MB).
	// Total memory ≈ MaxMemoryBytes × concurrent_requests.
	MaxMemoryBytes int64
}

// SignPackFile signs an evidence pack and writes the attestation back to it.
// Uses DefaultSigningMemoryLimit; use SignPackFileWithOptions for larger packs.
func SignPackFile(ctx context.Context, packPath string, s Signer) error {
	return SignPackFileWithOptions(ctx, packPath, s, MemoryLimitOptions{})
}

// SignPackFileWithOptions signs a pack with configurable memory limits.
// Attestation is written to attestations/{sha256(identity)}.sigstore.json.
// TOCTOU-safe: snapshots pack, verifies integrity, then writes from snapshot.
func SignPackFileWithOptions(ctx context.Context, packPath string, s Signer, opts MemoryLimitOptions) error {
	if s == nil {
		return errors.E(errors.InvalidInput, "signer cannot be nil", nil)
	}

	snapshot, manifest, err := loadSigningSnapshot(packPath, effectiveSigningMemoryLimit(opts))
	if err != nil {
		return err
	}
	statementJSON, filename, err := buildSigningPayload(manifest, s.Identity())
	if err != nil {
		return err
	}
	bundleJSON, err := signPayload(ctx, s, statementJSON)
	if err != nil {
		return err
	}
	if err := writeZipFromSnapshot(packPath, snapshot, filename, bundleJSON); err != nil {
		return fmt.Errorf("adding attestation to pack: %w", err)
	}
	return nil
}

func effectiveSigningMemoryLimit(opts MemoryLimitOptions) int64 {
	if opts.MaxMemoryBytes > 0 {
		return opts.MaxMemoryBytes
	}
	return limits.DefaultSigningMemoryLimit
}

func loadSigningSnapshot(packPath string, maxMemory int64) (map[string]*snapshotEntry, *pack.Manifest, error) {
	p, err := pack.Open(packPath)
	if err != nil {
		return nil, nil, fmt.Errorf("opening pack: %w", err)
	}
	defer func() { _ = p.Close() }()

	zipReader := p.Zip()
	if zipReader == nil {
		return nil, nil, errors.E(errors.InvalidInput, "pack was not opened from a file", nil)
	}

	snapshot, err := snapshotZipContentsWithLimit(zipReader, maxMemory)
	if err != nil {
		return nil, nil, fmt.Errorf("snapshotting pack contents: %w", err)
	}

	manifest, err := verifySnapshotIntegrity(snapshot)
	if err != nil {
		return nil, nil, fmt.Errorf("pack integrity check failed (refusing to sign): %w", err)
	}
	return snapshot, manifest, nil
}

func buildSigningPayload(manifest *pack.Manifest, identity string) ([]byte, string, error) {
	statement, err := NewStatement(manifest.PackDigest, manifest.Stream)
	if err != nil {
		return nil, "", err
	}

	statementJSON, err := json.Marshal(statement)
	if err != nil {
		return nil, "", fmt.Errorf("marshaling statement: %w", err)
	}
	filename, err := safeAttestationFilename(identity)
	if err != nil {
		return nil, "", fmt.Errorf("invalid signer identity: %w", err)
	}
	return statementJSON, filename, nil
}

func signPayload(ctx context.Context, s Signer, statementJSON []byte) ([]byte, error) {
	bundle, err := s.Sign(ctx, statementJSON)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	if bundle == nil {
		return nil, errors.E(errors.InvalidInput, "signer returned nil bundle", nil)
	}
	bundleJSON, err := MarshalBundle(bundle)
	if err != nil {
		return nil, fmt.Errorf("marshaling bundle: %w", err)
	}
	return bundleJSON, nil
}

// snapshotEntry holds a single file's contents and metadata from a zip archive.
type snapshotEntry struct {
	header  zip.FileHeader
	content []byte
}

// snapshotZipContentsWithLimit reads all file contents into memory.
// Enforces per-entry and aggregate size limits.
func snapshotZipContentsWithLimit(zr *zip.Reader, maxTotalBytes int64) (map[string]*snapshotEntry, error) {
	if len(zr.File) > limits.MaxZipEntries {
		return nil, errors.E(errors.ZipBomb,
			fmt.Sprintf("zip entry count %d exceeds limit %d", len(zr.File), limits.MaxZipEntries), nil)
	}

	// SECURITY: Validate compression ratios before reading any content.
	// This prevents memory exhaustion from zip bombs.
	if err := ziputil.CheckCompressionRatio(zr, limits.MaxCompressionRatio); err != nil {
		return nil, err
	}

	perEntryLimit := limits.Artifact.Bytes()
	if maxTotalBytes < perEntryLimit {
		perEntryLimit = maxTotalBytes
	}

	snapshot := make(map[string]*snapshotEntry)
	var totalBytes int64

	for _, f := range zr.File {
		if f.Mode().IsDir() {
			continue
		}
		content, err := readSnapshotEntry(f, perEntryLimit, maxTotalBytes-totalBytes, maxTotalBytes)
		if err != nil {
			return nil, err
		}
		totalBytes += int64(len(content))
		snapshot[f.Name] = &snapshotEntry{header: f.FileHeader, content: content}
	}
	return snapshot, nil
}

func readSnapshotEntry(f *zip.File, perEntryLimit, remaining, maxTotalBytes int64) ([]byte, error) {
	if f.UncompressedSize64 > uint64(perEntryLimit) {
		return nil, errors.E(errors.ArtifactTooLarge,
			fmt.Sprintf("entry %q declared size %d exceeds limit %d", f.Name, f.UncompressedSize64, perEntryLimit), nil)
	}
	if remaining <= 0 {
		return nil, errors.E(errors.ZipBomb,
			fmt.Sprintf("aggregate size exceeds signing memory limit %d bytes", maxTotalBytes), nil)
	}

	reader, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", f.Name, err)
	}
	defer func() { _ = reader.Close() }()

	readLimit := perEntryLimit + 1
	if remaining < readLimit {
		readLimit = remaining + 1
	}
	content, err := io.ReadAll(io.LimitReader(reader, readLimit))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", f.Name, err)
	}
	if int64(len(content)) > perEntryLimit {
		return nil, errors.E(errors.ArtifactTooLarge,
			fmt.Sprintf("entry %q exceeds size limit %d bytes", f.Name, perEntryLimit), nil)
	}
	if int64(len(content)) > remaining {
		return nil, errors.E(errors.ZipBomb,
			fmt.Sprintf("aggregate size exceeds signing memory limit %d bytes", maxTotalBytes), nil)
	}
	return content, nil
}

// verifySnapshotIntegrity verifies pack integrity against snapshot bytes.
func verifySnapshotIntegrity(snapshot map[string]*snapshotEntry) (*pack.Manifest, error) {
	manifest, err := parseSnapshotManifest(snapshot)
	if err != nil {
		return nil, err
	}
	declaredArtifacts, err := verifyManifestDeclaredArtifacts(snapshot, manifest)
	if err != nil {
		return nil, err
	}
	if err := rejectUndeclaredSnapshotArtifacts(snapshot, declaredArtifacts); err != nil {
		return nil, err
	}
	if err := validateSnapshotFileSet(snapshot); err != nil {
		return nil, err
	}
	if err := verifySnapshotPackDigest(manifest); err != nil {
		return nil, err
	}
	return manifest, nil
}

// writeZipFromSnapshot writes a new zip from snapshot, adding the attestation.
// Uses TOCTOU-safe operations to prevent symlink race attacks where an attacker
// swaps parent directory components during the write flow.
func writeZipFromSnapshot(zipPath string, snapshot map[string]*snapshotEntry, attestationName string, attestationContent []byte) error {
	baseDir, targetPath, dir, err := resolveSnapshotWritePaths(zipPath)
	if err != nil {
		return err
	}
	tempFile, tempPath, err := createTempSnapshotFile(dir)
	if err != nil {
		return err
	}

	success := false
	defer func() {
		if !success {
			_ = os.Remove(tempPath)
		}
	}()

	zipWriter := zip.NewWriter(tempFile)
	defer func() {
		if !success {
			_ = zipWriter.Close() // Error intentionally ignored in cleanup path
			_ = tempFile.Close()  // Error intentionally ignored in cleanup path
		}
	}()

	if err := writeSnapshotZip(zipWriter, snapshot, attestationName, attestationContent); err != nil {
		return err
	}
	if err := closeSnapshotWriters(zipWriter, tempFile); err != nil {
		return err
	}
	if err := safefile.Rename(baseDir, tempPath, targetPath); err != nil {
		return fmt.Errorf("replacing original zip: %w", err)
	}
	success = true
	return nil
}

func parseSnapshotManifest(snapshot map[string]*snapshotEntry) (*pack.Manifest, error) {
	manifestEntry, ok := snapshot[packpath.Manifest]
	if !ok {
		return nil, errors.E(errors.MissingEntry, packpath.Manifest+" not found in snapshot", nil)
	}
	manifest, err := pack.ParseManifest(manifestEntry.content)
	if err != nil {
		return nil, fmt.Errorf("parsing manifest: %w", err)
	}
	return manifest, nil
}

func verifyManifestDeclaredArtifacts(snapshot map[string]*snapshotEntry, manifest *pack.Manifest) (map[string]struct{}, error) {
	declaredArtifacts := make(map[string]struct{})
	for _, artifact := range manifest.Artifacts {
		if artifact.Type != "embedded" {
			continue
		}
		if !strings.HasPrefix(artifact.Path, packpath.ArtifactsDir) {
			return nil, errors.E(errors.InvalidPath,
				fmt.Sprintf("artifact path %q not under %s", artifact.Path, packpath.ArtifactsDir), nil)
		}
		entry, ok := snapshot[artifact.Path]
		if !ok {
			return nil, errors.E(errors.MissingEntry,
				fmt.Sprintf("artifact %q in manifest not found in snapshot", artifact.Path), nil)
		}
		if err := verifySnapshotArtifactEntry(artifact, entry); err != nil {
			return nil, err
		}
		declaredArtifacts[artifact.Path] = struct{}{}
	}
	return declaredArtifacts, nil
}

func verifySnapshotArtifactEntry(artifact pack.Artifact, entry *snapshotEntry) error {
	if artifact.Size != nil {
		expectedSize, err := artifact.Size.Int64()
		if err != nil {
			return errors.E(errors.InvalidManifest,
				fmt.Sprintf("artifact %q has invalid size", artifact.Path), err)
		}
		if int64(len(entry.content)) != expectedSize {
			return errors.E(errors.SizeMismatch,
				fmt.Sprintf("artifact %q size mismatch: manifest %d, actual %d", artifact.Path, expectedSize, len(entry.content)), nil)
		}
	}
	computedDigest := digest.FromBytes(entry.content)
	expectedDigest, err := digest.Parse(artifact.Digest)
	if err != nil {
		return errors.E(errors.InvalidManifest,
			fmt.Sprintf("artifact %q has invalid digest format in manifest", artifact.Path), err)
	}
	if !computedDigest.Equal(expectedDigest) {
		return errors.E(errors.DigestMismatch,
			fmt.Sprintf("artifact %q digest mismatch: expected %s", artifact.Path, artifact.Digest), nil)
	}
	return nil
}

func rejectUndeclaredSnapshotArtifacts(snapshot map[string]*snapshotEntry, declaredArtifacts map[string]struct{}) error {
	for path := range snapshot {
		if !strings.HasPrefix(path, packpath.ArtifactsDir) {
			continue
		}
		if _, declared := declaredArtifacts[path]; !declared {
			return errors.E(errors.InvalidManifest,
				fmt.Sprintf("artifact %q in snapshot not declared in manifest", path), nil)
		}
	}
	return nil
}

func validateSnapshotFileSet(snapshot map[string]*snapshotEntry) error {
	for path := range snapshot {
		switch {
		case path == packpath.Manifest:
		case strings.HasPrefix(path, packpath.ArtifactsDir):
		case strings.HasPrefix(path, packpath.Attestations):
			if !strings.HasSuffix(path, packpath.SigstoreExt) {
				return errors.E(errors.InvalidPath,
					fmt.Sprintf("invalid attestation file %q: must end with %s", path, packpath.SigstoreExt), nil)
			}
			remainder := strings.TrimPrefix(path, packpath.Attestations)
			if strings.Contains(remainder, "/") {
				return errors.E(errors.InvalidPath,
					fmt.Sprintf("invalid attestation path %q: must be direct child of %s", path, packpath.Attestations), nil)
			}
		default:
			return errors.E(errors.InvalidPath, fmt.Sprintf("unexpected file %q in pack", path), nil)
		}
	}
	return nil
}

func verifySnapshotPackDigest(manifest *pack.Manifest) error {
	canonical := pack.BuildCanonicalArtifactList(manifest)
	computedPackDigest := pack.HashCanonicalList(canonical)
	if computedPackDigest != manifest.PackDigest {
		return errors.E(errors.DigestMismatch,
			fmt.Sprintf("pack_digest mismatch: expected %s", manifest.PackDigest), nil)
	}
	return nil
}

func resolveSnapshotWritePaths(zipPath string) (baseDir, targetPath, dir string, err error) {
	absZipPath, err := filepath.Abs(zipPath)
	if err != nil {
		return "", "", "", fmt.Errorf("resolving zip path: %w", err)
	}
	dir = filepath.Dir(absZipPath)
	baseDir = filepath.Dir(dir)
	if baseDir == "" {
		baseDir = "/"
	}
	return baseDir, filepath.Join(dir, filepath.Base(absZipPath)), dir, nil
}

func createTempSnapshotFile(dir string) (*os.File, string, error) {
	tempFile, err := os.CreateTemp(dir, "pack-*.zip")
	if err != nil {
		return nil, "", fmt.Errorf("creating temp file: %w", err)
	}
	return tempFile, tempFile.Name(), nil
}

func writeSnapshotZip(zipWriter *zip.Writer, snapshot map[string]*snapshotEntry, attestationName string, attestationContent []byte) error {
	for _, dirPath := range []string{packpath.ArtifactsDir, packpath.Attestations} {
		if _, err := zipWriter.Create(dirPath); err != nil {
			return fmt.Errorf("creating directory %s: %w", dirPath, err)
		}
	}

	names := make([]string, 0, len(snapshot))
	for name := range snapshot {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		if name == attestationName {
			continue
		}
		if err := writeSnapshotEntry(zipWriter, name, snapshot[name]); err != nil {
			return fmt.Errorf("writing %s: %w", name, err)
		}
	}
	w, err := zipWriter.Create(attestationName)
	if err != nil {
		return fmt.Errorf("creating attestation in zip: %w", err)
	}
	if _, err := w.Write(attestationContent); err != nil {
		return fmt.Errorf("writing attestation: %w", err)
	}
	return nil
}

func closeSnapshotWriters(zipWriter *zip.Writer, tempFile *os.File) error {
	if err := zipWriter.Close(); err != nil {
		return fmt.Errorf("closing zip writer: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}
	return nil
}

func writeSnapshotEntry(zw *zip.Writer, name string, entry *snapshotEntry) error {
	header := entry.header
	header.Name = name
	writer, err := zw.CreateHeader(&header)
	if err != nil {
		return err
	}
	n, err := writer.Write(entry.content)
	if err != nil {
		return err
	}
	if n != len(entry.content) {
		return fmt.Errorf("short write: wrote %d of %d bytes for %s", n, len(entry.content), name)
	}
	return nil
}

// safeAttestationFilename returns attestations/{sha256(identity)}.sigstore.json.
func safeAttestationFilename(identity string) (string, error) {
	if identity == "" {
		return "", errors.E(errors.InvalidInput, "signer identity cannot be empty", nil)
	}
	h := sha256.Sum256([]byte(identity))
	return packpath.Attestations + hex.EncodeToString(h[:]) + packpath.SigstoreExt, nil
}
