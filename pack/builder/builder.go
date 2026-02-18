// Package builder creates evidence packs.
//
// A Builder constructs evidence packs by adding artifacts and sources,
// computing digests, generating a manifest, and creating the ZIP archive.
//
// Example:
//
//	b := builder.New("my-org/prod")
//	b.AddSource("github", "1.0.0")
//	b.AddFile("artifacts/config.json", "/path/to/config.json")
//	if err := b.Build("pack.zip"); err != nil {
//	    log.Fatal(err)
//	}
//
// For signing, call sign.SignPackFile after Build:
//
//	if err := b.Build("pack.zip"); err != nil { ... }
//	if err := sign.SignPackFile(ctx, "pack.zip", signer); err != nil { ... }
package builder

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/boundedio"
	"github.com/locktivity/epack/internal/digest"
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/packpath"
	"github.com/locktivity/epack/internal/safefile"
	"github.com/locktivity/epack/internal/timestamp"
	"github.com/locktivity/epack/pack"
)

// Builder constructs evidence packs.
type Builder struct {
	stream     string
	sources    []pack.Source
	artifacts  []artifact
	provenance *pack.Provenance
}

// artifact holds pending artifact data before building.
type artifact struct {
	path        string   // Path in the pack (e.g., "artifacts/config.json")
	data        []byte   // Content bytes
	contentType string   // Optional MIME type
	displayName string   // Optional display name
	description string   // Optional description
	collectedAt string   // Optional timestamp
	schema      string   // Optional schema identifier
	controls    []string // Optional control IDs
}

// New creates a new Builder for the given stream identifier.
// The stream identifies the evidence stream (e.g., "my-org/prod").
func New(stream string) *Builder {
	return &Builder{
		stream: stream,
	}
}

// AddSource adds a source collector to the manifest.
// Sources are informational and do not affect verification.
func (b *Builder) AddSource(name, version string) *Builder {
	b.sources = append(b.sources, pack.Source{Name: name, Version: version})
	return b
}

// SetProvenance sets the provenance for the manifest.
// Use this when creating merged packs to document source packs.
func (b *Builder) SetProvenance(prov pack.Provenance) *Builder {
	b.provenance = &prov
	return b
}

// ArtifactOptions contains optional metadata for an artifact.
type ArtifactOptions struct {
	ContentType string   // MIME type (e.g., "application/json")
	DisplayName string   // Human-readable name
	Description string   // Description of the artifact
	CollectedAt string   // Timestamp when collected (YYYY-MM-DDTHH:MM:SSZ)
	Schema      string   // Schema identifier
	Controls    []string // Control IDs this artifact supports
}

// AddArtifact adds an artifact from in-memory bytes with auto-prefixed path.
// The name is automatically prefixed with "artifacts/" (e.g., "config.json"
// becomes "artifacts/config.json").
//
// This is a convenience wrapper around AddBytes for the common case where
// all artifacts go in the artifacts/ directory.
func (b *Builder) AddArtifact(name string, data []byte) error {
	return b.AddArtifactWithOptions(name, data, ArtifactOptions{})
}

// AddArtifactWithOptions adds an artifact with auto-prefixed path and metadata.
// The name is automatically prefixed with "artifacts/".
func (b *Builder) AddArtifactWithOptions(name string, data []byte, opts ArtifactOptions) error {
	return b.AddBytesWithOptions(packpath.ArtifactsDir+name, data, opts)
}

// AddArtifactFile adds an artifact from a file with auto-prefixed path.
// The name is automatically prefixed with "artifacts/" (e.g., "config.json"
// becomes "artifacts/config.json").
//
// This is a convenience wrapper around AddFile for the common case where
// all artifacts go in the artifacts/ directory.
func (b *Builder) AddArtifactFile(name, filePath string) error {
	return b.AddArtifactFileWithOptions(name, filePath, ArtifactOptions{})
}

// AddArtifactFileWithOptions adds an artifact from a file with auto-prefixed path
// and metadata options.
func (b *Builder) AddArtifactFileWithOptions(name, filePath string, opts ArtifactOptions) error {
	return b.AddFileWithOptions(packpath.ArtifactsDir+name, filePath, opts)
}

// AddArtifactReader adds an artifact from an io.Reader with auto-prefixed path.
// The name is automatically prefixed with "artifacts/".
func (b *Builder) AddArtifactReader(name string, r io.Reader) error {
	return b.AddArtifactReaderWithOptions(name, r, ArtifactOptions{})
}

// AddArtifactReaderWithOptions adds an artifact from a reader with auto-prefixed
// path and metadata options.
func (b *Builder) AddArtifactReaderWithOptions(name string, r io.Reader, opts ArtifactOptions) error {
	return b.AddReaderWithOptions(packpath.ArtifactsDir+name, r, opts)
}

// AddFile adds an artifact from a file on disk.
// The path must start with "artifacts/" per the spec.
// The file size is checked before reading to prevent memory exhaustion.
func (b *Builder) AddFile(artifactPath, filePath string) error {
	return b.AddFileWithOptions(artifactPath, filePath, ArtifactOptions{})
}

// AddFileWithOptions adds an artifact from a file with metadata options.
// The file is opened once and size-checked via Fstat to prevent TOCTOU races.
func (b *Builder) AddFileWithOptions(artifactPath, filePath string, opts ArtifactOptions) error {
	data, err := boundedio.ReadFileWithLimit(filePath, limits.Artifact)
	if err != nil {
		if boundedio.IsBoundedReadError(err) {
			return errors.E(errors.ArtifactTooLarge,
				fmt.Sprintf("file %q exceeds artifact size limit (%d bytes)",
					filePath, limits.Artifact.Bytes()), err)
		}
		return fmt.Errorf("reading file %q: %w", filePath, err)
	}

	return b.AddBytesWithOptions(artifactPath, data, opts)
}

// AddBytes adds an artifact from in-memory bytes.
// The path must start with "artifacts/" per the spec.
func (b *Builder) AddBytes(path string, data []byte) error {
	return b.AddBytesWithOptions(path, data, ArtifactOptions{})
}

// AddBytesWithOptions adds an artifact from bytes with metadata options.
func (b *Builder) AddBytesWithOptions(path string, data []byte, opts ArtifactOptions) error {
	if err := b.validateArtifactPath(path); err != nil {
		return err
	}

	// Check for duplicates
	for _, a := range b.artifacts {
		if a.path == path {
			return errors.E(errors.DuplicatePath,
				fmt.Sprintf("duplicate artifact path: %q", path), nil)
		}
	}

	// Check size limit
	if int64(len(data)) > limits.Artifact.Bytes() {
		return errors.E(errors.ArtifactTooLarge,
			fmt.Sprintf("artifact %q exceeds size limit (%d > %d bytes)",
				path, len(data), limits.Artifact.Bytes()), nil)
	}

	// Defensive copy of caller-owned slices to prevent mutation after call
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	var controlsCopy []string
	if len(opts.Controls) > 0 {
		controlsCopy = make([]string, len(opts.Controls))
		copy(controlsCopy, opts.Controls)
	}

	b.artifacts = append(b.artifacts, artifact{
		path:        path,
		data:        dataCopy,
		contentType: opts.ContentType,
		displayName: opts.DisplayName,
		description: opts.Description,
		collectedAt: opts.CollectedAt,
		schema:      opts.Schema,
		controls:    controlsCopy,
	})

	return nil
}

// AddReader adds an artifact from an io.Reader.
// The entire content is read into memory. Use AddFile for large files.
func (b *Builder) AddReader(path string, r io.Reader) error {
	return b.AddReaderWithOptions(path, r, ArtifactOptions{})
}

// AddReaderWithOptions adds an artifact from a reader with metadata options.
// Reading is bounded by MaxArtifactSizeBytes to prevent memory exhaustion.
func (b *Builder) AddReaderWithOptions(path string, r io.Reader, opts ArtifactOptions) error {
	data, err := boundedio.ReadReaderWithLimit(r, path, limits.Artifact)
	if err != nil {
		if boundedio.IsBoundedReadError(err) {
			return errors.E(errors.ArtifactTooLarge,
				fmt.Sprintf("content for %q exceeds artifact size limit (%d bytes)",
					path, limits.Artifact.Bytes()), err)
		}
		return fmt.Errorf("reading content for %q: %w", path, err)
	}
	return b.AddBytesWithOptions(path, data, opts)
}

// validateArtifactPath checks that a path is valid for an artifact.
// SECURITY: Delegates to packpath.ValidateArtifactPath to ensure consistent
// validation between builder (pack creation) and manifest (pack parsing).
func (b *Builder) validateArtifactPath(path string) error {
	return packpath.ValidateArtifactPath(path)
}

// Build creates the evidence pack at the specified output path.
// This computes all digests, generates the manifest, and creates the ZIP.
// If a signer was configured, it also signs the pack.
func (b *Builder) Build(outputPath string) error {
	return b.BuildContext(context.Background(), outputPath)
}

// BuildContext creates the evidence pack with a context for cancellation.
func (b *Builder) BuildContext(ctx context.Context, outputPath string) error {
	if err := b.validate(); err != nil {
		return err
	}

	manifest, err := b.buildManifest()
	if err != nil {
		return err
	}

	return b.writeZip(outputPath, manifest)
}

// validate checks builder constraints before building.
func (b *Builder) validate() error {
	if b.stream == "" {
		return errors.E(errors.InvalidInput, "stream is required", nil)
	}
	if len(b.artifacts) > limits.MaxArtifactCount {
		return errors.E(errors.TooManyArtifacts,
			fmt.Sprintf("artifact count %d exceeds limit %d",
				len(b.artifacts), limits.MaxArtifactCount), nil)
	}
	var totalSize int64
	for _, a := range b.artifacts {
		totalSize += int64(len(a.data))
	}
	if totalSize > limits.MaxPackSizeBytes {
		return errors.E(errors.ArtifactTooLarge,
			fmt.Sprintf("total pack size %d exceeds limit %d",
				totalSize, limits.MaxPackSizeBytes), nil)
	}
	return nil
}

// buildManifest creates the manifest with computed digests.
// It validates the manifest can be parsed by ParseManifest (round-trip validation)
// to ensure the builder produces spec-compliant packs.
func (b *Builder) buildManifest() ([]byte, error) {
	artifacts := make([]pack.Artifact, 0, len(b.artifacts))
	for _, a := range b.artifacts {
		size := json.Number(strconv.FormatInt(int64(len(a.data)), 10))
		artifacts = append(artifacts, pack.Artifact{
			Type:        "embedded",
			Path:        a.path,
			Digest:      computeSHA256(a.data),
			Size:        &size,
			ContentType: a.contentType,
			DisplayName: a.displayName,
			Description: a.description,
			CollectedAt: a.collectedAt,
			Schema:      a.schema,
			Controls:    a.controls,
		})
	}

	// Sort artifacts by path for deterministic output
	sort.Slice(artifacts, func(i, j int) bool {
		return artifacts[i].Path < artifacts[j].Path
	})

	// Ensure sources is an empty array, not nil (spec requires the field)
	sources := b.sources
	if sources == nil {
		sources = []pack.Source{}
	}

	// Build manifest with placeholder pack_digest, then compute the real one
	manifest := pack.Manifest{
		SpecVersion: "1.0",
		Stream:      b.stream,
		GeneratedAt: timestamp.Now().String(),
		Sources:     sources,
		Artifacts:   artifacts,
	}

	// Add provenance if set
	if b.provenance != nil {
		manifest.Provenance = b.provenance
	}

	canonical := pack.BuildCanonicalArtifactList(&manifest)
	manifest.PackDigest = pack.HashCanonicalList(canonical)

	data, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("marshaling manifest: %w", err)
	}
	if int64(len(data)) > limits.Manifest.Bytes() {
		return nil, errors.E(errors.ArtifactTooLarge,
			fmt.Sprintf("manifest size %d exceeds limit %d",
				len(data), limits.Manifest.Bytes()), nil)
	}

	// Round-trip validation: ensure the manifest we produce is spec-compliant
	// and can be parsed by pack.ParseManifest. This catches issues like
	// invalid field values, encoding problems, or spec violations.
	if _, err := pack.ParseManifest(data); err != nil {
		return nil, fmt.Errorf("builder produced invalid manifest: %w", err)
	}

	return data, nil
}

// writeZip creates the ZIP archive atomically using TOCTOU-safe operations.
// Uses safefile.MkdirAll and atomic rename to prevent symlink race attacks where
// an attacker swaps parent directory components during the write flow.
func (b *Builder) writeZip(outputPath string, manifestBytes []byte) error {
	// Resolve to absolute path first
	absOutputPath, err := filepath.Abs(outputPath)
	if err != nil {
		return fmt.Errorf("resolving output path: %w", err)
	}

	outputDir := filepath.Dir(absOutputPath)
	outputName := filepath.Base(absOutputPath)

	// Find the deepest existing ancestor directory as our trusted base.
	// This handles cases where multiple intermediate directories need to be created.
	baseDir := outputDir
	for {
		info, err := os.Lstat(baseDir)
		if err == nil {
			// Found an existing directory - validate it's not a symlink
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("refusing to write: ancestor directory %s is a symlink", baseDir)
			}
			if !info.IsDir() {
				return fmt.Errorf("refusing to write: %s exists but is not a directory", baseDir)
			}
			break
		}
		if !os.IsNotExist(err) {
			return fmt.Errorf("checking output directory: %w", err)
		}
		// Directory doesn't exist, try parent
		parent := filepath.Dir(baseDir)
		if parent == baseDir {
			// Reached filesystem root
			break
		}
		baseDir = parent
	}

	// Create output directory using safefile (symlink-safe)
	if err := safefile.MkdirAll(baseDir, outputDir); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	// Create temp file in the output directory
	// We create it in a secure location under our control
	tempFile, err := os.CreateTemp(outputDir, "pack-*.zip")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tempPath := tempFile.Name()
	success := false
	defer func() {
		if !success {
			_ = os.Remove(tempPath)
		}
	}()

	if err := b.writeZipContents(tempFile, manifestBytes); err != nil {
		_ = tempFile.Close()
		return err
	}

	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}

	// TOCTOU-safe rename: Rename keeps directory fd pinned from
	// creation through the rename, preventing symlink swap attacks between
	// directory creation and the final rename.
	if err := safefile.Rename(baseDir, tempPath, filepath.Join(outputDir, outputName)); err != nil {
		return fmt.Errorf("renaming temp file: %w", err)
	}

	success = true
	return nil
}

// writeZipContents writes the manifest and artifacts to the ZIP.
func (b *Builder) writeZipContents(f *os.File, manifestBytes []byte) error {
	zw := zip.NewWriter(f)

	// Write manifest.json
	if err := writeZipEntry(zw, packpath.Manifest, manifestBytes); err != nil {
		_ = zw.Close()
		return err
	}

	// Create artifacts/ directory (required by spec)
	if _, err := zw.Create(packpath.ArtifactsDir); err != nil {
		_ = zw.Close()
		return fmt.Errorf("creating %s directory: %w", packpath.ArtifactsDir, err)
	}

	// Write artifacts sorted by path for determinism
	sorted := make([]artifact, len(b.artifacts))
	copy(sorted, b.artifacts)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].path < sorted[j].path
	})
	for _, a := range sorted {
		if err := writeZipEntry(zw, a.path, a.data); err != nil {
			_ = zw.Close()
			return err
		}
	}

	return zw.Close()
}

// writeZipEntry writes a single file to the ZIP.
func writeZipEntry(zw *zip.Writer, path string, data []byte) error {
	w, err := zw.Create(path)
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// computeSHA256 returns "sha256:{hex}" for the given data.
// Uses internal/digest package for consistent formatting.
func computeSHA256(data []byte) string {
	return digest.FromBytes(data).String()
}
