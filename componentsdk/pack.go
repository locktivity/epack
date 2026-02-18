package componentsdk

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/locktivity/epack/packspec"
)

// Pack size limits (enforced to prevent DoS)
const (
	// MaxArtifactSize is the maximum size for a single artifact (100 MB).
	MaxArtifactSize = 100 * 1024 * 1024

	// MaxManifestSize is the maximum size for manifest.json (10 MB).
	MaxManifestSize = 10 * 1024 * 1024
)

// ErrArtifactTooLarge is returned when an artifact exceeds MaxArtifactSize.
var ErrArtifactTooLarge = errors.New("artifact exceeds maximum size")

// Pack provides read-only access to an evidence pack.
type Pack struct {
	reader   *zip.ReadCloser
	manifest *Manifest
	index    map[string]*zip.File
}

// Type aliases from packspec for consistent types across the codebase.
// These ensure componentsdk uses the same Manifest and Artifact types as pack/.
type (
	Manifest            = packspec.Manifest
	Artifact            = packspec.Artifact
	Source              = packspec.Source
	Provenance          = packspec.Provenance
	SourcePack          = packspec.SourcePack
	EmbeddedAttestation = packspec.EmbeddedAttestation
)

// CollectorMetadata contains metadata about a collector run.
// This is SDK-specific metadata for collector components.
type CollectorMetadata struct {
	// Name is the collector name.
	Name string `json:"name"`

	// Version is the collector version.
	Version string `json:"version,omitempty"`

	// CollectedAt is the collection timestamp.
	CollectedAt string `json:"collected_at,omitempty"`
}

// OpenPack opens an evidence pack file and reads its manifest.
// The caller must call Close() when done.
func OpenPack(path string) (*Pack, error) {
	reader, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("opening pack: %w", err)
	}

	p := &Pack{
		reader: reader,
		index:  make(map[string]*zip.File),
	}

	// Build index of files
	for _, f := range reader.File {
		p.index[f.Name] = f
	}

	// Read manifest
	manifestFile, ok := p.index["manifest.json"]
	if !ok {
		_ = reader.Close()
		return nil, errors.New("manifest.json not found in pack")
	}

	manifestReader, err := manifestFile.Open()
	if err != nil {
		_ = reader.Close()
		return nil, fmt.Errorf("opening manifest.json: %w", err)
	}
	defer func() { _ = manifestReader.Close() }()

	// Limit manifest size
	limitedReader := io.LimitReader(manifestReader, MaxManifestSize+1)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		_ = reader.Close()
		return nil, fmt.Errorf("reading manifest.json: %w", err)
	}
	if len(data) > MaxManifestSize {
		_ = reader.Close()
		return nil, errors.New("manifest.json exceeds maximum size")
	}

	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		_ = reader.Close()
		return nil, fmt.Errorf("parsing manifest.json: %w", err)
	}

	p.manifest = &manifest
	return p, nil
}

// Manifest returns the pack's manifest.
func (p *Pack) Manifest() *Manifest {
	return p.manifest
}

// Artifacts returns all artifacts in the pack.
func (p *Pack) Artifacts() []Artifact {
	if p.manifest == nil {
		return nil
	}
	return p.manifest.Artifacts
}

// HasArtifact checks if an artifact exists at the given path.
func (p *Pack) HasArtifact(path string) bool {
	_, ok := p.index[path]
	return ok
}

// ReadArtifact reads the contents of an artifact by path.
// Returns ErrArtifactTooLarge if the artifact exceeds MaxArtifactSize.
func (p *Pack) ReadArtifact(path string) ([]byte, error) {
	file, ok := p.index[path]
	if !ok {
		return nil, fmt.Errorf("artifact not found: %s", path)
	}

	// Check uncompressed size
	if file.UncompressedSize64 > MaxArtifactSize {
		return nil, fmt.Errorf("%w: %s (%d bytes)", ErrArtifactTooLarge, path, file.UncompressedSize64)
	}

	reader, err := file.Open()
	if err != nil {
		return nil, fmt.Errorf("opening artifact %s: %w", path, err)
	}
	defer func() { _ = reader.Close() }()

	// Use LimitReader to enforce size limit even if header lies
	limitedReader := io.LimitReader(reader, MaxArtifactSize+1)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("reading artifact %s: %w", path, err)
	}

	if len(data) > MaxArtifactSize {
		return nil, fmt.Errorf("%w: %s", ErrArtifactTooLarge, path)
	}

	return data, nil
}

// ReadArtifactJSON reads and unmarshals a JSON artifact.
func (p *Pack) ReadArtifactJSON(path string, v any) error {
	data, err := p.ReadArtifact(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// Close closes the pack and releases resources.
func (p *Pack) Close() error {
	if p.reader != nil {
		return p.reader.Close()
	}
	return nil
}

// ListFiles returns all file paths in the pack (including non-artifacts).
func (p *Pack) ListFiles() []string {
	paths := make([]string, 0, len(p.index))
	for path := range p.index {
		paths = append(paths, path)
	}
	return paths
}
