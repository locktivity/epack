package builder

import (
	"path/filepath"
	"strings"
)

// ArtifactSource describes where to get artifact content.
type ArtifactSource struct {
	// DestPath is the path in the pack (e.g., "artifacts/config.json").
	// If empty for file sources, defaults to "artifacts/" + basename.
	DestPath string

	// SourcePath is the file path to read from.
	// Supports glob patterns (e.g., "./reports/*.json").
	// Mutually exclusive with Data.
	SourcePath string

	// Data is raw bytes to add directly.
	// Mutually exclusive with SourcePath.
	Data []byte

	// ContentType is the optional MIME type.
	ContentType string
}

// AddArtifacts adds multiple artifacts to the builder.
//
// For sources with SourcePath containing glob patterns, all matching files are added.
// For sources with SourcePath pointing to a file, that file is added.
// For sources with Data, the raw bytes are added directly.
func (b *Builder) AddArtifacts(sources []ArtifactSource) error {
	for _, src := range sources {
		if err := b.addArtifactSource(src); err != nil {
			return err
		}
	}
	return nil
}

// addArtifactSource processes a single artifact source.
func (b *Builder) addArtifactSource(src ArtifactSource) error {
	// Handle raw bytes
	if src.Data != nil {
		return b.addBytesSource(src)
	}

	// Handle file/glob source
	return b.addFileSource(src)
}

// addBytesSource adds raw bytes as an artifact.
func (b *Builder) addBytesSource(src ArtifactSource) error {
	destPath := src.DestPath
	if destPath == "" {
		return nil // No destination path for bytes without DestPath
	}

	// Ensure artifacts/ prefix
	if !strings.HasPrefix(destPath, "artifacts/") {
		destPath = "artifacts/" + destPath
	}

	opts := ArtifactOptions{
		ContentType: src.ContentType,
	}
	return b.AddBytesWithOptions(destPath, src.Data, opts)
}

// addFileSource adds file(s) as artifacts, supporting glob patterns.
func (b *Builder) addFileSource(src ArtifactSource) error {
	if src.SourcePath == "" {
		return nil
	}

	// Expand glob pattern
	matches, err := filepath.Glob(src.SourcePath)
	if err != nil {
		return err
	}

	for _, match := range matches {
		// Determine destination path
		destPath := src.DestPath
		if destPath == "" {
			destPath = "artifacts/" + filepath.Base(match)
		} else if len(matches) > 1 {
			// Multiple matches: append basename to dest path
			destPath = strings.TrimSuffix(destPath, "/") + "/" + filepath.Base(match)
		}

		// Ensure artifacts/ prefix
		if !strings.HasPrefix(destPath, "artifacts/") {
			destPath = "artifacts/" + destPath
		}

		opts := ArtifactOptions{
			ContentType: src.ContentType,
		}
		if err := b.AddFileWithOptions(destPath, match, opts); err != nil {
			return err
		}
	}

	return nil
}
