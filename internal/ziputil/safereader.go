package ziputil

import (
	"archive/zip"
	"fmt"
	"io"

	"github.com/locktivity/epack/internal/limits"
)

// SafeReader wraps a zip.Reader with pre-validated security checks.
// All entries are validated at construction time, ensuring that iteration
// over the reader's files is safe.
//
// SECURITY: SafeReader provides defense-in-depth by validating:
// - Compression ratio limits (zip bomb prevention)
// - Path safety (traversal, reserved names, encoding)
// - Entry count limits (DoS prevention)
// - Windows path collision detection
//
// Use NewSafeReader to create validated instances. Direct construction
// bypasses validation and should be avoided.
type SafeReader struct {
	*zip.Reader

	// validated indicates the reader passed all security checks
	validated bool
}

// SafeReaderOption configures SafeReader behavior.
type SafeReaderOption func(*safeReaderConfig)

type safeReaderConfig struct {
	maxCompressionRatio int
	maxEntries          int
	skipCollisionCheck  bool
}

func defaultSafeReaderConfig() *safeReaderConfig {
	return &safeReaderConfig{
		maxCompressionRatio: limits.MaxCompressionRatio,
		maxEntries:          limits.MaxZipEntries,
		skipCollisionCheck:  false,
	}
}

// WithMaxCompressionRatio sets a custom maximum compression ratio.
// Default is limits.MaxCompressionRatio (100:1).
func WithMaxCompressionRatio(ratio int) SafeReaderOption {
	return func(c *safeReaderConfig) {
		if ratio > 0 {
			c.maxCompressionRatio = ratio
		}
	}
}

// WithMaxEntries sets a custom maximum entry count.
// Default is limits.MaxZipEntries.
func WithMaxEntries(max int) SafeReaderOption {
	return func(c *safeReaderConfig) {
		if max > 0 {
			c.maxEntries = max
		}
	}
}

// WithSkipCollisionCheck disables Windows path collision checking.
// Only use this for archives known to be safe or in test scenarios.
func WithSkipCollisionCheck() SafeReaderOption {
	return func(c *safeReaderConfig) {
		c.skipCollisionCheck = true
	}
}

// NewSafeReader creates a SafeReader from an io.ReaderAt with comprehensive validation.
// Returns an error if any security check fails:
// - Entry count exceeds limits
// - Compression ratio exceeds limits (zip bomb detection)
// - Any path fails validation (traversal, encoding, reserved names)
// - Windows path collisions detected
//
// Once created, iteration over r.File is guaranteed safe.
func NewSafeReader(r io.ReaderAt, size int64, opts ...SafeReaderOption) (*SafeReader, error) {
	cfg := defaultSafeReaderConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, fmt.Errorf("opening zip: %w", err)
	}

	// SECURITY: Check entry count limit before iterating
	if len(zr.File) > cfg.maxEntries {
		return nil, fmt.Errorf("zip entry count %d exceeds limit %d", len(zr.File), cfg.maxEntries)
	}

	// SECURITY: Validate compression ratios (zip bomb prevention)
	if err := CheckCompressionRatio(zr, cfg.maxCompressionRatio); err != nil {
		return nil, err
	}

	// SECURITY: Validate all paths
	// Also collect canonical paths for collision detection
	seenPaths := make(map[string]string, len(zr.File))     // exact path -> first occurrence
	seenCanonical := make(map[string]string, len(zr.File)) // canonical -> first occurrence

	for _, f := range zr.File {
		// SECURITY: Validate directory entry attributes match path (R-321-323, R-347)
		if err := ValidateDirectoryEntry(f); err != nil {
			return nil, fmt.Errorf("invalid zip entry: %w", err)
		}

		// SECURITY: Reject symlinks (can escape extraction directory)
		if err := ValidateNotSymlink(f); err != nil {
			return nil, fmt.Errorf("invalid zip entry: %w", err)
		}

		// SECURITY: Reject device files
		if err := ValidateNotDeviceFile(f); err != nil {
			return nil, fmt.Errorf("invalid zip entry: %w", err)
		}

		// Skip directories (they end with /)
		if f.FileInfo().IsDir() {
			continue
		}

		// Validate path safety
		if err := ValidatePath(f.Name); err != nil {
			return nil, fmt.Errorf("invalid zip entry: %w", err)
		}

		// SECURITY: Reject AppleDouble metadata files (R-101)
		if err := ValidateNotAppleDouble(f.Name); err != nil {
			return nil, fmt.Errorf("invalid zip entry: %w", err)
		}

		// Check for exact duplicates
		if first, exists := seenPaths[f.Name]; exists {
			return nil, fmt.Errorf("duplicate zip entry %q (first seen: %s)", f.Name, first)
		}
		seenPaths[f.Name] = f.Name

		// Check for Windows path collisions
		if !cfg.skipCollisionCheck {
			canonical := WindowsCanonicalPath(f.Name)
			if first, exists := seenCanonical[canonical]; exists && first != f.Name {
				return nil, fmt.Errorf("path collision (Windows case-folding): %q and %q both resolve to %q",
					first, f.Name, canonical)
			}
			seenCanonical[canonical] = f.Name
		}
	}

	return &SafeReader{
		Reader:    zr,
		validated: true,
	}, nil
}

// NewSafeReaderFromZip wraps an existing zip.Reader with validation.
// Use this when you already have a zip.Reader (e.g., from zip.OpenReader).
func NewSafeReaderFromZip(zr *zip.Reader, opts ...SafeReaderOption) (*SafeReader, error) {
	cfg := defaultSafeReaderConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	// SECURITY: Check entry count limit
	if len(zr.File) > cfg.maxEntries {
		return nil, fmt.Errorf("zip entry count %d exceeds limit %d", len(zr.File), cfg.maxEntries)
	}

	// SECURITY: Validate compression ratios
	if err := CheckCompressionRatio(zr, cfg.maxCompressionRatio); err != nil {
		return nil, err
	}

	// SECURITY: Validate all paths and check collisions
	seenPaths := make(map[string]string, len(zr.File))
	seenCanonical := make(map[string]string, len(zr.File))

	for _, f := range zr.File {
		// SECURITY: Validate directory entry attributes match path (R-321-323, R-347)
		if err := ValidateDirectoryEntry(f); err != nil {
			return nil, fmt.Errorf("invalid zip entry: %w", err)
		}

		// SECURITY: Reject symlinks (can escape extraction directory)
		if err := ValidateNotSymlink(f); err != nil {
			return nil, fmt.Errorf("invalid zip entry: %w", err)
		}

		// SECURITY: Reject device files
		if err := ValidateNotDeviceFile(f); err != nil {
			return nil, fmt.Errorf("invalid zip entry: %w", err)
		}

		if f.FileInfo().IsDir() {
			continue
		}

		if err := ValidatePath(f.Name); err != nil {
			return nil, fmt.Errorf("invalid zip entry: %w", err)
		}

		// SECURITY: Reject AppleDouble metadata files (R-101)
		if err := ValidateNotAppleDouble(f.Name); err != nil {
			return nil, fmt.Errorf("invalid zip entry: %w", err)
		}

		if first, exists := seenPaths[f.Name]; exists {
			return nil, fmt.Errorf("duplicate zip entry %q (first seen: %s)", f.Name, first)
		}
		seenPaths[f.Name] = f.Name

		if !cfg.skipCollisionCheck {
			canonical := WindowsCanonicalPath(f.Name)
			if first, exists := seenCanonical[canonical]; exists && first != f.Name {
				return nil, fmt.Errorf("path collision (Windows case-folding): %q and %q both resolve to %q",
					first, f.Name, canonical)
			}
			seenCanonical[canonical] = f.Name
		}
	}

	return &SafeReader{
		Reader:    zr,
		validated: true,
	}, nil
}

// IsValidated returns true if the reader passed all security checks.
// This should always be true for readers created via NewSafeReader.
func (sr *SafeReader) IsValidated() bool {
	return sr.validated
}

// OpenFile opens a file from the archive by name.
// Returns an error if the file is not found.
func (sr *SafeReader) OpenFile(name string) (io.ReadCloser, error) {
	for _, f := range sr.File {
		if f.Name == name {
			return f.Open()
		}
	}
	return nil, fmt.Errorf("file not found in archive: %s", name)
}

// FileNames returns a list of all file names in the archive (excluding directories).
func (sr *SafeReader) FileNames() []string {
	var names []string
	for _, f := range sr.File {
		if !f.FileInfo().IsDir() {
			names = append(names, f.Name)
		}
	}
	return names
}
