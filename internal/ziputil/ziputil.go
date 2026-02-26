// Package ziputil validates and safely reads ZIP archives used by evidence packs.
// Invariants: entry paths are validated, zip-bomb ratios are bounded, and unsafe collisions are rejected.
package ziputil

import (
	"archive/zip"
	"fmt"
	"os"
	"strings"
	"unicode"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/validate"
	"golang.org/x/text/unicode/norm"
)

// WindowsCanonicalPath returns the Windows-canonical form of a path for collision detection.
// On Windows, paths are case-insensitive and certain characters are stripped:
// - Trailing dots are stripped from each segment
// - Trailing spaces are stripped from each segment
// - Case is normalized to lowercase
//
// Two paths that produce the same canonical form will collide on Windows.
// Use for duplicate detection in manifests.
func WindowsCanonicalPath(path string) string {
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		// Strip trailing dots and spaces (Windows does this automatically)
		seg = strings.TrimRight(seg, ". ")
		// Lowercase for case-insensitive comparison
		segments[i] = strings.ToLower(seg)
	}
	return strings.Join(segments, "/")
}

const (
	// Path validation constants per spec Section 2.3.
	MaxPathLength    = 240 // Maximum total path length in bytes
	MaxSegmentLength = 80  // Maximum segment length in bytes (accommodates attestation filenames)

	// DefaultMaxCompressionRatio is the default maximum compression ratio allowed.
	// A ratio of 100 means the uncompressed size can be at most 100x the compressed size.
	// This helps prevent zip bomb attacks.
	DefaultMaxCompressionRatio = 100
)

// CheckCompressionRatio rejects archives containing entries whose
// uncompressed-to-compressed ratio exceeds maxRatio.
// If maxRatio <= 0, DefaultMaxCompressionRatio is used.
func CheckCompressionRatio(archive *zip.Reader, maxRatio int) error {
	if maxRatio <= 0 {
		maxRatio = DefaultMaxCompressionRatio
	}
	maxRatioU64 := uint64(maxRatio)

	for _, entry := range archive.File {
		if entry.FileInfo().IsDir() {
			continue
		}

		compressedBytes := entry.CompressedSize64
		uncompressedBytes := entry.UncompressedSize64

		if isTrulyEmpty(compressedBytes, uncompressedBytes) {
			continue
		}

		if compressedBytes == 0 {
			return errors.E(
				errors.ZipBomb,
				fmt.Sprintf(
					"suspicious zip entry %q: uncompressed=%d bytes, compressed=0 bytes",
					entry.Name,
					uncompressedBytes,
				),
				nil,
			)
		}

		if exceedsCompressionRatioLimit(uncompressedBytes, compressedBytes, maxRatioU64) {
			humanReadableRatio := float64(uncompressedBytes) / float64(compressedBytes)
			return errors.E(
				errors.ZipBomb,
				fmt.Sprintf(
					"zip entry %q exceeds compression ratio limit: %.1f:1 is greater than %d:1 (uncompressed=%d bytes, compressed=%d bytes)",
					entry.Name,
					humanReadableRatio,
					maxRatio,
					uncompressedBytes,
					compressedBytes,
				),
				nil,
			)
		}
	}

	return nil
}

func isTrulyEmpty(compressedBytes, uncompressedBytes uint64) bool {
	return compressedBytes == 0 && uncompressedBytes == 0
}

// exceedsCompressionRatioLimit reports whether uncompressedBytes is greater than
// maxRatio * compressedBytes, without multiplying and risking uint64 overflow.
func exceedsCompressionRatioLimit(uncompressedBytes, compressedBytes, maxRatio uint64) bool {
	quotient := uncompressedBytes / compressedBytes
	remainder := uncompressedBytes % compressedBytes
	return quotient > maxRatio || (quotient == maxRatio && remainder != 0)
}

// ValidatePath checks that a zip entry path is safe per spec Section 2.3.
// It rejects:
// - Empty paths
// - Control characters
// - Backslashes (must use forward slashes only)
// - Trailing slashes (files must not end with /)
// - Empty segments (consecutive slashes like //)
// - Path traversal (. and .. segments)
// - Absolute paths (leading / or Windows drive letters)
// - Windows reserved characters (colons)
// - Windows reserved names (CON, PRN, etc. without extensions)
// - UNC paths (//server/share)
// - Non-NFC Unicode (path must equal its NFC normalization)
// - Paths exceeding length limits
func ValidatePath(name string) error {
	if err := validatePathGlobalRules(name); err != nil {
		return err
	}
	return validatePathSegments(name)
}

func validatePathGlobalRules(name string) error {
	if name == "" {
		return errors.E(errors.InvalidPath, "empty path", nil)
	}
	for i, r := range name {
		if unicode.IsControl(r) {
			return errors.E(errors.InvalidPath,
				fmt.Sprintf("path contains control character at position %d: %q", i, name), nil)
		}
	}
	if strings.Contains(name, "\\") {
		return errors.E(errors.InvalidPath, fmt.Sprintf("path contains backslash (must use forward slashes): %q", name), nil)
	}
	if strings.HasSuffix(name, "/") {
		return errors.E(errors.InvalidPath, fmt.Sprintf("path must not end with slash: %q", name), nil)
	}
	if strings.HasPrefix(name, "/") {
		return errors.E(errors.InvalidPath, fmt.Sprintf("absolute path not allowed: %q", name), nil)
	}
	if strings.HasPrefix(name, "//") {
		return errors.E(errors.InvalidPath, fmt.Sprintf("UNC path not allowed: %q", name), nil)
	}
	if isWindowsAbsolutePath(name) {
		return errors.E(errors.InvalidPath, fmt.Sprintf("Windows absolute path not allowed: %q", name), nil)
	}
	if strings.Contains(name, ":") {
		return errors.E(errors.InvalidPath, fmt.Sprintf("path contains colon (reserved on Windows): %q", name), nil)
	}
	if len(name) > MaxPathLength {
		return errors.E(errors.InvalidPath,
			fmt.Sprintf("path exceeds maximum length (%d > %d): %q", len(name), MaxPathLength, name), nil)
	}
	if !norm.NFC.IsNormalString(name) {
		return errors.E(errors.InvalidPath, fmt.Sprintf("path is not in NFC normalized form: %q", name), nil)
	}
	return nil
}

func isWindowsAbsolutePath(name string) bool {
	if len(name) < 2 || name[1] != ':' {
		return false
	}
	c := name[0]
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func validatePathSegments(name string) error {
	segments := strings.Split(name, "/")
	for _, seg := range segments {
		if err := validatePathSegment(name, seg); err != nil {
			return err
		}
	}
	return nil
}

func validatePathSegment(fullPath, seg string) error {
	if seg == "" {
		return errors.E(errors.InvalidPath,
			fmt.Sprintf("path contains empty segment (consecutive slashes): %q", fullPath), nil)
	}
	if seg == "." || seg == ".." || strings.HasPrefix(seg, "..") {
		return errors.E(errors.InvalidPath,
			fmt.Sprintf("path contains traversal segment: %q", fullPath), nil)
	}
	if len(seg) > MaxSegmentLength {
		return errors.E(errors.InvalidPath,
			fmt.Sprintf("path segment exceeds maximum length (%d > %d): %q", len(seg), MaxSegmentLength, seg), nil)
	}
	if validate.IsWindowsReserved(seg) {
		return errors.E(errors.InvalidPath,
			fmt.Sprintf("path contains Windows reserved name: %q", seg), nil)
	}
	if strings.HasSuffix(seg, ".") || strings.HasSuffix(seg, " ") {
		return errors.E(errors.InvalidPath,
			fmt.Sprintf("path segment has trailing dot or space (causes Windows collision): %q", seg), nil)
	}
	return nil
}

// ValidateDirectoryEntry checks that a ZIP entry's attributes are consistent with its path.
// Per spec Section 2.3 (R-321 through R-323, R-347):
// - A trailing "/" in the path indicates a directory entry
// - Directory entries MUST have size 0
// - ZIP mode bits indicating directory MUST match path ending with "/"
// - ZIP mode bits indicating file MUST NOT have path ending with "/"
func ValidateDirectoryEntry(f *zip.File) error {
	mode := f.Mode()
	isDir := mode.IsDir()
	pathEndsWithSlash := strings.HasSuffix(f.Name, "/")

	// R-321/R-323: If mode bits say directory, path must end with /
	if isDir && !pathEndsWithSlash {
		return errors.E(errors.InvalidPath,
			fmt.Sprintf("ZIP entry has directory mode but path does not end with '/': %q", f.Name), nil)
	}

	// R-347: If mode bits say file, path must NOT end with /
	if !isDir && pathEndsWithSlash {
		return errors.E(errors.InvalidPath,
			fmt.Sprintf("ZIP entry has file mode but path ends with '/': %q", f.Name), nil)
	}

	// R-322: Directory entries must have size 0
	if isDir || pathEndsWithSlash {
		if f.UncompressedSize64 != 0 {
			return errors.E(errors.InvalidPath,
				fmt.Sprintf("directory entry must have size 0, got %d: %q", f.UncompressedSize64, f.Name), nil)
		}
	}

	return nil
}

// ValidateNotSymlink checks that a ZIP entry is not a symlink.
// Symlinks in ZIP archives are a security risk as they can escape the extraction directory.
func ValidateNotSymlink(f *zip.File) error {
	mode := f.Mode()
	if mode&os.ModeSymlink != 0 {
		return errors.E(errors.InvalidPath,
			fmt.Sprintf("ZIP entry is a symlink (not allowed): %q", f.Name), nil)
	}
	return nil
}

// ValidateNotDeviceFile checks that a ZIP entry is not a device file.
// Device files in ZIP archives are a security risk.
func ValidateNotDeviceFile(f *zip.File) error {
	mode := f.Mode()
	if mode&os.ModeDevice != 0 {
		return errors.E(errors.InvalidPath,
			fmt.Sprintf("ZIP entry is a device file (not allowed): %q", f.Name), nil)
	}
	return nil
}

// IsAppleDoubleFile checks if a path is an AppleDouble metadata file.
// Per spec Section 7.3 (R-101), these SHOULD be rejected:
// - Files under __MACOSX/ directory (resource fork storage)
// - Files starting with ._ (AppleDouble sidecar files)
func IsAppleDoubleFile(path string) bool {
	// Check for __MACOSX/ directory (macOS resource fork storage)
	if strings.HasPrefix(path, "__MACOSX/") {
		return true
	}

	// Check for ._ prefix in any path segment (AppleDouble sidecar files)
	// These can appear as "._filename" or "dir/._filename"
	segments := strings.Split(path, "/")
	for _, seg := range segments {
		if strings.HasPrefix(seg, "._") {
			return true
		}
	}

	return false
}

// ValidateNotAppleDouble rejects AppleDouble metadata files.
// Per spec Section 7.3 (R-101), these SHOULD be rejected as they:
// - Contain macOS-specific metadata not relevant to evidence packs
// - May contain unexpected executable content
// - Cause confusion when packs are created on macOS and consumed elsewhere
func ValidateNotAppleDouble(path string) error {
	if IsAppleDoubleFile(path) {
		return errors.E(errors.InvalidPath,
			fmt.Sprintf("AppleDouble metadata file not allowed: %q", path), nil)
	}
	return nil
}
