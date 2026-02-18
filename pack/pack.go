package pack

import (
	"archive/zip"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/boundedio"
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/packpath"
	"github.com/locktivity/epack/internal/ziputil"
)

// Pack represents an evidence pack loaded from a zip archive, containing the manifest and indexed files.
//
// Pack is safe for concurrent read operations.
type Pack struct {
	manifest *Manifest
	index    map[string]*zip.File
	reader   *zip.ReadCloser
}

// ReadBudget tracks cumulative bytes read during an operation to prevent DoS attacks.
// Create a new ReadBudget for each logical operation (e.g., Extract, Verify).
// ReadBudget is safe for concurrent use within a single operation.
//
// SECURITY: Each operation should have its own budget to prevent:
//   - A prior operation's reads from exhausting the budget for subsequent operations
//   - Long-running processes hitting cumulative limits that make the Pack unusable
//
// Example:
//
//	budget := pack.NewReadBudget()
//	data, err := p.ReadArtifactWithBudget("artifacts/file.json", budget)
type ReadBudget struct {
	bytesRead atomic.Int64
	maxBytes  int64
}

// NewReadBudget creates a new per-operation read budget with the default pack-wide limit.
func NewReadBudget() *ReadBudget {
	return &ReadBudget{
		maxBytes: limits.MaxPackSizeBytes,
	}
}

// NewReadBudgetWithLimit creates a new per-operation read budget with a custom limit.
func NewReadBudgetWithLimit(maxBytes int64) *ReadBudget {
	return &ReadBudget{
		maxBytes: maxBytes,
	}
}

// BytesRead returns the number of bytes read so far.
func (b *ReadBudget) BytesRead() int64 {
	return b.bytesRead.Load()
}

// Remaining returns the number of bytes remaining in the budget.
func (b *ReadBudget) Remaining() int64 {
	return b.maxBytes - b.bytesRead.Load()
}

// Manifest returns a COPY of the pack's manifest.
// Mutations to the returned value do not affect the pack's internal state.
func (p *Pack) Manifest() Manifest {
	return p.manifest.Copy()
}

// Close releases resources associated with the pack.
// Close is not safe to call concurrently with active read operations.
func (p *Pack) Close() error {
	if p.reader == nil {
		return nil
	}
	err := p.reader.Close()
	p.reader = nil
	return err
}

// Zip returns the underlying zip.Reader for advanced read-only operations.
// Returns nil if the pack was not opened from a file.
func (p *Pack) Zip() *zip.Reader {
	if p.reader == nil {
		return nil
	}
	return &p.reader.Reader
}

// HasFile reports whether a file exists in the pack at the given path.
func (p *Pack) HasFile(path string) bool {
	_, ok := p.index[path]
	return ok
}

// ReadFileUntrusted reads raw file bytes WITHOUT integrity verification.
// SECURITY: The returned content is UNTRUSTED - it has not been verified against
// any manifest digest. Use ReadArtifact for verified reads of manifest-declared artifacts.
// This is useful for attestations and other non-artifact files where the caller
// will perform their own verification (e.g., Sigstore signature verification).
func (p *Pack) ReadFileUntrusted(path string) ([]byte, error) {
	return p.ReadFileUntrustedWithBudget(path, nil)
}

// ReadFileUntrustedWithBudget reads raw file bytes WITHOUT integrity verification,
// tracking reads against the provided budget.
// SECURITY: The returned content is UNTRUSTED - see ReadFileUntrusted for details.
//
// If budget is nil, only per-artifact limits are enforced.
func (p *Pack) ReadFileUntrustedWithBudget(path string, budget *ReadBudget) ([]byte, error) {
	reader, err := p.OpenFileUntrustedWithBudget(path, budget)
	if err != nil {
		return nil, err
	}
	defer func() { _ = reader.Close() }()

	return io.ReadAll(reader)
}

// OpenFileUntrusted returns a reader WITHOUT integrity verification.
// SECURITY: The returned content is UNTRUSTED - it has not been verified against
// any manifest digest. Use OpenArtifact for verified streaming reads.
// Callers must close the returned reader.
//
// This reader enforces per-artifact size limits to prevent DoS via decompression bombs.
// For pack-wide limits, use OpenFileUntrustedWithBudget with a ReadBudget.
func (p *Pack) OpenFileUntrusted(path string) (io.ReadCloser, error) {
	return p.OpenFileUntrustedWithBudget(path, nil)
}

// OpenFileUntrustedWithBudget returns a reader WITHOUT integrity verification,
// tracking reads against the provided budget.
// SECURITY: The returned content is UNTRUSTED - see OpenFileUntrusted for details.
// Use OpenArtifactWithBudget for verified streaming reads with budget tracking.
// Callers must close the returned reader.
//
// If budget is nil, only per-artifact limits are enforced.
func (p *Pack) OpenFileUntrustedWithBudget(path string, budget *ReadBudget) (io.ReadCloser, error) {
	file, ok := p.index[path]
	if !ok {
		return nil, errors.E(errors.MissingEntry, fmt.Sprintf("file not found: %q", path), nil)
	}

	reader, err := file.Open()
	if err != nil {
		return nil, fmt.Errorf("opening file %q: %w", path, err)
	}

	return &limitedReader{
		reader:           reader,
		path:             path,
		maxArtifactBytes: limits.Artifact.Bytes(),
		budget:           budget,
	}, nil
}

// limitedReader wraps a reader to enforce per-artifact and operation-wide size limits.
// It is safe for concurrent use when multiple readers share the same ReadBudget.
type limitedReader struct {
	reader           io.ReadCloser
	path             string
	maxArtifactBytes int64       // per-artifact limit
	budget           *ReadBudget // per-operation budget (may be nil)
	bytesRead        int64       // bytes read through this reader (not shared)
}

func (r *limitedReader) Read(p []byte) (int, error) {
	// Check artifact limit first
	remaining := r.maxArtifactBytes - r.bytesRead
	if remaining == 0 {
		// At limit - peek 1 byte to distinguish "exact size" from "truncated"
		// For the peek, we need to reserve 1 byte from budget atomically
		if r.budget != nil {
			if !r.tryReserveBudgetBytes(1) {
				return 0, errors.E(errors.ZipBomb,
					fmt.Sprintf("operation read limit exceeded (%d bytes)", r.budget.maxBytes), nil)
			}
		}
		var peek [1]byte
		n, err := r.reader.Read(peek[:])
		if n > 0 {
			// There was more data - artifact exceeds limit
			r.bytesRead += int64(n)
			// Note: we already reserved 1 byte, so budget is already updated
			return 0, errors.E(errors.ArtifactTooLarge,
				fmt.Sprintf("%q exceeds artifact size limit (%d bytes)", r.path, r.maxArtifactBytes), nil)
		}
		// No bytes read - release the reservation
		if r.budget != nil {
			r.budget.bytesRead.Add(-1)
		}
		if err == io.EOF {
			// Underlying stream ended exactly at limit - clean EOF
			return 0, io.EOF
		}
		if err == nil {
			// Reader returned (0, nil) which is allowed but would cause io.ReadAll to spin
			return 0, io.ErrNoProgress
		}
		// Some other error from underlying reader - wrap with context
		return 0, fmt.Errorf("read artifact %q: %w", r.path, err)
	}
	if remaining < 0 {
		// Past limit (shouldn't happen with proper capping)
		return 0, errors.E(errors.ArtifactTooLarge,
			fmt.Sprintf("%q exceeds artifact size limit (%d bytes)", r.path, r.maxArtifactBytes), nil)
	}

	// Cap buffer to not exceed artifact limit
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}

	// Atomically reserve bytes from operation budget BEFORE reading
	// This prevents concurrent readers from overshooting the limit
	var reserved int64
	if r.budget != nil {
		reserved = r.reserveBudgetBytes(int64(len(p)))
		if reserved == 0 {
			// No budget available
			return 0, errors.E(errors.ZipBomb,
				fmt.Sprintf("operation read limit exceeded (%d bytes)", r.budget.maxBytes), nil)
		}
		// Cap buffer to reserved amount
		if int64(len(p)) > reserved {
			p = p[:reserved]
		}
	}

	n, err := r.reader.Read(p)
	r.bytesRead += int64(n)

	// Release unused reservation (reserved - actual read)
	if r.budget != nil && reserved > int64(n) {
		r.budget.bytesRead.Add(-(reserved - int64(n)))
	}

	// Wrap non-EOF errors with context
	if err != nil && err != io.EOF {
		return n, fmt.Errorf("read artifact %q: %w", r.path, err)
	}

	return n, err
}

func (r *limitedReader) Close() error {
	return r.reader.Close()
}

// tryReserveBudgetBytes attempts to atomically reserve exactly n bytes from the budget.
// Returns true if the reservation succeeded, false if budget would be exceeded.
// Uses compare-and-swap to prevent concurrent readers from overshooting.
func (r *limitedReader) tryReserveBudgetBytes(n int64) bool {
	for {
		current := r.budget.bytesRead.Load()
		if current+n > r.budget.maxBytes {
			return false
		}
		if r.budget.bytesRead.CompareAndSwap(current, current+n) {
			return true
		}
		// CAS failed, another goroutine modified the counter; retry
	}
}

// reserveBudgetBytes atomically reserves up to n bytes from the budget.
// Returns the number of bytes actually reserved (may be less than n if near limit).
// Returns 0 if no budget is available.
// Uses compare-and-swap to prevent concurrent readers from overshooting.
func (r *limitedReader) reserveBudgetBytes(n int64) int64 {
	for {
		current := r.budget.bytesRead.Load()
		available := r.budget.maxBytes - current
		if available <= 0 {
			return 0
		}
		// Reserve up to n bytes, but no more than available
		toReserve := n
		if toReserve > available {
			toReserve = available
		}
		if r.budget.bytesRead.CompareAndSwap(current, current+toReserve) {
			return toReserve
		}
		// CAS failed, another goroutine modified the counter; retry
	}
}

// Open loads an evidence pack from the specified file path, validating its structure and manifest.
//
// SECURITY: Uses SafeReader to validate ZIP structure before processing:
// - Entry count limits (DoS prevention)
// - Compression ratio limits (zip bomb detection)
// - Path safety (traversal, encoding, reserved names)
// - Windows path collision detection
func Open(path string) (*Pack, error) {
	zipReader, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}

	// SECURITY: Wrap with SafeReader for upfront validation of all ZIP security checks.
	// This centralizes validation and prevents TOCTOU issues.
	safeReader, err := ziputil.NewSafeReaderFromZip(&zipReader.Reader)
	if err != nil {
		_ = zipReader.Close()
		return nil, mapSafeReaderError(err)
	}

	pack, err := loadFromSafeReader(safeReader)
	if err != nil {
		_ = zipReader.Close()
		return nil, err
	}

	pack.reader = zipReader
	return pack, nil
}

// mapSafeReaderError maps SafeReader validation errors to appropriate pack error codes.
func mapSafeReaderError(err error) error {
	msg := err.Error()

	// Entry count exceeded
	if strings.Contains(msg, "entry count") && strings.Contains(msg, "exceeds limit") {
		return errors.E(errors.TooManyArtifacts, msg, err)
	}

	// Compression ratio exceeded (zip bomb)
	if strings.Contains(msg, "compression ratio") {
		return errors.E(errors.ZipBomb, msg, err)
	}

	// Duplicate entries
	if strings.Contains(msg, "duplicate zip entry") {
		return errors.E(errors.DuplicatePath, msg, err)
	}

	// Path validation failures (traversal, reserved names, etc.)
	if strings.Contains(msg, "invalid zip entry") ||
		strings.Contains(msg, "path traversal") ||
		strings.Contains(msg, "absolute path") ||
		strings.Contains(msg, "reserved name") ||
		strings.Contains(msg, "invalid UTF-8") ||
		strings.Contains(msg, "Windows path collision") {
		return errors.E(errors.InvalidPath, msg, err)
	}

	// Default to ZipBomb for other security-related errors
	return errors.E(errors.ZipBomb, msg, err)
}

// ListAttestations returns a sorted list of attestation file paths.
// Attestations are files in the attestations/ directory ending with .sigstore.json.
func (p *Pack) ListAttestations() []string {
	var attestations []string
	for path := range p.index {
		if strings.HasPrefix(path, packpath.Attestations) && strings.HasSuffix(path, packpath.SigstoreExt) {
			attestations = append(attestations, path)
		}
	}
	sort.Strings(attestations)
	return attestations
}

// ReadAttestation reads and returns the contents of an attestation file.
// Attestations are not integrity-verified since they are not in the manifest.
// Enforces MaxAttestationSizeBytes limit (1 MB) to prevent memory DoS attacks.
func (p *Pack) ReadAttestation(path string) ([]byte, error) {
	if !strings.HasPrefix(path, packpath.Attestations) || !strings.HasSuffix(path, packpath.SigstoreExt) {
		return nil, errors.E(errors.InvalidPath, fmt.Sprintf("not an attestation path: %q", path), nil)
	}

	file, ok := p.index[path]
	if !ok {
		return nil, errors.E(errors.MissingEntry, fmt.Sprintf("attestation not found: %q", path), nil)
	}

	// Enforce attestation size limit BEFORE reading to prevent memory exhaustion
	// Attestations should be much smaller than artifacts (1 MB vs 100 MB)
	if file.UncompressedSize64 > uint64(limits.Attestation.Bytes()) {
		return nil, errors.E(errors.AttestationTooLarge,
			fmt.Sprintf("attestation %q exceeds size limit: %d > %d bytes",
				path, file.UncompressedSize64, limits.Attestation.Bytes()), nil)
	}

	reader, err := file.Open()
	if err != nil {
		return nil, fmt.Errorf("opening attestation %q: %w", path, err)
	}
	defer func() { _ = reader.Close() }()

	// Use boundedio for consistent bounded reading with proper error types
	data, err := boundedio.ReadReaderWithLimit(reader, path, limits.Attestation)
	if err != nil {
		if boundedio.IsBoundedReadError(err) {
			return nil, errors.E(errors.AttestationTooLarge,
				fmt.Sprintf("attestation %q exceeds size limit during read", path), nil)
		}
		return nil, fmt.Errorf("reading attestation %q: %w", path, err)
	}

	return data, nil
}

// loadFromSafeReader loads a pack from a pre-validated SafeReader.
// SECURITY: SafeReader has already validated entry count, compression ratio,
// path safety, and Windows collisions. This function handles pack-specific validation.
func loadFromSafeReader(safeReader *ziputil.SafeReader) (*Pack, error) {
	zipReader := safeReader.Reader

	// Build index from validated reader - path validation already done by SafeReader
	index, err := indexZipValidated(zipReader)
	if err != nil {
		return nil, err
	}

	// Check artifact count limit (pack-specific, not ZIP-generic)
	artifactCount := 0
	for path := range index {
		if strings.HasPrefix(path, packpath.ArtifactsDir) {
			artifactCount++
		}
	}
	if artifactCount > limits.MaxArtifactCount {
		return nil, errors.E(errors.TooManyArtifacts,
			fmt.Sprintf("artifact count %d exceeds limit %d", artifactCount, limits.MaxArtifactCount), nil)
	}

	// Validate pack-specific structure (artifacts/, attestations/, manifest.json)
	if err := validateStructure(zipReader); err != nil {
		return nil, err
	}

	manifestFile, ok := index[packpath.Manifest]
	if !ok {
		return nil, errors.E(errors.MissingRequiredField, "manifest.json not found", nil)
	}

	manifestData, err := readFileWithLimits(manifestFile, limits.Manifest.Bytes(), limits.Manifest.Bytes())
	if err != nil {
		return nil, fmt.Errorf("reading manifest.json: %w", err)
	}

	manifest, err := ParseManifest(manifestData)
	if err != nil {
		return nil, fmt.Errorf("parsing manifest.json: %w", err)
	}

	if err := validateArtifactsMatch(index, manifest); err != nil {
		return nil, err
	}

	return &Pack{
		manifest: manifest,
		index:    index,
	}, nil
}

// indexZipValidated builds a map of path -> *zip.File for files in a pre-validated archive.
// SECURITY: Path validation already performed by SafeReader.
// Only checks for non-regular files and duplicates.
func indexZipValidated(zipReader *zip.Reader) (map[string]*zip.File, error) {
	index := make(map[string]*zip.File)
	for _, file := range zipReader.File {
		mode := file.Mode()

		// Skip directories
		if mode.IsDir() {
			continue
		}

		// Only allow regular files
		if !mode.IsRegular() {
			return nil, errors.E(errors.InvalidPath,
				fmt.Sprintf("non-regular file entry %q (mode %v) is not allowed", file.Name, mode), nil)
		}

		// Check for duplicates (SafeReader also checks this, but defense-in-depth)
		if _, exists := index[file.Name]; exists {
			return nil, errors.E(errors.DuplicatePath,
				fmt.Sprintf("duplicate file path %q in zip archive", file.Name), nil)
		}

		index[file.Name] = file
	}

	return index, nil
}

// indexZip builds a map of path -> *zip.File for all files in the archive.
// It validates paths, rejects non-regular files, and detects duplicate entries.
//
// Deprecated: Use SafeReader for new code. This function is retained for test compatibility
// but the main Open() path now uses SafeReader which centralizes ZIP security validation.
func indexZip(zipReader *zip.Reader) (map[string]*zip.File, error) {
	index := make(map[string]*zip.File)
	for _, file := range zipReader.File {
		mode := file.Mode()

		// Skip directories
		if mode.IsDir() {
			continue
		}

		// Only allow regular files
		if !mode.IsRegular() {
			return nil, errors.E(errors.InvalidPath,
				fmt.Sprintf("non-regular file entry %q (mode %v) is not allowed", file.Name, mode), nil)
		}

		// Validate path safety
		if err := ziputil.ValidatePath(file.Name); err != nil {
			return nil, err
		}

		// Check for duplicates
		if _, exists := index[file.Name]; exists {
			return nil, errors.E(errors.DuplicatePath,
				fmt.Sprintf("duplicate file path %q in zip archive", file.Name), nil)
		}

		index[file.Name] = file
	}

	return index, nil
}

// validateStructure checks that the pack contains only allowed top-level entries:
// - manifest.json (required)
// - artifacts/ (required, contains embedded artifacts)
// - attestations/ (optional, contains .sigstore.json files)
func validateStructure(zipReader *zip.Reader) error {
	hasArtifacts := false

	for _, f := range zipReader.File {
		if f.Name == packpath.ArtifactsDir || strings.HasPrefix(f.Name, packpath.ArtifactsDir) {
			hasArtifacts = true
		}

		if f.Mode().IsDir() {
			// Allow artifacts/ and attestations/ directory entries
			if f.Name == packpath.ArtifactsDir || f.Name == packpath.Attestations {
				continue
			}
			// Reject other directory entries at top level
			if !strings.HasPrefix(f.Name, packpath.ArtifactsDir) && !strings.HasPrefix(f.Name, packpath.Attestations) {
				return errors.E(errors.InvalidPath,
					fmt.Sprintf("unexpected directory %q in pack", f.Name), nil)
			}
			continue
		}

		if f.Name == packpath.Manifest {
			continue
		}

		if strings.HasPrefix(f.Name, packpath.ArtifactsDir) {
			continue
		}

		if remainder, ok := strings.CutPrefix(f.Name, packpath.Attestations); ok {
			// Attestations must be direct children (no subdirectories)
			if strings.Contains(remainder, "/") {
				return errors.E(errors.InvalidPath,
					fmt.Sprintf("invalid attestation file path %q: must be directly under attestations/", f.Name), nil)
			}

			if !strings.HasSuffix(remainder, packpath.SigstoreExt) {
				return errors.E(errors.InvalidPath,
					fmt.Sprintf("invalid attestation file name %q: must end with %s", f.Name, packpath.SigstoreExt), nil)
			}
			continue
		}

		return errors.E(errors.InvalidPath,
			fmt.Sprintf("unexpected file %q in pack", f.Name), nil)
	}

	if !hasArtifacts {
		return errors.E(errors.MissingRequiredField, "artifacts/ directory not found", nil)
	}

	return nil
}

// readFileWithLimits reads a file enforcing both artifact and remaining pack limits.
// The actual bytes read are counted, not header values.
func readFileWithLimits(file *zip.File, maxArtifact, remainingPack int64) ([]byte, error) {
	if remainingPack <= 0 {
		return nil, errors.E(errors.ZipBomb,
			fmt.Sprintf("pack size limit exceeded (%d bytes)", limits.MaxPackSizeBytes), nil)
	}

	reader, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = reader.Close() }()

	maxRead := min(maxArtifact, remainingPack)

	// Read maxRead+1 to detect if we exceed the limit
	limited := io.LimitReader(reader, maxRead+1)
	contents, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}

	// Check if we exceeded maxRead, then determine which limit was active
	if int64(len(contents)) > maxRead {
		if maxRead == maxArtifact {
			return nil, errors.E(errors.ArtifactTooLarge,
				fmt.Sprintf("%q exceeds artifact size limit (%d > %d bytes)", file.Name, len(contents), maxArtifact), nil)
		}
		return nil, errors.E(errors.ZipBomb,
			fmt.Sprintf("%q would exceed pack size limit (%d bytes remaining)", file.Name, remainingPack), nil)
	}

	return contents, nil
}

// validateArtifactsMatch ensures ZIP contents and manifest are in sync.
// - Every embedded artifact in manifest must exist in ZIP
// - Every file under artifacts/ must be listed in manifest
func validateArtifactsMatch(index map[string]*zip.File, manifest *Manifest) error {
	expected := make(map[string]struct{})
	for _, artifact := range manifest.Artifacts {
		if artifact.Type == "embedded" {
			expected[artifact.Path] = struct{}{}
		}
	}

	// Check: manifest artifacts exist in ZIP
	for path := range expected {
		if _, exists := index[path]; !exists {
			return errors.E(errors.MissingEntry,
				"artifact in manifest not found in ZIP: "+path, nil)
		}
	}

	// Check: ZIP artifacts are listed in manifest
	for path := range index {
		if !strings.HasPrefix(path, packpath.ArtifactsDir) {
			continue
		}
		if _, exists := expected[path]; !exists {
			return errors.E(errors.InvalidPath,
				"artifact in ZIP not listed in manifest: "+path, nil)
		}
	}

	return nil
}
