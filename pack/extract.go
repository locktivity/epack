package pack

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/locktivity/epack/internal/safefile"
)

// SafeExtractAll returns ExtractOptions configured for secure extraction.
// This is the recommended way to configure extraction for production use.
//
// Features:
//   - Extracts all artifacts to the specified directory
//   - Pre-verifies pack integrity before extraction
//   - Fails if files already exist (no overwrite)
//
// Example:
//
//	p, _ := pack.Open("evidence.epack")
//	result, err := p.Extract(pack.SafeExtractAll("/tmp/output"))
func SafeExtractAll(outputDir string) ExtractOptions {
	return ExtractOptions{
		OutputDir:           outputDir,
		All:                 true,
		Force:               false, // Don't overwrite existing files
		SkipPreVerification: false, // Verify integrity first
	}
}

// ExtractOptions configures artifact extraction behavior.
type ExtractOptions struct {
	// OutputDir is the directory to extract artifacts to.
	OutputDir string

	// Paths specifies specific artifact paths to extract.
	// If empty and All is false, returns an error.
	Paths []string

	// All extracts all artifacts when true.
	All bool

	// Filter is a glob pattern to match artifact paths.
	// Only artifacts matching the pattern are extracted.
	Filter string

	// Force overwrites existing files when true.
	Force bool

	// SkipPreVerification skips VerifyIntegrity() before extraction.
	// By default (when false), Extract runs VerifyIntegrity() to ensure
	// the pack_digest matches the canonical artifact list, preventing
	// attacks where extra artifacts are injected into the ZIP.
	//
	// Set to true only for performance when you've already verified the pack.
	SkipPreVerification bool
}

// ExtractResult contains information about extracted artifacts.
type ExtractResult struct {
	// Extracted is the list of file paths that were extracted.
	Extracted []string
}

// Extract extracts artifacts from the pack to the filesystem.
//
// The extraction is performed safely:
//   - Path traversal attacks are rejected
//   - Symlinks in the output path are rejected
//   - Directory creation is race-safe (fd-based on Unix)
//   - File writes use O_NOFOLLOW to prevent symlink attacks
//   - Per-operation read budget prevents DoS via decompression bombs
//   - Pack integrity verified before extraction (unless SkipPreVerification is set)
//
// By default, VerifyIntegrity() is called before extraction to ensure
// pack_digest matches the canonical artifact list. This prevents attacks
// where an attacker injects extra artifacts not in the original manifest.
// Set SkipPreVerification=true only if you've already verified the pack.
func (p *Pack) Extract(opts ExtractOptions) (*ExtractResult, error) {
	if err := maybeVerifyBeforeExtract(p, opts.SkipPreVerification); err != nil {
		return nil, err
	}
	absOutputDir, err := prepareOutputDir(opts.OutputDir)
	if err != nil {
		return nil, err
	}

	// Determine which artifacts to extract
	toExtract, err := p.selectArtifacts(opts)
	if err != nil {
		return nil, err
	}

	if len(toExtract) == 0 {
		return &ExtractResult{}, nil
	}

	// SECURITY: Create a per-operation read budget.
	// This ensures each Extract operation gets its own budget, preventing:
	// - Prior operations from exhausting budget for subsequent operations
	// - Long-running processes hitting cumulative limits
	budget := NewReadBudget()

	// Extract each artifact
	var extracted []string
	for _, a := range toExtract {
		if a.Type != "embedded" {
			continue
		}

		outPath, err := p.extractArtifactWithBudget(absOutputDir, a, opts.Force, budget)
		if err != nil {
			return nil, err
		}

		extracted = append(extracted, outPath)
	}

	return &ExtractResult{Extracted: extracted}, nil
}

func maybeVerifyBeforeExtract(p *Pack, skipPreVerification bool) error {
	if skipPreVerification {
		return nil
	}
	if err := p.VerifyIntegrity(); err != nil {
		return fmt.Errorf("integrity verification failed: %w", err)
	}
	return nil
}

func prepareOutputDir(outputDir string) (string, error) {
	if outputDir == "" {
		outputDir = "."
	}
	absOutputDir, err := filepath.Abs(outputDir)
	if err != nil {
		return "", fmt.Errorf("resolving output directory: %w", err)
	}

	parentDir := filepath.Dir(absOutputDir)
	if parentDir == "" {
		parentDir = "/"
	}
	parentInfo, err := os.Lstat(parentDir)
	if err != nil {
		return "", fmt.Errorf("output parent directory does not exist: %w", err)
	}
	if parentInfo.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("refusing to extract: parent directory %s is a symlink", parentDir)
	}
	if err := safefile.MkdirAll(parentDir, absOutputDir); err != nil {
		return "", fmt.Errorf("creating output directory: %w", err)
	}
	return absOutputDir, nil
}

// selectArtifacts determines which artifacts to extract based on options.
func (p *Pack) selectArtifacts(opts ExtractOptions) ([]Artifact, error) {
	manifest := p.Manifest()

	if opts.All {
		// Return defensive copy to prevent callers from modifying internal state
		return slices.Clone(manifest.Artifacts), nil
	}

	if opts.Filter != "" {
		return filterArtifactsByPattern(manifest.Artifacts, opts.Filter), nil
	}

	if len(opts.Paths) > 0 {
		return selectArtifactsByPaths(manifest.Artifacts, opts.Paths)
	}

	return nil, fmt.Errorf("specify artifact paths, All=true, or Filter pattern")
}

func filterArtifactsByPattern(artifacts []Artifact, pattern string) []Artifact {
	var matched []Artifact
	for _, a := range artifacts {
		if matchPath(a.Path, pattern) {
			matched = append(matched, a)
		}
	}
	return matched
}

func selectArtifactsByPaths(artifacts []Artifact, paths []string) ([]Artifact, error) {
	pathSet := make(map[string]bool, len(paths))
	for _, p := range paths {
		pathSet[p] = true
	}

	var selected []Artifact
	foundPaths := make(map[string]bool, len(paths))
	for _, a := range artifacts {
		if pathSet[a.Path] {
			selected = append(selected, a)
			foundPaths[a.Path] = true
		}
	}
	for _, reqPath := range paths {
		if !foundPaths[reqPath] {
			return nil, fmt.Errorf("artifact not found: %s", reqPath)
		}
	}
	return selected, nil
}

// extractArtifactWithBudget extracts a single artifact with budget tracking.
func (p *Pack) extractArtifactWithBudget(absOutputDir string, a Artifact, force bool, budget *ReadBudget) (string, error) {
	// Validate and join path safely
	// Validate the artifact path is safe and get the absolute output path
	outPath, err := safefile.ValidatePath(absOutputDir, a.Path)
	if err != nil {
		return "", fmt.Errorf("unsafe artifact path %s: %w", a.Path, err)
	}

	// Read artifact data with integrity verification and budget tracking
	data, err := p.ReadArtifactWithBudget(a.Path, budget)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", a.Path, err)
	}

	// TOCTOU-safe write using fd-pinned operations.
	// When force=false, use WriteFileExclusive which atomically fails
	// if the file already exists (via O_EXCL on Unix, CREATE_NEW on Windows).
	// This prevents the race between existence check and file creation.
	//
	// Note: We pass a.Path (the relative path) to WriteFile, not outPath (the absolute path).
	// WriteFile expects a relative path and will join it with baseDir internally.
	if force {
		// Force mode: use WriteFile which will overwrite existing files.
		// This keeps directory fd pinned from creation through file write,
		// preventing parent symlink swaps.
		if err := safefile.WriteFile(absOutputDir, a.Path, data.Bytes()); err != nil {
			return "", fmt.Errorf("writing %s: %w", outPath, err)
		}
	} else {
		// Non-force mode: use exclusive write to atomically fail if file exists.
		// This eliminates the TOCTOU race between existence check and file creation.
		if err := safefile.WriteFileExclusive(absOutputDir, a.Path, data.Bytes()); err != nil {
			if err == safefile.ErrFileExists {
				return "", fmt.Errorf("file already exists: %s (use Force=true to overwrite)", outPath)
			}
			return "", fmt.Errorf("writing %s: %w", outPath, err)
		}
	}

	return outPath, nil
}

// matchPath checks if a path matches a glob pattern.
// It matches against both the full path and the base name.
func matchPath(path, pattern string) bool {
	// Try matching the full path
	if matched, _ := filepath.Match(pattern, path); matched {
		return true
	}
	// Try matching just the filename
	if matched, _ := filepath.Match(pattern, filepath.Base(path)); matched {
		return true
	}
	return false
}
