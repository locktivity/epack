//go:build components

package componentcmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/locktivity/epack/internal/execsafe"
	"github.com/locktivity/epack/internal/safefile"
	"github.com/locktivity/epack/internal/validate"
)

// gitCommandTimeout is the maximum time to wait for git commands.
// SECURITY: Prevents DoS from hanging git operations (e.g., network issues,
// corrupted repos, or malicious .git directories).
const gitCommandTimeout = 10 * time.Second

// Scaffolding constants
const (
	configFileName  = "epack.yaml"
	gitignoreFile   = ".gitignore"
	readmeFile      = "README.md"
	packsDir        = "packs"
	gitkeepFile     = ".gitkeep"
	samplePackFile  = "sample.epack"
	defaultFilePerm = 0644
	defaultDirPerm  = 0755
)

// Managed gitignore block markers
const (
	gitignoreBlockStart = "# >>> epack (managed) >>>"
	gitignoreBlockEnd   = "# <<< epack (managed) <<<"
	gitignoreContent    = `.epack/
packs/*.pack
!packs/.gitkeep`
)


// ScaffoldOptions configures the scaffolding behavior.
type ScaffoldOptions struct {
	ProjectName    string // Name of the project (directory name for 'new', inferred for 'init')
	TargetDir      string // Directory to scaffold into (must exist for init, created for new)
	SkipSample     bool   // Don't include sample.epack
	SkipGit        bool   // Don't run git init
	Force          bool   // Overwrite existing files
	SkipConfig     bool   // Don't create epack.yaml (for idempotent init when config exists)
	AlreadyInitted bool   // Config already exists (for output messaging)
}

// ScaffoldResult contains information about what was scaffolded.
type ScaffoldResult struct {
	TargetDir      string   // Absolute path to scaffolded directory
	Stream         string   // Inferred stream name
	FilesCreated   []string // List of files created (relative to TargetDir)
	GitInited      bool     // Whether git init was run
	AlreadyInitted bool     // Whether this was already initialized (config existed)
}

// ValidateProjectName checks if a project name is safe for use as a directory name.
// Rejects path separators, traversal, absolute paths, Windows reserved names,
// and Windows-forbidden characters.
func ValidateProjectName(name string) error {
	if name == "" {
		return fmt.Errorf("project name cannot be empty")
	}

	// Reject path separators
	if strings.ContainsAny(name, "/\\") {
		return fmt.Errorf("project name cannot contain path separators: %q", name)
	}

	// Reject path traversal using centralized validation
	if err := validate.PathSafe(name); err != nil {
		return fmt.Errorf("project name %q: %w", name, err)
	}

	// Reject absolute paths (Windows drive letters)
	if len(name) >= 2 && name[1] == ':' {
		c := name[0]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return fmt.Errorf("project name cannot be an absolute path: %q", name)
		}
	}

	// Use centralized Windows filename validation
	if err := validate.WindowsFilename(name); err != nil {
		return fmt.Errorf("project name: %w", err)
	}

	return nil
}

// InferStreamFromGit attempts to infer a stream name from the git remote.
// Returns a stream name like "org/repo/prod" or falls back to "example/<dirname>/prod".
func InferStreamFromGit(dir, projectName string) string {
	// Try to get git remote URL with timeout
	// SECURITY: Timeout prevents hanging on corrupted repos or network issues.
	ctx, cancel := context.WithTimeout(context.Background(), gitCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "git", "remote", "get-url", "origin")
	cmd.Dir = dir
	// SECURITY: Use restricted environment to prevent PATH poisoning attacks.
	// A malicious .git/config could potentially influence git behavior, and
	// a poisoned PATH could execute attacker-controlled binaries.
	cmd.Env = execsafe.BuildRestrictedEnvSafe(os.Environ(), false)
	output, err := cmd.Output()
	if err != nil {
		// No git remote or timeout, use fallback
		return fmt.Sprintf("example/%s/prod", projectName)
	}

	remoteURL := strings.TrimSpace(string(output))
	orgRepo := parseGitRemoteURL(remoteURL)
	if orgRepo == "" {
		return fmt.Sprintf("example/%s/prod", projectName)
	}

	return orgRepo + "/prod"
}

// parseGitRemoteURL extracts org/repo from various git URL formats.
// Handles:
//   - https://github.com/org/repo.git
//   - git@github.com:org/repo.git
//   - ssh://git@github.com/org/repo.git
//   - https://gitlab.com/group/subgroup/repo.git (takes last two segments)
func parseGitRemoteURL(url string) string {
	// Remove common URL schemes
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "ssh://")

	// Remove user@host: prefix (git@github.com:org/repo)
	if idx := strings.Index(url, "@"); idx != -1 {
		url = url[idx+1:]
	}

	// Normalize colon to slash (git@github.com:org/repo -> github.com/org/repo)
	url = strings.Replace(url, ":", "/", 1)

	// Remove host (everything before first slash that's part of the path)
	// Find the host boundary - after first slash
	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[idx+1:]
	}

	// Remove .git suffix
	url = strings.TrimSuffix(url, ".git")

	// Split into segments and take last two
	segments := strings.Split(url, "/")
	if len(segments) < 2 {
		return ""
	}

	// Take last two segments (handles nested GitLab groups)
	org := segments[len(segments)-2]
	repo := segments[len(segments)-1]

	// Validate segments are non-empty
	if org == "" || repo == "" {
		return ""
	}

	return org + "/" + repo
}

// Scaffold creates the project structure in the target directory.
// For 'new': creates the directory first
// For 'init': expects the directory to exist
//
// Idempotent behavior:
//   - If SkipConfig is true: don't touch epack.yaml
//   - Always update .gitignore managed block (rewrite to current rules)
//   - Always ensure packs/.gitkeep exists
//   - Copy sample.epack only if it doesn't exist
func Scaffold(opts ScaffoldOptions) (*ScaffoldResult, error) {
	result := &ScaffoldResult{
		FilesCreated:   make([]string, 0),
		AlreadyInitted: opts.AlreadyInitted,
	}

	// Get absolute path to target directory
	absDir, err := filepath.Abs(opts.TargetDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve target directory: %w", err)
	}
	result.TargetDir = absDir

	// Infer project name from directory if not provided
	projectName := opts.ProjectName
	if projectName == "" {
		projectName = filepath.Base(absDir)
	}

	// Infer stream name
	result.Stream = InferStreamFromGit(absDir, projectName)

	// Create epack.yaml (unless SkipConfig is set for idempotent init)
	if !opts.SkipConfig {
		if err := scaffoldConfig(absDir, result.Stream, opts.Force); err != nil {
			return nil, err
		}
		result.FilesCreated = append(result.FilesCreated, configFileName)
	}

	// Update .gitignore (idempotent managed block)
	if err := scaffoldGitignore(absDir); err != nil {
		return nil, err
	}
	result.FilesCreated = append(result.FilesCreated, gitignoreFile)

	// Create packs/ directory with .gitkeep
	packsPath := filepath.Join(absDir, packsDir)
	if err := os.MkdirAll(packsPath, defaultDirPerm); err != nil {
		return nil, fmt.Errorf("failed to create packs directory: %w", err)
	}
	gitkeepPath := filepath.Join(packsPath, gitkeepFile)
	if _, err := os.Stat(gitkeepPath); os.IsNotExist(err) {
		if err := safefile.WriteFile(packsPath, gitkeepFile, []byte{}); err != nil {
			return nil, fmt.Errorf("failed to create .gitkeep: %w", err)
		}
	}
	result.FilesCreated = append(result.FilesCreated, filepath.Join(packsDir, gitkeepFile))

	// Create README.md (only for 'new', not 'init')
	readmePath := filepath.Join(absDir, readmeFile)
	if _, err := os.Stat(readmePath); os.IsNotExist(err) {
		if err := scaffoldReadme(absDir, projectName); err != nil {
			return nil, err
		}
		result.FilesCreated = append(result.FilesCreated, readmeFile)
	}

	// Copy sample.epack (unless --skip-sample or already exists)
	if !opts.SkipSample {
		samplePath := filepath.Join(absDir, samplePackFile)
		if _, err := os.Stat(samplePath); os.IsNotExist(err) {
			if err := scaffoldSamplePack(absDir); err != nil {
				// Non-fatal - sample pack might not be embedded yet
				// Just skip silently for now
			} else {
				result.FilesCreated = append(result.FilesCreated, samplePackFile)
			}
		}
	}

	// Run git init if appropriate
	if !opts.SkipGit {
		if gitInited, err := maybeGitInit(absDir); err == nil && gitInited {
			result.GitInited = true
		}
	}

	return result, nil
}

// scaffoldConfig creates the epack.yaml configuration file.
// Returns nil without writing if the file exists and force is false.
func scaffoldConfig(dir, stream string, force bool) error {
	configPath := filepath.Join(dir, configFileName)

	// Check if file exists (unless force)
	if !force {
		if _, err := os.Stat(configPath); err == nil {
			// File exists and not forcing - this is handled by SkipConfig now
			// but keep this check as a safety measure
			return nil
		}
	}

	content := generateConfigYAML(stream)
	return safefile.WriteFile(dir, configFileName, []byte(content))
}

// generateConfigYAML creates the epack.yaml content with the given stream.
func generateConfigYAML(stream string) string {
	return fmt.Sprintf(`# Evidence Pack Configuration
# Documentation: https://docs.epack.dev

# Stream identifies this evidence collection
# Change to your org/environment (e.g., acme/prod)
stream: %s

# Output directory for generated packs
output: packs/

# Platforms to lock (defaults to current platform if omitted)
# platforms:
#   - linux/amd64
#   - darwin/arm64

collectors:
  # Dependency vulnerability scanning (no secrets required)
  # Scans package-lock.json, go.sum, Cargo.lock, etc.
  # deps:
  #   source: locktivity/epack-collector-deps@v1

  # GitHub organization security posture
  # Requires: export GITHUB_TOKEN=<token>
  # github:
  #   source: locktivity/epack-collector-github@v1
  #   config:
  #     organization: your-org
  #     github_token: ${GITHUB_TOKEN}

# Tools for analyzing evidence packs
# tools:
#   ai:
#     source: locktivity/epack-tool-ai@v1
`, stream)
}

// scaffoldGitignore updates or creates .gitignore with managed block.
func scaffoldGitignore(dir string) error {
	gitignorePath := filepath.Join(dir, gitignoreFile)

	// Read existing content if file exists
	var existingContent string
	if data, err := os.ReadFile(gitignorePath); err == nil {
		existingContent = string(data)
	}

	// Update or append managed block
	newContent := updateManagedBlock(existingContent, gitignoreBlockStart, gitignoreBlockEnd, gitignoreContent)

	return safefile.WriteFile(dir, gitignoreFile, []byte(newContent))
}

// updateManagedBlock updates the managed block in content, or appends it if not present.
func updateManagedBlock(content, startMarker, endMarker, blockContent string) string {
	// Build the full managed block
	managedBlock := fmt.Sprintf("%s\n%s\n%s", startMarker, blockContent, endMarker)

	// Check if markers already exist
	startIdx := strings.Index(content, startMarker)
	endIdx := strings.Index(content, endMarker)

	if startIdx != -1 && endIdx != -1 && startIdx < endIdx {
		// Replace existing block
		before := content[:startIdx]
		after := content[endIdx+len(endMarker):]
		return before + managedBlock + after
	}

	// Append new block
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	if content != "" {
		content += "\n"
	}
	return content + managedBlock + "\n"
}

// scaffoldReadme creates a README.md file.
func scaffoldReadme(dir, projectName string) error {
	content := fmt.Sprintf(`# %s

Evidence pack pipeline created with [epack](https://epack.dev).

## Quick Start

    # Explore the sample pack
    epack verify sample.epack
    epack inspect sample.epack

    # Configure collectors (edit epack.yaml), then:
    epack collect

    # Sign the pack
    epack sign packs/*.pack

## Structure

- `+"`epack.yaml`"+` - Pipeline configuration
- `+"`sample.epack`"+` - Example pack to explore
- `+"`packs/`"+` - Output directory for generated packs
`, projectName)

	return safefile.WriteFile(dir, readmeFile, []byte(content))
}

// scaffoldSamplePack copies the embedded sample.epack to the target directory.
func scaffoldSamplePack(dir string) error {
	if len(samplePackData) == 0 {
		return fmt.Errorf("sample pack not embedded")
	}
	return safefile.WriteFile(dir, samplePackFile, samplePackData)
}

// maybeGitInit runs git init if git is available and we're not in a git repo.
// SECURITY: Uses timeouts on all git commands to prevent DoS from hanging operations.
// Uses restricted environment to prevent PATH poisoning attacks.
func maybeGitInit(dir string) (bool, error) {
	// Check if git is available
	if _, err := exec.LookPath("git"); err != nil {
		return false, nil // Git not available, skip silently
	}

	// SECURITY: Build restricted environment once for all git commands.
	// This prevents PATH poisoning where an attacker could place a malicious
	// "git" binary in a directory that appears earlier in PATH.
	restrictedEnv := execsafe.BuildRestrictedEnvSafe(os.Environ(), false)

	// Check if already in a git repo (with timeout)
	ctx, cancel := context.WithTimeout(context.Background(), gitCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "git", "rev-parse", "--is-inside-work-tree")
	cmd.Dir = dir
	cmd.Env = restrictedEnv
	if err := cmd.Run(); err == nil {
		return false, nil // Already in a git repo
	}

	// Run git init (with fresh timeout)
	ctx2, cancel2 := context.WithTimeout(context.Background(), gitCommandTimeout)
	defer cancel2()

	cmd = exec.CommandContext(ctx2, "git", "init")
	cmd.Dir = dir
	cmd.Env = restrictedEnv
	if err := cmd.Run(); err != nil {
		return false, err
	}

	return true, nil
}

// IsDirEmpty checks if a directory is empty.
func IsDirEmpty(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	return len(entries) == 0, nil
}

// IsDirNonEmpty checks if a directory exists and is non-empty.
func IsDirNonEmpty(dir string) (bool, error) {
	info, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.IsDir() {
		return false, fmt.Errorf("path exists but is not a directory: %s", dir)
	}

	empty, err := IsDirEmpty(dir)
	if err != nil {
		return false, err
	}
	return !empty, nil
}

// streamIdentifierPattern validates stream format (org/name/env or similar)
var streamIdentifierPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+(/[a-zA-Z0-9_-]+)*$`)

// ValidateStream checks if a stream identifier is valid.
func ValidateStream(stream string) error {
	if stream == "" {
		return fmt.Errorf("stream cannot be empty")
	}
	if !streamIdentifierPattern.MatchString(stream) {
		return fmt.Errorf("invalid stream format: %q (expected format: org/name/env)", stream)
	}
	return nil
}
