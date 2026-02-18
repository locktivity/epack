// Package componentsdk provides tools for component SDK authors.
// It includes scaffolding, development running, testing, and mock generation.
package componentsdk

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/safefile"
)

// ScaffoldOptions configures the component scaffolding.
type ScaffoldOptions struct {
	// TargetDir is the directory to scaffold into (must exist).
	TargetDir string

	// Name is the component name (without epack-<kind>- prefix).
	Name string

	// Kind is the component kind (tool, collector, remote, utility).
	Kind componenttypes.ComponentKind
}

// ScaffoldResult contains information about what was scaffolded.
type ScaffoldResult struct {
	// FilesCreated is the list of files created (relative to TargetDir).
	FilesCreated []string

	// ModulePath is the generated Go module path.
	ModulePath string

	// BinaryName is the generated binary name (e.g., "epack-tool-foo").
	BinaryName string
}

// Scaffold creates a component project in the target directory.
// The directory must already exist.
func Scaffold(opts ScaffoldOptions) (*ScaffoldResult, error) {
	binaryName := fmt.Sprintf("epack-%s-%s", opts.Kind, opts.Name)
	result := &ScaffoldResult{
		FilesCreated: make([]string, 0),
		ModulePath:   fmt.Sprintf("github.com/OWNER/%s", binaryName),
		BinaryName:   binaryName,
	}

	// Create main.go
	mainContent, err := generateMainGo(opts.Name, opts.Kind)
	if err != nil {
		return nil, fmt.Errorf("failed to generate main.go: %w", err)
	}
	if err := safefile.WriteFile(opts.TargetDir, "main.go", []byte(mainContent)); err != nil {
		return nil, fmt.Errorf("failed to create main.go: %w", err)
	}
	result.FilesCreated = append(result.FilesCreated, "main.go")

	// Create go.mod
	goModContent, err := generateGoMod(result.ModulePath)
	if err != nil {
		return nil, fmt.Errorf("failed to generate go.mod: %w", err)
	}
	if err := safefile.WriteFile(opts.TargetDir, "go.mod", []byte(goModContent)); err != nil {
		return nil, fmt.Errorf("failed to create go.mod: %w", err)
	}
	result.FilesCreated = append(result.FilesCreated, "go.mod")

	// Create .slsa-goreleaser/ directory with platform-specific configs for SLSA Level 3 builds
	slsaDir := filepath.Join(opts.TargetDir, ".slsa-goreleaser")
	if err := os.MkdirAll(slsaDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create .slsa-goreleaser directory: %w", err)
	}

	// Generate configs for each supported platform
	platforms := []struct{ goos, goarch string }{
		{"linux", "amd64"},
		{"linux", "arm64"},
		{"darwin", "amd64"},
		{"darwin", "arm64"},
	}
	for _, p := range platforms {
		content, err := generateSLSAGoreleaser(opts.Name, opts.Kind, p.goos, p.goarch)
		if err != nil {
			return nil, fmt.Errorf("failed to generate SLSA config for %s-%s: %w", p.goos, p.goarch, err)
		}
		filename := fmt.Sprintf("%s-%s-%s.yml", binaryName, p.goos, p.goarch)
		if err := safefile.WriteFile(slsaDir, filename, []byte(content)); err != nil {
			return nil, fmt.Errorf("failed to create %s: %w", filename, err)
		}
		result.FilesCreated = append(result.FilesCreated, ".slsa-goreleaser/"+filename)
	}

	// Create .github/workflows directory
	workflowDir := filepath.Join(opts.TargetDir, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create workflows directory: %w", err)
	}

	// Create release.yaml workflow
	releaseContent, err := generateReleaseWorkflow(opts.Name, opts.Kind)
	if err != nil {
		return nil, fmt.Errorf("failed to generate release.yaml: %w", err)
	}
	if err := safefile.WriteFile(workflowDir, "release.yaml", []byte(releaseContent)); err != nil {
		return nil, fmt.Errorf("failed to create release.yaml: %w", err)
	}
	result.FilesCreated = append(result.FilesCreated, ".github/workflows/release.yaml")

	// Create README.md
	readmeContent, err := generateReadme(opts.Name, opts.Kind, result.ModulePath)
	if err != nil {
		return nil, fmt.Errorf("failed to generate README.md: %w", err)
	}
	if err := safefile.WriteFile(opts.TargetDir, "README.md", []byte(readmeContent)); err != nil {
		return nil, fmt.Errorf("failed to create README.md: %w", err)
	}
	result.FilesCreated = append(result.FilesCreated, "README.md")

	// Create .gitignore
	gitignoreContent, err := generateGitignore(opts.Name, opts.Kind)
	if err != nil {
		return nil, fmt.Errorf("failed to generate .gitignore: %w", err)
	}
	if err := safefile.WriteFile(opts.TargetDir, ".gitignore", []byte(gitignoreContent)); err != nil {
		return nil, fmt.Errorf("failed to create .gitignore: %w", err)
	}
	result.FilesCreated = append(result.FilesCreated, ".gitignore")

	// Create docs/ directory for registry documentation
	docsDir := filepath.Join(opts.TargetDir, "docs")
	if err := os.MkdirAll(docsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create docs directory: %w", err)
	}

	// Create docs/overview.md
	overviewContent, err := generateDocsOverview(opts.Name, opts.Kind)
	if err != nil {
		return nil, fmt.Errorf("failed to generate docs/overview.md: %w", err)
	}
	if err := safefile.WriteFile(docsDir, "overview.md", []byte(overviewContent)); err != nil {
		return nil, fmt.Errorf("failed to create docs/overview.md: %w", err)
	}
	result.FilesCreated = append(result.FilesCreated, "docs/overview.md")

	// Create docs/configuration.md
	configContent, err := generateDocsConfiguration(opts.Name, opts.Kind)
	if err != nil {
		return nil, fmt.Errorf("failed to generate docs/configuration.md: %w", err)
	}
	if err := safefile.WriteFile(docsDir, "configuration.md", []byte(configContent)); err != nil {
		return nil, fmt.Errorf("failed to create docs/configuration.md: %w", err)
	}
	result.FilesCreated = append(result.FilesCreated, "docs/configuration.md")

	// Create docs/examples.md
	examplesContent, err := generateDocsExamples(opts.Name, opts.Kind)
	if err != nil {
		return nil, fmt.Errorf("failed to generate docs/examples.md: %w", err)
	}
	if err := safefile.WriteFile(docsDir, "examples.md", []byte(examplesContent)); err != nil {
		return nil, fmt.Errorf("failed to create docs/examples.md: %w", err)
	}
	result.FilesCreated = append(result.FilesCreated, "docs/examples.md")

	return result, nil
}

// ValidateName checks if a component name is valid.
// Names must match ^[a-z0-9][a-z0-9._-]{0,63}$
func ValidateName(name string) error {
	if name == "" {
		return fmt.Errorf("component name cannot be empty")
	}
	if len(name) > 64 {
		return fmt.Errorf("component name too long (max 64 characters)")
	}
	for i, c := range name {
		if i == 0 {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
				return fmt.Errorf("component name must start with lowercase letter or digit")
			}
		} else {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '.' && c != '_' && c != '-' {
				return fmt.Errorf("component name can only contain lowercase letters, digits, dots, underscores, and hyphens")
			}
		}
	}
	return nil
}

// SupportedKinds returns the component kinds that support scaffolding.
func SupportedKinds() []componenttypes.ComponentKind {
	return []componenttypes.ComponentKind{
		componenttypes.KindTool,
		componenttypes.KindCollector,
		componenttypes.KindRemote,
		componenttypes.KindUtility,
	}
}

// ParseKind parses a string into a ComponentKind, returning an error if unsupported.
func ParseKind(s string) (componenttypes.ComponentKind, error) {
	switch s {
	case "tool":
		return componenttypes.KindTool, nil
	case "collector":
		return componenttypes.KindCollector, nil
	case "remote":
		return componenttypes.KindRemote, nil
	case "utility":
		return componenttypes.KindUtility, nil
	default:
		return "", fmt.Errorf("unsupported component type: %s (use: tool, collector, remote, utility)", s)
	}
}
