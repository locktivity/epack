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

	if err := scaffoldRootFiles(opts, result); err != nil {
		return nil, err
	}
	if err := scaffoldSLSAConfigs(opts, binaryName, result); err != nil {
		return nil, err
	}
	if err := scaffoldWorkflows(opts, result); err != nil {
		return nil, err
	}
	if err := scaffoldDocs(opts, result); err != nil {
		return nil, err
	}

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
		if i == 0 && !isValidNameStart(c) {
			return fmt.Errorf("component name must start with lowercase letter or digit")
		}
		if i > 0 && !isValidNameChar(c) {
			return fmt.Errorf("component name can only contain lowercase letters, digits, dots, underscores, and hyphens")
		}
	}
	return nil
}

func scaffoldRootFiles(opts ScaffoldOptions, result *ScaffoldResult) error {
	mainContent, err := generateMainGo(opts.Name, opts.Kind)
	if err != nil {
		return fmt.Errorf("failed to generate main.go: %w", err)
	}
	if err := writeScaffoldFile(opts.TargetDir, "main.go", mainContent, result); err != nil {
		return fmt.Errorf("failed to create main.go: %w", err)
	}

	goModContent, err := generateGoMod(result.ModulePath)
	if err != nil {
		return fmt.Errorf("failed to generate go.mod: %w", err)
	}
	if err := writeScaffoldFile(opts.TargetDir, "go.mod", goModContent, result); err != nil {
		return fmt.Errorf("failed to create go.mod: %w", err)
	}

	readmeContent, err := generateReadme(opts.Name, opts.Kind, result.ModulePath)
	if err != nil {
		return fmt.Errorf("failed to generate README.md: %w", err)
	}
	if err := writeScaffoldFile(opts.TargetDir, "README.md", readmeContent, result); err != nil {
		return fmt.Errorf("failed to create README.md: %w", err)
	}

	gitignoreContent, err := generateGitignore(opts.Name, opts.Kind)
	if err != nil {
		return fmt.Errorf("failed to generate .gitignore: %w", err)
	}
	if err := writeScaffoldFile(opts.TargetDir, ".gitignore", gitignoreContent, result); err != nil {
		return fmt.Errorf("failed to create .gitignore: %w", err)
	}
	return nil
}

func scaffoldSLSAConfigs(opts ScaffoldOptions, binaryName string, result *ScaffoldResult) error {
	slsaDir := filepath.Join(opts.TargetDir, ".slsa-goreleaser")
	if err := os.MkdirAll(slsaDir, 0755); err != nil {
		return fmt.Errorf("failed to create .slsa-goreleaser directory: %w", err)
	}

	platforms := []struct{ goos, goarch string }{
		{"linux", "amd64"},
		{"linux", "arm64"},
		{"darwin", "amd64"},
		{"darwin", "arm64"},
	}
	for _, p := range platforms {
		content, err := generateSLSAGoreleaser(opts.Name, opts.Kind, p.goos, p.goarch)
		if err != nil {
			return fmt.Errorf("failed to generate SLSA config for %s-%s: %w", p.goos, p.goarch, err)
		}
		filename := fmt.Sprintf("%s-%s-%s.yml", binaryName, p.goos, p.goarch)
		if err := writeScaffoldFileWithRecord(slsaDir, filename, ".slsa-goreleaser/"+filename, content, result); err != nil {
			return fmt.Errorf("failed to create %s: %w", filename, err)
		}
	}
	return nil
}

func scaffoldWorkflows(opts ScaffoldOptions, result *ScaffoldResult) error {
	workflowDir := filepath.Join(opts.TargetDir, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0755); err != nil {
		return fmt.Errorf("failed to create workflows directory: %w", err)
	}

	ciContent, err := generateCIWorkflow(opts.Name, opts.Kind)
	if err != nil {
		return fmt.Errorf("failed to generate ci.yaml: %w", err)
	}
	if err := writeScaffoldFileWithRecord(workflowDir, "ci.yaml", ".github/workflows/ci.yaml", ciContent, result); err != nil {
		return fmt.Errorf("failed to create ci.yaml: %w", err)
	}

	releaseContent, err := generateReleaseWorkflow(opts.Name, opts.Kind)
	if err != nil {
		return fmt.Errorf("failed to generate release.yaml: %w", err)
	}
	if err := writeScaffoldFileWithRecord(workflowDir, "release.yaml", ".github/workflows/release.yaml", releaseContent, result); err != nil {
		return fmt.Errorf("failed to create release.yaml: %w", err)
	}

	return nil
}

func scaffoldDocs(opts ScaffoldOptions, result *ScaffoldResult) error {
	docsDir := filepath.Join(opts.TargetDir, "docs")
	if err := os.MkdirAll(docsDir, 0755); err != nil {
		return fmt.Errorf("failed to create docs directory: %w", err)
	}

	overviewContent, err := generateDocsOverview(opts.Name, opts.Kind)
	if err != nil {
		return fmt.Errorf("failed to generate docs/overview.md: %w", err)
	}
	if err := writeScaffoldFileWithRecord(docsDir, "overview.md", "docs/overview.md", overviewContent, result); err != nil {
		return fmt.Errorf("failed to create docs/overview.md: %w", err)
	}

	configContent, err := generateDocsConfiguration(opts.Name, opts.Kind)
	if err != nil {
		return fmt.Errorf("failed to generate docs/configuration.md: %w", err)
	}
	if err := writeScaffoldFileWithRecord(docsDir, "configuration.md", "docs/configuration.md", configContent, result); err != nil {
		return fmt.Errorf("failed to create docs/configuration.md: %w", err)
	}

	examplesContent, err := generateDocsExamples(opts.Name, opts.Kind)
	if err != nil {
		return fmt.Errorf("failed to generate docs/examples.md: %w", err)
	}
	if err := writeScaffoldFileWithRecord(docsDir, "examples.md", "docs/examples.md", examplesContent, result); err != nil {
		return fmt.Errorf("failed to create docs/examples.md: %w", err)
	}
	return nil
}

func writeScaffoldFile(baseDir, relPath, content string, result *ScaffoldResult) error {
	if err := safefile.WriteFile(baseDir, relPath, []byte(content)); err != nil {
		return err
	}
	result.FilesCreated = append(result.FilesCreated, relPath)
	return nil
}

func writeScaffoldFileWithRecord(baseDir, relPath, recordPath, content string, result *ScaffoldResult) error {
	if err := safefile.WriteFile(baseDir, relPath, []byte(content)); err != nil {
		return err
	}
	result.FilesCreated = append(result.FilesCreated, recordPath)
	return nil
}

func isValidNameStart(c rune) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}

func isValidNameChar(c rune) bool {
	return isValidNameStart(c) || c == '.' || c == '_' || c == '-'
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
