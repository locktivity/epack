// Package componentsdk provides tools for component SDK authors.
// It includes scaffolding, development running, testing, and mock generation.
package componentsdk

import (
	"fmt"
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

	// ModulePath is the Go module path. Empty means
	// github.com/OWNER/epack-<kind>-<name>.
	ModulePath string
}

// ScaffoldResult contains information about what was scaffolded.
type ScaffoldResult struct {
	// FilesCreated is the list of files created (relative to TargetDir).
	FilesCreated []string

	// ModulePath is the generated Go module path.
	ModulePath string

	// BinaryName is the generated binary name (e.g., "epack-tool-foo").
	BinaryName string

	// MainPackage is the package that builds the binary (e.g., ".").
	MainPackage string

	// EpackVersion is the epack version go.mod requires, or "" when this
	// epack is a source build and go.mod requires none.
	EpackVersion string
}

// scaffoldFile is one file a scaffold writes: its path in the project and
// the template that renders it.
type scaffoldFile struct {
	path     string
	template string
	goos     string
	goarch   string
}

// Scaffold creates a component project in the target directory.
// The directory must already exist.
//
// A collector gets the layout the epack collectors share: the entrypoint in
// cmd/<binary>, collection logic in internal/collector, a Makefile, and a
// testdata/conformance.json config that CI passes to the conformance harness.
// Other kinds keep main.go at the project root.
func Scaffold(opts ScaffoldOptions) (*ScaffoldResult, error) {
	binaryName := fmt.Sprintf("epack-%s-%s", opts.Kind, opts.Name)
	modulePath := opts.ModulePath
	if modulePath == "" {
		modulePath = "github.com/OWNER/" + binaryName
	}
	data := newTemplateData(opts.Name, opts.Kind, modulePath)
	result := &ScaffoldResult{
		FilesCreated: make([]string, 0),
		ModulePath:   modulePath,
		BinaryName:   binaryName,
		MainPackage:  data.MainPackage,
		EpackVersion: data.EpackVersion,
	}

	for _, file := range scaffoldFiles(opts.Kind, binaryName) {
		fileData := data
		fileData.GOOS, fileData.GOARCH = file.goos, file.goarch
		content, err := renderTemplate(file.template, fileData)
		if err != nil {
			return nil, fmt.Errorf("failed to generate %s: %w", file.path, err)
		}
		if err := safefile.WriteFile(opts.TargetDir, filepath.FromSlash(file.path), []byte(content)); err != nil {
			return nil, fmt.Errorf("failed to create %s: %w", file.path, err)
		}
		result.FilesCreated = append(result.FilesCreated, file.path)
	}
	return result, nil
}

func scaffoldFiles(kind componenttypes.ComponentKind, binaryName string) []scaffoldFile {
	var files []scaffoldFile
	if kind == componenttypes.KindCollector {
		files = append(files,
			scaffoldFile{path: "cmd/" + binaryName + "/main.go", template: "collector.main.go.tmpl"},
			scaffoldFile{path: "internal/collector/collector.go", template: "collector.go.tmpl"},
			scaffoldFile{path: "internal/collector/collector_test.go", template: "collector_test.go.tmpl"},
			scaffoldFile{path: "testdata/conformance.json", template: "collector.conformance.json.tmpl"},
			scaffoldFile{path: "Makefile", template: "collector.makefile.tmpl"},
		)
	} else {
		files = append(files, scaffoldFile{path: "main.go", template: string(kind) + ".main.go.tmpl"})
	}
	files = append(files,
		scaffoldFile{path: "go.mod", template: "go.mod.tmpl"},
		scaffoldFile{path: "README.md", template: "readme.md.tmpl"},
		scaffoldFile{path: ".gitignore", template: "gitignore.tmpl"},
	)
	for _, p := range []struct{ goos, goarch string }{
		{"linux", "amd64"},
		{"linux", "arm64"},
		{"darwin", "amd64"},
		{"darwin", "arm64"},
	} {
		files = append(files, scaffoldFile{
			path:     fmt.Sprintf(".slsa-goreleaser/%s-%s-%s.yml", binaryName, p.goos, p.goarch),
			template: "slsa-goreleaser.yaml.tmpl",
			goos:     p.goos,
			goarch:   p.goarch,
		})
	}
	return append(files,
		scaffoldFile{path: ".github/workflows/ci.yaml", template: "ci.yaml.tmpl"},
		scaffoldFile{path: ".github/workflows/release.yaml", template: "release.yaml.tmpl"},
		scaffoldFile{path: "docs/overview.md", template: "docs/overview.md.tmpl"},
		scaffoldFile{path: "docs/configuration.md", template: "docs/configuration.md.tmpl"},
		scaffoldFile{path: "docs/examples.md", template: "docs/examples.md.tmpl"},
	)
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
