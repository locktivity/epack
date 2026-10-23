// Package componentsdk provides tools for component SDK authors.
// It includes scaffolding, development running, testing, and mock generation.
package componentsdk

import (
	"fmt"
	"path/filepath"

	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/safefile"
	"github.com/locktivity/epack/internal/tracemap"
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

	// Repository is the GitHub repository, as owner/name, that a collector's
	// docs name as its source. It starts with OWNER/ when the module path is
	// not on github.com or has no owner yet.
	Repository string
}

// scaffoldFile is one file a scaffold writes: its path in the project and
// the template that renders it.
type scaffoldFile struct {
	path     string
	template string
	goos     string
	goarch   string
	// traceMap marks a trace map, written in the order epack sdk map
	// writes it once its names are filled in.
	traceMap bool
}

// Scaffold creates a component project in the target directory.
// The directory must already exist.
//
// A collector gets the layout the epack collectors share: the entrypoint in
// cmd/<binary>, its spec, handler, and gap records in internal/collector, a
// vendor client in internal/<vendor package>, its artifact's schema and
// trace map in docs/schema, a collectortest suite with a hand-written
// scenario and the one a test records from a sandbox, CI that calls epack's
// shared collector workflow, and release workflows that can hold a release
// as a draft until the sandbox check passes. Other kinds keep main.go at the
// project root.
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
		Repository:   data.Repository,
	}

	for _, file := range scaffoldFiles(opts.Kind, binaryName, data.VendorPackage) {
		fileData := data
		fileData.GOOS, fileData.GOARCH = file.goos, file.goarch
		content, err := renderTemplate(file.template, fileData)
		if err != nil {
			return nil, fmt.Errorf("failed to generate %s: %w", file.path, err)
		}
		if file.traceMap {
			canonical, err := tracemap.Canonical([]byte(content))
			if err != nil {
				return nil, fmt.Errorf("failed to generate %s: %w", file.path, err)
			}
			content = string(canonical)
		}
		if err := safefile.WriteFile(opts.TargetDir, filepath.FromSlash(file.path), []byte(content)); err != nil {
			return nil, fmt.Errorf("failed to create %s: %w", file.path, err)
		}
		result.FilesCreated = append(result.FilesCreated, file.path)
	}
	return result, nil
}

func scaffoldFiles(kind componenttypes.ComponentKind, binaryName, vendorPackage string) []scaffoldFile {
	var files []scaffoldFile
	readme, ci, release := "readme.md.tmpl", "ci.yaml.tmpl", "release.yaml.tmpl"
	configuration, examples := "docs/configuration.md.tmpl", "docs/examples.md.tmpl"
	if kind == componenttypes.KindCollector {
		files = append(files,
			scaffoldFile{path: "cmd/" + binaryName + "/main.go", template: "collector.main.go.tmpl"},
			scaffoldFile{path: "internal/collector/handler.go", template: "collector.handler.go.tmpl"},
			scaffoldFile{path: "internal/collector/config.go", template: "collector.config.go.tmpl"},
			scaffoldFile{path: "internal/collector/collector.go", template: "collector.go.tmpl"},
			scaffoldFile{path: "internal/collector/gaps.go", template: "collector.gaps.go.tmpl"},
			scaffoldFile{path: "internal/collector/collectortest_test.go", template: "collector.collectortest_test.go.tmpl"},
			scaffoldFile{path: "internal/collector/fixtures_test.go", template: "collector.fixtures_test.go.tmpl"},
			scaffoldFile{path: "internal/collector/record_test.go", template: "collector.record_test.go.tmpl"},
			scaffoldFile{path: "internal/collector/recording_scrub_test.go", template: "collector.recording_scrub_test.go.tmpl"},
			scaffoldFile{path: "internal/" + vendorPackage + "/client.go", template: "collector.client.go.tmpl"},
			scaffoldFile{path: "docs/schema/v1.0.0.json", template: "collector.schema.json.tmpl"},
			scaffoldFile{path: "docs/schema/embed.go", template: "collector.schema.embed.go.tmpl"},
			scaffoldFile{path: "docs/schema/trace-map.json", template: "collector.trace-map.json.tmpl", traceMap: true},
			scaffoldFile{path: "docs/levels.md", template: "docs/collector.levels.md.tmpl"},
			scaffoldFile{path: "testdata/conformance.json", template: "collector.conformance.json.tmpl"},
			scaffoldFile{path: "Makefile", template: "collector.makefile.tmpl"},
			scaffoldFile{path: "LICENSE", template: "collector.license.tmpl"},
			scaffoldFile{path: ".github/workflows/publish.yaml", template: "collector.publish.yaml.tmpl"},
		)
		readme, ci, release = "collector.readme.md.tmpl", "collector.ci.yaml.tmpl", "collector.release.yaml.tmpl"
		configuration, examples = "docs/collector.configuration.md.tmpl", "docs/collector.examples.md.tmpl"
	} else {
		files = append(files, scaffoldFile{path: "main.go", template: string(kind) + ".main.go.tmpl"})
	}
	files = append(files,
		scaffoldFile{path: "go.mod", template: "go.mod.tmpl"},
		scaffoldFile{path: "README.md", template: readme},
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
		scaffoldFile{path: ".github/workflows/ci.yaml", template: ci},
		scaffoldFile{path: ".github/workflows/release.yaml", template: release},
		scaffoldFile{path: "docs/overview.md", template: "docs/overview.md.tmpl"},
		scaffoldFile{path: "docs/configuration.md", template: configuration},
		scaffoldFile{path: "docs/examples.md", template: examples},
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
