package componentsdk

import (
	"bytes"
	"embed"
	"fmt"
	"text/template"

	"github.com/locktivity/epack/internal/componenttypes"
)

//go:embed templates/*.tmpl templates/docs/*.tmpl
var templateFS embed.FS

// templateData holds all template variables.
type templateData struct {
	Name          string // Component name (e.g., "my-analyzer")
	Kind          string // Component kind (e.g., "tool")
	BinaryName    string // Full binary name (e.g., "epack-tool-my-analyzer")
	ModulePath    string // Go module path
	ConfigSection string // YAML config section (e.g., "tools", "collectors")
	GOOS          string // Target OS for SLSA configs (e.g., "linux", "darwin")
	GOARCH        string // Target architecture for SLSA configs (e.g., "amd64", "arm64")
}

// newTemplateData creates template data from scaffold options.
func newTemplateData(name string, kind componenttypes.ComponentKind, modulePath string) templateData {
	// Determine config section (plural form for YAML)
	configSection := string(kind) + "s"
	if kind == componenttypes.KindUtility {
		configSection = "utilities"
	}

	return templateData{
		Name:          name,
		Kind:          string(kind),
		BinaryName:    fmt.Sprintf("epack-%s-%s", kind, name),
		ModulePath:    modulePath,
		ConfigSection: configSection,
	}
}

// renderTemplate renders a template by name with the given data.
func renderTemplate(name string, data templateData) (string, error) {
	tmplContent, err := templateFS.ReadFile("templates/" + name)
	if err != nil {
		return "", fmt.Errorf("failed to read template %s: %w", name, err)
	}

	tmpl, err := template.New(name).Parse(string(tmplContent))
	if err != nil {
		return "", fmt.Errorf("failed to parse template %s: %w", name, err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template %s: %w", name, err)
	}

	return buf.String(), nil
}

// generateMainGo generates main.go content for the given component kind.
func generateMainGo(name string, kind componenttypes.ComponentKind) (string, error) {
	templateName := string(kind) + ".main.go.tmpl"
	data := newTemplateData(name, kind, "")
	return renderTemplate(templateName, data)
}

// generateGoMod generates go.mod content.
func generateGoMod(modulePath string) (string, error) {
	data := templateData{ModulePath: modulePath}
	return renderTemplate("go.mod.tmpl", data)
}

// generateReleaseWorkflow generates .github/workflows/release.yaml content.
func generateReleaseWorkflow(name string, kind componenttypes.ComponentKind) (string, error) {
	data := newTemplateData(name, kind, "")
	return renderTemplate("release.yaml.tmpl", data)
}

// generateReadme generates README.md content.
func generateReadme(name string, kind componenttypes.ComponentKind, modulePath string) (string, error) {
	data := newTemplateData(name, kind, modulePath)
	return renderTemplate("readme.md.tmpl", data)
}

// generateGitignore generates .gitignore content.
func generateGitignore(name string, kind componenttypes.ComponentKind) (string, error) {
	data := newTemplateData(name, kind, "")
	return renderTemplate("gitignore.tmpl", data)
}

// generateDocsOverview generates docs/overview.md content.
func generateDocsOverview(name string, kind componenttypes.ComponentKind) (string, error) {
	data := newTemplateData(name, kind, "")
	return renderTemplate("docs/overview.md.tmpl", data)
}

// generateDocsConfiguration generates docs/configuration.md content.
func generateDocsConfiguration(name string, kind componenttypes.ComponentKind) (string, error) {
	data := newTemplateData(name, kind, "")
	return renderTemplate("docs/configuration.md.tmpl", data)
}

// generateDocsExamples generates docs/examples.md content.
func generateDocsExamples(name string, kind componenttypes.ComponentKind) (string, error) {
	data := newTemplateData(name, kind, "")
	return renderTemplate("docs/examples.md.tmpl", data)
}

// generateSLSAGoreleaser generates a .slsa-goreleaser config for a specific platform.
func generateSLSAGoreleaser(name string, kind componenttypes.ComponentKind, goos, goarch string) (string, error) {
	data := newTemplateData(name, kind, "")
	data.GOOS = goos
	data.GOARCH = goarch
	return renderTemplate("slsa-goreleaser.yaml.tmpl", data)
}

// generateCIWorkflow generates .github/workflows/ci.yaml content.
func generateCIWorkflow(name string, kind componenttypes.ComponentKind) (string, error) {
	data := newTemplateData(name, kind, "")
	return renderTemplate("ci.yaml.tmpl", data)
}
