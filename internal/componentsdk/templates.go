package componentsdk

import (
	"bytes"
	"embed"
	"fmt"
	"regexp"
	"strings"
	"text/template"

	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/version"
)

//go:embed templates/*.tmpl templates/docs/*.tmpl
var templateFS embed.FS

// templateData holds all template variables.
type templateData struct {
	Name          string // Component name (e.g., "my-analyzer")
	Kind          string // Component kind (e.g., "tool")
	BinaryName    string // Full binary name (e.g., "epack-tool-my-analyzer")
	ModulePath    string // Go module path
	MainPackage   string // Package to build (e.g., ".", "./cmd/epack-collector-github")
	ConfigSection string // YAML config section (e.g., "tools", "collectors")
	GOOS          string // Target OS for SLSA configs (e.g., "linux", "darwin")
	GOARCH        string // Target architecture for SLSA configs (e.g., "amd64", "arm64")
	EpackVersion  string // epack module version for go.mod (e.g., "v0.5.3"); empty to let go mod tidy pick
}

// newTemplateData creates template data from scaffold options.
func newTemplateData(name string, kind componenttypes.ComponentKind, modulePath string) templateData {
	binaryName := fmt.Sprintf("epack-%s-%s", kind, name)
	mainPackage := "."
	if kind == componenttypes.KindCollector {
		mainPackage = "./cmd/" + binaryName
	}
	return templateData{
		Name:          name,
		Kind:          string(kind),
		BinaryName:    binaryName,
		ModulePath:    modulePath,
		MainPackage:   mainPackage,
		ConfigSection: kind.Plural(),
		EpackVersion:  epackModuleVersion(version.Version),
	}
}

// releaseVersion matches the versions a release build of epack reports,
// with or without the v prefix.
var releaseVersion = regexp.MustCompile(`^v?\d+\.\d+\.\d+(-(alpha|beta|rc)(\.\d+)?)?$`)

// epackModuleVersion is the epack module version a scaffold requires: this
// build's own release, with the v prefix Go needs. A source build reports
// "dev" and a build past a tag reports a git describe string; neither is a
// module version, so go mod tidy picks the latest release instead.
func epackModuleVersion(v string) string {
	if !releaseVersion.MatchString(v) {
		return ""
	}
	return "v" + strings.TrimPrefix(v, "v")
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
