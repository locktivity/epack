package componentsdk

import (
	"bytes"
	"embed"
	"fmt"
	"go/token"
	"regexp"
	"slices"
	"strings"
	"text/template"

	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/execsafe"
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
	EpackCommit   string // Commit of that epack release, which collector CI pins; empty for a source build
	VendorPackage string // Go package of a collector's vendor client (e.g., "github")
	TokenEnv      string // Variable a collector reads its API token from (e.g., "GITHUB_API_TOKEN")
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
		EpackCommit:   epackReleaseCommit(version.Version, version.Commit),
		VendorPackage: vendorPackage(name),
		TokenEnv:      tokenEnv(name),
	}
}

var commitSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

// epackReleaseCommit is the commit a release build of epack was built from,
// which a collector's CI pins epack's shared workflow to, so the workflow and
// the SDK in go.mod come from the same release. It is "" for a source build.
func epackReleaseCommit(v, commit string) string {
	if epackModuleVersion(v) == "" || !commitSHA.MatchString(commit) {
		return ""
	}
	return commit
}

// takenPackageNames are the packages a collector scaffold's files name
// alongside its vendor client, and Go's predeclared identifiers, which an
// import of the same name would shadow.
var takenPackageNames = strings.Fields(`collector main schema componentsdk collectortest fmt math testing time
	any append bool byte cap clear close comparable complex complex64 complex128 copy delete
	error false float32 float64 imag int int8 int16 int32 int64 iota len make max min new nil
	panic print println real recover rune string true uint uint8 uint16 uint32 uint64 uintptr`)

// vendorPackage is the collector's name as the Go package of its vendor
// client, such as "googleworkspace" for google-workspace, or "api" when the
// name makes no usable package name.
func vendorPackage(name string) string {
	pkg := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return -1
	}, name)
	if !token.IsIdentifier(pkg) || slices.Contains(takenPackageNames, pkg) {
		return "api"
	}
	return pkg
}

var shellVariable = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// tokenEnv is the variable the collector reads its API token from, such as
// GOOGLE_WORKSPACE_API_TOKEN for google-workspace, or API_TOKEN when the
// name makes no usable variable.
func tokenEnv(name string) string {
	env := strings.NewReplacer("-", "_", ".", "_").Replace(strings.ToUpper(name)) + "_API_TOKEN"
	if !shellVariable.MatchString(env) || execsafe.ValidateSecretName(env) != nil {
		return "API_TOKEN"
	}
	return env
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
