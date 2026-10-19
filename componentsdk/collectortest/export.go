package collectortest

import (
	"cmp"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/packpath"
	"github.com/locktivity/epack/internal/safefile"
)

// outEnv names the directory scenario runs write their output under.
const outEnv = "COLLECTORTEST_OUT"

// exporter writes what each scenario run emitted to
// $COLLECTORTEST_OUT/<suite>/<scenario>/, each artifact at its path in a
// pack, and lists them in <suite>/scenarios.json, so the output of two
// versions of a collector can be compared scenario by scenario.
type exporter struct {
	root  string
	dir   string
	used  map[string]bool
	index exportIndex
}

// exportIndex is scenarios.json.
type exportIndex struct {
	Suite     string           `json:"suite"`
	Scenarios []exportScenario `json:"scenarios"`
}

type exportScenario struct {
	Name      string           `json:"name"`
	Dir       string           `json:"dir"`
	ExitCode  int              `json:"exit_code"`
	Failure   *exportFailure   `json:"failure,omitempty"`
	Artifacts []exportArtifact `json:"artifacts"`
}

type exportFailure struct {
	Code    componentsdk.Code `json:"code"`
	Message string            `json:"message,omitempty"`
}

// exportArtifact lists an artifact by its path in a pack and its schema ID,
// "" for none, which a pack built from the output needs.
type exportArtifact struct {
	Path   string `json:"path"`
	Schema string `json:"schema"`
	File   bool   `json:"file,omitempty"`
}

// newExporter returns the suite's exporter, or nil when COLLECTORTEST_OUT is
// unset. It clears what an earlier run wrote for the suite.
func newExporter(s Suite) (*exporter, error) {
	root := os.Getenv(outEnv)
	if root == "" {
		return nil, nil
	}
	name := cmp.Or(s.Name, s.Spec.Name)
	e := &exporter{
		root:  root,
		dir:   cmp.Or(slug(name), "suite"),
		used:  map[string]bool{},
		index: exportIndex{Suite: name, Scenarios: []exportScenario{}},
	}
	if err := safefile.EnsureBaseDir(root); err != nil {
		return nil, err
	}
	if err := os.RemoveAll(filepath.Join(root, e.dir)); err != nil {
		return nil, err
	}
	return e, nil
}

// add writes a scenario run's artifacts, data artifacts as their bytes and
// file artifacts copied from the run's staging directory.
func (e *exporter) add(label string, res componentsdk.InProcessResult, outputDir string) error {
	entry := exportScenario{Name: label, Dir: e.scenarioDir(label), ExitCode: res.ExitCode, Artifacts: []exportArtifact{}}
	if res.Failure != nil {
		entry.Failure = &exportFailure{Code: res.Failure.Code, Message: res.Failure.Message}
	}
	dir := filepath.Join(e.dir, entry.Dir)
	if err := safefile.MkdirAll(e.root, filepath.Join(e.root, dir)); err != nil {
		return err
	}
	for _, a := range res.Artifacts {
		path := a.Path
		if err := packpath.ValidateArtifactPath(path); err != nil {
			return fmt.Errorf("artifact %q: %w", path, err)
		}
		data := []byte(a.Data)
		if a.File != "" {
			var err error
			if data, err = safefile.ReadFileBeneath(outputDir, filepath.FromSlash(a.File), limits.Artifact); err != nil {
				return fmt.Errorf("reading staged file %s: %w", a.File, err)
			}
		}
		if err := safefile.WriteFile(e.root, filepath.Join(dir, filepath.FromSlash(path)), data); err != nil {
			return err
		}
		entry.Artifacts = append(entry.Artifacts, exportArtifact{Path: path, Schema: a.Schema, File: a.File != ""})
	}
	e.index.Scenarios = append(e.index.Scenarios, entry)
	return nil
}

func (e *exporter) finish() error {
	return safefile.WriteJSON(e.root, filepath.Join(e.dir, "scenarios.json"), e.index)
}

// scenarioDir returns the directory for a scenario: its name as a slug, with
// a number after it when another scenario took that slug.
func (e *exporter) scenarioDir(label string) string {
	base := cmp.Or(slug(label), "scenario")
	dir := base
	for n := 2; e.used[dir]; n++ {
		dir = base + "-" + strconv.Itoa(n)
	}
	e.used[dir] = true
	return dir
}

// slug lowercases s and turns each run of other characters than ASCII
// letters and digits into one hyphen, trimmed from the ends.
func slug(s string) string {
	var b strings.Builder
	pending := false
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			if pending && b.Len() > 0 {
				b.WriteByte('-')
			}
			pending = false
			b.WriteRune(r)
			continue
		}
		pending = true
	}
	return b.String()
}
