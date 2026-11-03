package shadow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/locktivity/epack/internal/collector"
	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/dispatch"
)

// Validation is the part of a validator's validation.json that a shadow
// reads: each requirement's result.
type Validation struct {
	Profile struct {
		ID string `json:"id"`
	} `json:"profile"`
	Requirements []Requirement `json:"requirements"`
}

// Requirement is one requirement's result. Actual is the value it read,
// which goes only into the preview.
type Requirement struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Status      string `json:"status"`
	FailureKind string `json:"failure_kind,omitempty"`
	Actual      any    `json:"actual,omitempty"`
}

// Validator validates the pack at packPath, writing into outputDir.
type Validator func(ctx context.Context, packPath, outputDir string) (*Validation, error)

// ControlChange is a requirement whose result the candidate changes, such
// as from pass to unknown, which the app shows as Met to Not collected.
type ControlChange struct {
	Profile string `json:"profile"`
	ID      string `json:"id"`
	Name    string `json:"name,omitempty"`
	From    string `json:"from"`
	To      string `json:"to"`
}

// ControlValue is the value a requirement read in the locked run and in the
// candidate's, for the preview.
type ControlValue struct {
	ID   string `json:"id"`
	From any    `json:"from,omitempty"`
	To   any    `json:"to,omitempty"`
}

// validateTool returns the name of the project's validate tool: the one
// named validate, or the one whose source is epack-tool-validate.
func validateTool(cfg *config.JobConfig) string {
	if _, ok := cfg.Tools["validate"]; ok {
		return "validate"
	}
	names := make([]string, 0, len(cfg.Tools))
	for name := range cfg.Tools {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if strings.Contains(cfg.Tools[name].Source, "epack-tool-validate") {
			return name
		}
	}
	return ""
}

// controlCheck checks the controls on each run's pack and adds how the
// candidate changes their results to the report.
type controlCheck interface {
	// packer returns how to build the pack of the run labeled label, pinned
	// to pinned, or nil when the run needs no pack.
	packer(label string, pinned *lockfile.LockFile) func([]collector.RunResult) (string, error)
	check(ctx context.Context, outs trio[RunOutput], packs trio[string], rep *Report, preview *Preview)
}

// newControlCheck returns the check for the validator in opts, or else the
// project's validate tool. Packs go in packDir, and each validation in its
// own directory under scratch.
func newControlCheck(cfg *config.JobConfig, opts Options, scratch, packDir string) controlCheck {
	validate := opts.Validate
	if validate == nil {
		tool := validateTool(cfg)
		if tool == "" {
			return noControlCheck("epack.yaml configures no validate tool")
		}
		validate = dispatchValidator(tool, opts.Getenv)
	}
	return validatorCheck{validate: validate, cfg: cfg, scratch: scratch, packDir: packDir}
}

// noControlCheck is the special case of a project with no validate tool. It
// builds no packs and says why there are no control results.
type noControlCheck string

func (noControlCheck) packer(string, *lockfile.LockFile) func([]collector.RunResult) (string, error) {
	return nil
}

func (reason noControlCheck) check(_ context.Context, _ trio[RunOutput], _ trio[string], rep *Report, _ *Preview) {
	rep.ControlsSkipped = string(reason)
}

// validatorCheck builds each run's pack and validates it.
type validatorCheck struct {
	validate         Validator
	cfg              *config.JobConfig
	scratch, packDir string
}

func (v validatorCheck) packer(label string, pinned *lockfile.LockFile) func([]collector.RunResult) (string, error) {
	return func(results []collector.RunResult) (string, error) {
		path := filepath.Join(v.packDir, label+".epack")
		return path, collector.BuildPack(v.cfg, pinned, results, path)
	}
}

// check validates the packs in the order the runs ran them, each into its
// own directory, and compares the results.
func (v validatorCheck) check(ctx context.Context, outs trio[RunOutput], packs trio[string], rep *Report, preview *Preview) {
	if anyFailed(outs) {
		rep.ControlsSkipped = "a run failed, so there are no packs to validate"
		return
	}
	var results trio[*Validation]
	into := results.inRunOrder()
	for i, pack := range packs.inRunOrder() {
		res, err := v.validate(ctx, *pack, filepath.Join(v.scratch, fmt.Sprintf("validation-%d", i)))
		if err != nil {
			rep.ControlsSkipped = fmt.Sprintf("the validate tool failed: %v", err)
			return
		}
		*into[i] = res
	}
	rep.Controls, rep.ControlNoise, preview.Controls = compareControls(results)
}

// discard is a dispatch.Output that keeps the tool runner's messages out of
// the shadow's own output.
type discard struct{}

func (discard) Stderr() interface{ Write([]byte) (int, error) } { return io.Discard }

// dispatchValidator runs the project's validate tool through epack's tool
// runner, with the digest checks any tool run makes, and reads the
// validation.json it writes under the run's output directory.
func dispatchValidator(tool string, getenv func(string) string) Validator {
	return func(ctx context.Context, packPath, outputDir string) (*Validation, error) {
		runErr := dispatch.ToolWithFlags(ctx, discard{}, tool, nil, dispatch.WrapperFlags{
			PackPath: packPath, OutputDir: outputDir, QuietMode: true, Getenv: getenv,
		})
		if runErr != nil {
			if msg := toolErrors(outputDir); msg != "" {
				return nil, errors.New(msg)
			}
			return nil, runErr
		}
		path := findFile(outputDir, "validation.json")
		if path == "" {
			if msg := toolErrors(outputDir); msg != "" {
				return nil, errors.New(msg)
			}
			return nil, fmt.Errorf("the %s tool wrote no validation.json", tool)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var v Validation
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&v); err != nil {
			return nil, fmt.Errorf("reading validation.json: %w", err)
		}
		return &v, nil
	}
}

// findFile returns the first file named name under dir, or "".
func findFile(dir, name string) string {
	found := ""
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err == nil && found == "" && !d.IsDir() && d.Name() == name {
			found = path
		}
		return nil
	})
	return found
}

// toolErrors returns the messages a failed tool run recorded in its
// result.json, or "".
func toolErrors(outputDir string) string {
	path := findFile(outputDir, "result.json")
	if path == "" {
		return ""
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var res struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if json.Unmarshal(raw, &res) != nil {
		return ""
	}
	var msgs []string
	for _, e := range res.Errors {
		if e.Message != "" {
			msgs = append(msgs, e.Message)
		}
	}
	return strings.Join(msgs, "; ")
}

// compareControls lists each requirement whose result differs between the
// first locked run and the candidate's. A requirement whose result also
// differs between the two locked runs is noise. Only the requirements the
// first locked run or the candidate's lists are compared, and one a run
// does not list reads there as the status "".
func compareControls(results trio[*Validation]) (changes []ControlChange, noise []string, values []ControlValue) {
	index := func(v *Validation) map[string]Requirement {
		out := map[string]Requirement{}
		for _, r := range v.Requirements {
			out[r.ID] = r
		}
		return out
	}
	reqs := mapTrio(results, index)
	ids := map[string]bool{}
	for id := range reqs.Locked1 {
		ids[id] = true
	}
	for id := range reqs.Candidate {
		ids[id] = true
	}
	statuses := mapTrio(reqs, func(r map[string]Requirement) map[string]string {
		out := map[string]string{}
		for id := range ids {
			out[id] = r[id].Status
		}
		return out
	})
	verdicts := threeWay(statuses, func(a, b string) bool { return a == b })
	for _, id := range sortedKeys(verdicts) {
		switch verdicts[id] {
		case noisy:
			noise = append(noise, id)
		case changed:
			a, b := reqs.Locked1[id], reqs.Candidate[id]
			name := b.Name
			if name == "" {
				name = a.Name
			}
			changes = append(changes, ControlChange{Profile: results.Candidate.Profile.ID, ID: id, Name: name, From: a.Status, To: b.Status})
			values = append(values, ControlValue{ID: id, From: a.Actual, To: b.Actual})
		}
	}
	return changes, noise, values
}
