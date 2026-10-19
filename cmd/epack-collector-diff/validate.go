package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/locktivity/epack/internal/execsafe"
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/procexec"
	"github.com/locktivity/epack/internal/safefile"
	"github.com/locktivity/epack/internal/timestamp"
	"github.com/locktivity/epack/internal/toolprotocol"
	"github.com/locktivity/epack/pack/builder"
)

const (
	validateTimeout = 2 * time.Minute
	validationFile  = "validation.json"
)

// validation is the part of epack-tool-validate's output the diff reads.
type validation struct {
	Profile      profileInfo   `json:"profile"`
	Requirements []requirement `json:"requirements"`
}

type profileInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type requirement struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	Severity string `json:"severity,omitempty"`
}

type outcome struct {
	Status   string `json:"status"`
	Severity string `json:"severity,omitempty"`
}

// validator runs epack-tool-validate the way epack tool runs a tool: in a
// run directory of its own, with the protocol environment, and with its
// config in a file named by EPACK_TOOL_CONFIG.
type validator struct {
	bin         string
	projectRoot string
	config      string
	work        string
	collectedAt string
	runs        int
}

// addControls validates both sides of every scenario present in both trees
// and adds a change for each requirement whose status or severity differs.
func addControls(ctx context.Context, r *report, base, head *tree, opts options) error {
	v, cleanup, err := newValidator(opts.validate, opts.profile)
	if err != nil {
		return err
	}
	defer cleanup()
	for i := range r.Scenarios {
		sr := &r.Scenarios[i]
		if sr.Status != statusCompared {
			continue
		}
		key := sr.Suite + "/" + sr.Scenario
		before, err := v.validate(ctx, base.scenarios[key], base, head)
		if err != nil {
			return fmt.Errorf("validating %s in --base: %w", key, err)
		}
		after, err := v.validate(ctx, head.scenarios[key], head, base)
		if err != nil {
			return fmt.Errorf("validating %s in --head: %w", key, err)
		}
		sr.Changes = append(sr.Changes, compareControls(before, after)...)
		if r.Profile == nil {
			r.Profile = &after.Profile
		}
	}
	return nil
}

func newValidator(bin, profile string) (*validator, func(), error) {
	if !strings.ContainsAny(bin, `/\`) {
		found, err := procexec.LookPath(bin)
		if err != nil {
			return nil, nil, fmt.Errorf("finding --validate: %w", err)
		}
		bin = found
	}
	bin, err := filepath.Abs(bin)
	if err != nil {
		return nil, nil, err
	}
	if info, err := os.Stat(bin); err != nil {
		return nil, nil, fmt.Errorf("--validate: %w", err)
	} else if info.IsDir() {
		return nil, nil, fmt.Errorf("--validate: %s is a directory", bin)
	}
	// The validator refuses a profile that is a symlink.
	profilePath, err := filepath.EvalSymlinks(profile)
	if err == nil {
		profilePath, err = filepath.Abs(profilePath)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("--profile: %w", err)
	}
	if info, err := os.Stat(profilePath); err != nil {
		return nil, nil, fmt.Errorf("--profile: %w", err)
	} else if info.IsDir() {
		return nil, nil, fmt.Errorf("--profile: %s is a directory", profile)
	}
	// The validator takes profile paths relative to EPACK_PROJECT_ROOT only.
	config, removeConfig, err := execsafe.WriteSecureConfigFile(map[string]any{"profile": filepath.Base(profilePath)}, "epack-tool-config-*")
	if err != nil {
		return nil, nil, err
	}
	work, err := os.MkdirTemp("", "epack-collector-diff-*")
	if err != nil {
		removeConfig()
		return nil, nil, err
	}
	v := &validator{
		bin:         bin,
		projectRoot: filepath.Dir(profilePath),
		config:      config,
		work:        work,
		collectedAt: timestamp.Now().String(),
	}
	cleanup := func() {
		removeConfig()
		_ = os.RemoveAll(work)
	}
	return v, cleanup, nil
}

// validate builds a pack of one scenario run's artifacts and returns what
// the validator made of it.
func (v *validator) validate(ctx context.Context, sc *scenario, t, other *tree) (*validation, error) {
	v.runs++
	dir := filepath.Join(v.work, strconv.Itoa(v.runs))
	if err := os.Mkdir(dir, limits.PrivateDirMode); err != nil {
		return nil, err
	}
	packPath := filepath.Join(dir, "scenario.epack")
	if err := v.buildPack(packPath, sc, t, other); err != nil {
		return nil, fmt.Errorf("building a pack: %w", err)
	}
	runID, runDir, err := toolprotocol.CreateRunDir(filepath.Join(dir, "scenario.runs"), "validate", true)
	if err != nil {
		return nil, err
	}
	env := append(execsafe.BuildRestrictedEnvSafe(os.Environ(), false),
		"EPACK_RUN_ID="+runID,
		"EPACK_RUN_DIR="+runDir,
		"EPACK_STARTED_AT="+toolprotocol.FormatTimestamp(time.Now()),
		"EPACK_TOOL_NAME=validate",
		"EPACK_PROTOCOL_VERSION=1",
		"EPACK_PACK_PATH="+packPath,
		"EPACK_TOOL_CONFIG="+v.config,
		"EPACK_PROJECT_ROOT="+v.projectRoot,
	)
	res, runErr := procexec.RunCapture(ctx, procexec.Spec{Path: v.bin, Dir: runDir, Env: env, Timeout: validateTimeout})
	result, err := readResult(runDir)
	if err != nil {
		if runErr != nil {
			return nil, fmt.Errorf("running %s: %v%s", v.bin, runErr, stderrTail(res.Stderr))
		}
		return nil, err
	}
	if result.Status == "failure" {
		return nil, fmt.Errorf("the validator failed: %s", errorMessages(result.Errors))
	}
	for _, out := range result.Outputs {
		if filepath.Base(out.Path) == validationFile {
			return readValidation(runDir, out.Path)
		}
	}
	return nil, fmt.Errorf("the validator wrote no %s", validationFile)
}

// buildPack adds the scenario's files under artifacts/, each with its schema
// from the index when it is JSON, since the validator decodes every artifact
// that has a schema. All artifacts get one collection time, so freshness
// checks treat both sides alike.
func (v *validator) buildPack(path string, sc *scenario, t, other *tree) error {
	b := builder.New("collectortest/" + sc.key())
	for _, p := range sortedKeys(sc.files) {
		if !strings.HasPrefix(p, "artifacts/") {
			continue
		}
		opts := builder.ArtifactOptions{CollectedAt: v.collectedAt}
		if _, ok := decodeJSON(sc.files[p]); ok {
			opts.Schema = t.schema(sc.key(), p, other)
		}
		if err := b.AddBytesWithOptions(p, sc.files[p], opts); err != nil {
			return err
		}
	}
	return b.Build(path)
}

func readResult(runDir string) (*toolprotocol.Result, error) {
	data, err := safefile.ReadFileBeneath(runDir, "result.json", limits.ToolResult)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errors.New("the validator wrote no result.json")
	}
	if err != nil {
		return nil, fmt.Errorf("reading the validator's result.json: %w", err)
	}
	var result toolprotocol.Result
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("reading the validator's result.json: %w", err)
	}
	return &result, nil
}

func readValidation(runDir, path string) (*validation, error) {
	if err := toolprotocol.ValidateOutputPath(runDir, path); err != nil {
		return nil, err
	}
	data, err := safefile.ReadFileBeneath(runDir, filepath.FromSlash(path), limits.Artifact)
	if err != nil {
		return nil, fmt.Errorf("reading the validator's %s: %w", validationFile, err)
	}
	var val validation
	if err := json.Unmarshal(data, &val); err != nil {
		return nil, fmt.Errorf("reading the validator's %s: %w", validationFile, err)
	}
	return &val, nil
}

func compareControls(base, head *validation) []change {
	before := map[string]requirement{}
	for _, req := range base.Requirements {
		before[req.ID] = req
	}
	seen := map[string]bool{}
	var changes []change
	for _, req := range head.Requirements {
		seen[req.ID] = true
		prev, ok := before[req.ID]
		switch {
		case !ok:
			changes = append(changes, controlChange(kindStatusChanged, req, nil, &req))
		case prev.Status != req.Status:
			changes = append(changes, controlChange(kindStatusChanged, req, &prev, &req))
		case prev.Severity != req.Severity:
			changes = append(changes, controlChange(kindSeverityChanged, req, &prev, &req))
		}
	}
	for _, req := range base.Requirements {
		if !seen[req.ID] {
			changes = append(changes, controlChange(kindStatusChanged, req, &req, nil))
		}
	}
	return changes
}

func controlChange(kind string, req requirement, base, head *requirement) change {
	c := change{Kind: kind, Requirement: req.ID, Name: req.Name}
	if base != nil {
		c.Base = mustJSON(outcome{Status: base.Status, Severity: base.Severity})
	}
	if head != nil {
		c.Head = mustJSON(outcome{Status: head.Status, Severity: head.Severity})
	}
	return c
}

func errorMessages(entries []toolprotocol.ErrorEntry) string {
	if len(entries) == 0 {
		return "no error given"
	}
	messages := make([]string, len(entries))
	for i, e := range entries {
		messages[i] = e.Message
	}
	return strings.Join(messages, "; ")
}

func stderrTail(stderr []byte) string {
	s := strings.TrimSpace(string(stderr))
	if s == "" {
		return ""
	}
	if len(s) > 2000 {
		s = s[len(s)-2000:]
	}
	return ": " + s
}
