package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/locktivity/epack/pack"
)

// The test binary also stands in for epack-tool-validate. The diff runs the
// validator with EPACK_TOOL_NAME=validate, and the binary then evaluates a
// fake profile against the pack instead of running the tests.
func TestMain(m *testing.M) {
	if os.Getenv("EPACK_TOOL_NAME") == "validate" {
		os.Exit(fakeValidate())
	}
	os.Exit(m.Run())
}

// fakeProfile is the profile format fakeValidate reads. A requirement passes
// when the number at Pointer in the artifact with Schema is at least Pass,
// fails with severity low when it is at least Low, fails with severity high
// below that, and is unknown when the value is null or absent.
type fakeProfile struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Fail         string            `json:"fail,omitempty"`
	Requirements []fakeRequirement `json:"requirements"`
}

type fakeRequirement struct {
	ID      string  `json:"id"`
	Name    string  `json:"name"`
	Schema  string  `json:"schema"`
	Pointer string  `json:"pointer"`
	Pass    float64 `json:"pass"`
	Low     float64 `json:"low"`
}

var runIDPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{6}Z-\d{6}$`)

// fakeValidate checks the tool protocol environment the way the real tool
// relies on it, then writes result.json and outputs/validation.json to the
// run directory. A broken contract becomes a failed run, which the diff
// reports as an error.
func fakeValidate() int {
	runDir := os.Getenv("EPACK_RUN_DIR")
	val, err := fakeEvaluate(runDir)
	result := map[string]any{"schema_version": 1, "status": "success", "outputs": []any{}, "errors": []any{}}
	if err != nil {
		result["status"] = "failure"
		result["errors"] = []any{map[string]string{"code": "TOOL_ERROR", "message": err.Error()}}
	} else {
		data, _ := json.Marshal(val)
		if err := os.MkdirAll(filepath.Join(runDir, "outputs"), 0o755); err != nil {
			return 1
		}
		if err := os.WriteFile(filepath.Join(runDir, "outputs", "validation.json"), data, 0o644); err != nil {
			return 1
		}
		result["outputs"] = []any{map[string]string{"path": "outputs/validation.json", "media_type": "application/json"}}
	}
	data, _ := json.Marshal(result)
	if err := os.WriteFile(filepath.Join(runDir, "result.json"), data, 0o644); err != nil {
		return 1
	}
	return 0
}

func fakeEvaluate(runDir string) (*validation, error) {
	if !filepath.IsAbs(runDir) {
		return nil, fmt.Errorf("EPACK_RUN_DIR %q is not absolute", runDir)
	}
	wd, _ := os.Getwd()
	if !sameDir(wd, runDir) {
		return nil, fmt.Errorf("working directory %s is not EPACK_RUN_DIR %s", wd, runDir)
	}
	if id := os.Getenv("EPACK_RUN_ID"); !runIDPattern.MatchString(id) {
		return nil, fmt.Errorf("EPACK_RUN_ID %q is not a run ID", id)
	}
	if os.Getenv("EPACK_PROTOCOL_VERSION") != "1" || os.Getenv("EPACK_STARTED_AT") == "" {
		return nil, fmt.Errorf("protocol version or start time missing")
	}
	var config struct {
		Profile string `json:"profile"`
	}
	data, err := os.ReadFile(os.Getenv("EPACK_TOOL_CONFIG"))
	if err != nil {
		return nil, fmt.Errorf("EPACK_TOOL_CONFIG: %w", err)
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("EPACK_TOOL_CONFIG: %w", err)
	}
	if config.Profile == "" || filepath.IsAbs(config.Profile) {
		return nil, fmt.Errorf("profile %q must be a path relative to EPACK_PROJECT_ROOT", config.Profile)
	}
	data, err = os.ReadFile(filepath.Join(os.Getenv("EPACK_PROJECT_ROOT"), config.Profile))
	if err != nil {
		return nil, fmt.Errorf("reading the profile: %w", err)
	}
	var profile fakeProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		return nil, fmt.Errorf("parsing the profile: %w", err)
	}
	if profile.Fail != "" {
		return nil, fmt.Errorf("%s", profile.Fail)
	}
	p, err := pack.Open(os.Getenv("EPACK_PACK_PATH"))
	if err != nil {
		return nil, fmt.Errorf("EPACK_PACK_PATH: %w", err)
	}
	defer func() { _ = p.Close() }()
	bodies := map[string]any{}
	for _, a := range p.Manifest().Artifacts {
		if a.Schema == "" {
			continue
		}
		if a.CollectedAt == "" {
			return nil, fmt.Errorf("artifact %s has a schema but no collected_at", a.Path)
		}
		raw, err := p.ReadArtifact(a.Path)
		if err != nil {
			return nil, err
		}
		var body any
		if err := json.Unmarshal(raw.Bytes(), &body); err != nil {
			return nil, err
		}
		bodies[a.Schema] = body
	}
	val := &validation{Profile: profileInfo{ID: profile.ID, Name: profile.Name, Version: profile.Version}}
	for _, req := range profile.Requirements {
		r := requirement{ID: req.ID, Name: req.Name, Status: "unknown"}
		if n, ok := lookup(bodies[req.Schema], req.Pointer).(float64); ok {
			switch {
			case n >= req.Pass:
				r.Status = "pass"
			case n >= req.Low:
				r.Status, r.Severity = "fail", "low"
			default:
				r.Status, r.Severity = "fail", "high"
			}
		}
		val.Requirements = append(val.Requirements, r)
	}
	return val, nil
}

func sameDir(a, b string) bool {
	ra, errA := filepath.EvalSymlinks(a)
	rb, errB := filepath.EvalSymlinks(b)
	return errA == nil && errB == nil && ra == rb
}

func lookup(v any, pointer string) any {
	for _, part := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[part]
	}
	return v
}

// writeTree writes files, by slash-separated path, under a new directory.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

type result struct {
	code     int
	stderr   string
	markdown string
	report   report
}

// runDiff runs the command with --markdown and --json files and reads both.
func runDiff(t *testing.T, args ...string) result {
	t.Helper()
	out := t.TempDir()
	mdPath, jsonPath := filepath.Join(out, "diff.md"), filepath.Join(out, "diff.json")
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), append(args, "--markdown", mdPath, "--json", jsonPath), &stdout, &stderr)
	res := result{code: code, stderr: stderr.String()}
	if code != exitOK {
		return res
	}
	if stdout.Len() > 0 {
		t.Errorf("stdout = %q, want nothing when --markdown names a file", stdout.String())
	}
	md, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatal(err)
	}
	res.markdown = string(md)
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &res.report); err != nil {
		t.Fatalf("decoding the JSON report: %v\n%s", err, data)
	}
	return res
}

// lines renders a scenario's changes one per line: kind, target, base, and
// head, with "-" for an absent side.
func lines(t *testing.T, r report, key string) []string {
	t.Helper()
	for _, sr := range r.Scenarios {
		if sr.key() != key {
			continue
		}
		var out []string
		for _, c := range sr.Changes {
			target := c.Artifact + c.Pointer
			if c.Requirement != "" {
				target = c.Requirement
			}
			side := func(raw json.RawMessage) string {
				if raw == nil {
					return "-"
				}
				var b bytes.Buffer
				if err := json.Compact(&b, raw); err != nil {
					t.Fatal(err)
				}
				return b.String()
			}
			out = append(out, strings.Join([]string{c.Kind, target, side(c.Base), side(c.Head)}, " "))
		}
		return out
	}
	t.Fatalf("no scenario %s in the report", key)
	return nil
}

func assertLines(t *testing.T, got, want []string) {
	t.Helper()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("changes:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestLeafChanges(t *testing.T) {
	base := writeTree(t, map[string]string{
		"aws/clean/artifacts/aws.json": `{
			"big": 12345678901234567890,
			"iam": {"mfa_pct": 92, "root_mfa": true, "admins": 3, "legacy": null, "keys": {"old": 1}},
			"network": {"open_ssh": 2, "note": "x|y", "cmd": "run ` + "`x`" + `", "ports": [22, 3389]},
			"storage": {"encrypted_pct": 50, "buckets": ["a", "b", "c"]},
			"tags": {"team/a~b": "x"}
		}`,
	})
	head := writeTree(t, map[string]string{
		"aws/clean/artifacts/aws.json": `{
			"big": 12345678901234567891,
			"iam": {"admins": 3, "mfa_pct": 100, "root_mfa": null, "phishing_pct": 40},
			"network": {"open_ssh": "2", "note": "x|z", "cmd": "run ` + "`y`" + `", "ports": [22, 3390]},
			"storage": {"encrypted_pct": 50.0, "buckets": ["a", "b"]},
			"tags": {"team/a~b": "y"}
		}`,
	})
	res := runDiff(t, "--base", base, "--head", head)
	if res.code != exitOK {
		t.Fatalf("exit %d: %s", res.code, res.stderr)
	}
	assertLines(t, lines(t, res.report, "aws/clean"), []string{
		"value_changed artifacts/aws.json/big 12345678901234567890 12345678901234567891",
		`newly_absent artifacts/aws.json/iam/keys {"old":1} -`,
		"field_removed artifacts/aws.json/iam/legacy null -",
		"value_changed artifacts/aws.json/iam/mfa_pct 92 100",
		"field_added artifacts/aws.json/iam/phishing_pct - 40",
		"newly_null artifacts/aws.json/iam/root_mfa true null",
		"value_changed artifacts/aws.json/network/cmd \"run `x`\" \"run `y`\"",
		`value_changed artifacts/aws.json/network/note "x|y" "x|z"`,
		`value_changed artifacts/aws.json/network/open_ssh 2 "2"`,
		"value_changed artifacts/aws.json/network/ports/1 3389 3390",
		`item_removed artifacts/aws.json/storage/buckets/2 "c" -`,
		`value_changed artifacts/aws.json/tags/team~1a~0b "x" "y"`,
	})
	s := res.report.Summary
	if s.Scenarios != 1 || s.ChangedScenarios != 1 || s.Changes != 12 || s.EvidenceChanges != 12 || s.ControlChanges != 0 {
		t.Errorf("summary = %+v", s)
	}
	for _, want := range []string{
		"12 changes in 1 of 1 scenario. Control outcomes were not compared because no profile was given.\n",
		"| Scenario | Metric or control | Base | Head | Change |\n",
		"| aws/clean | `artifacts/aws.json#/iam/root_mfa` | `true` | `null` | Newly null |\n",
		"| aws/clean | `artifacts/aws.json#/iam/legacy` | `null` | absent | Field removed |\n",
		"| aws/clean | `artifacts/aws.json#/iam/phishing_pct` | absent | `40` | Field added |\n",
		"| aws/clean | `artifacts/aws.json#/network/note` | `\"x\\|y\"` | `\"x\\|z\"` | Value changed |\n",
		"| aws/clean | `artifacts/aws.json#/network/cmd` | ``\"run `x`\"`` | ``\"run `y`\"`` | Value changed |\n",
	} {
		if !strings.Contains(res.markdown, want) {
			t.Errorf("markdown is missing %q:\n%s", want, res.markdown)
		}
	}
}

func TestArtifactsAndScenarios(t *testing.T) {
	base := writeTree(t, map[string]string{
		"scenarios.json":                  `{"scenarios": []}`,
		"s/scenarios.json":                `[]`,
		"s/kept/artifacts/a.json":         `{"x": 1, "y": [1, 2]}`,
		"s/kept/artifacts/broken.json":    `{"ok": true}`,
		"s/kept/artifacts/gone.json":      `{"y": 1}`,
		"s/kept/artifacts/report.txt":     "old",
		"s/kept/outcome.json":             `{"exit": 0}`,
		"s/only-in-base/artifacts/a.json": `{}`,
	})
	head := writeTree(t, map[string]string{
		"s/kept/artifacts/a.json":         "{\n  \"y\": [1, 2],\n  \"x\": 1.0\n}\n",
		"s/kept/artifacts/broken.json":    `{"ok": true`,
		"s/kept/artifacts/new.json":       `{"z": 1}`,
		"s/kept/artifacts/report.txt":     "newer",
		"s/kept/outcome.json":             `{"exit": 3}`,
		"s/only-in-head/artifacts/a.json": `{}`,
	})
	res := runDiff(t, "--base", base, "--head", head)
	if res.code != exitOK {
		t.Fatalf("exit %d: %s", res.code, res.stderr)
	}
	got := lines(t, res.report, "s/kept")
	want := []string{
		"content_changed artifacts/broken.json",
		"artifact_removed artifacts/gone.json",
		"artifact_added artifacts/new.json",
		"content_changed artifacts/report.txt",
		"value_changed outcome.json/exit 0 3",
	}
	if len(got) != len(want) {
		t.Fatalf("changes:\n%s\nwant %d", strings.Join(got, "\n"), len(want))
	}
	for i := range want {
		if !strings.HasPrefix(got[i], want[i]) {
			t.Errorf("change %d = %q, want it to start with %q", i, got[i], want[i])
		}
	}
	for _, sr := range res.report.Scenarios {
		wantStatus := map[string]string{"s/kept": statusCompared, "s/only-in-base": statusRemoved, "s/only-in-head": statusAdded}[sr.key()]
		if sr.Status != wantStatus {
			t.Errorf("scenario %s has status %q, want %q", sr.key(), sr.Status, wantStatus)
		}
	}
	s := res.report.Summary
	if s.Scenarios != 1 || s.AddedScenarios != 1 || s.RemovedScenarios != 1 || s.Changes != 5 {
		t.Errorf("summary = %+v", s)
	}
	for _, want := range []string{
		"Scenarios only in the head: s/only-in-head. Scenarios only in the base: s/only-in-base.\n",
		"| s/kept | `artifacts/report.txt` | 3 bytes | 5 bytes | Content changed |\n",
		"| s/kept | `artifacts/gone.json` | 8 bytes | absent | Artifact removed |\n",
		"| s/kept | `artifacts/new.json` | absent | 8 bytes | Artifact added |\n",
	} {
		if !strings.Contains(res.markdown, want) {
			t.Errorf("markdown is missing %q:\n%s", want, res.markdown)
		}
	}
}

func controlTrees(t *testing.T) (base, head, profile string) {
	t.Helper()
	base = writeTree(t, map[string]string{
		"scenarios.json": `{"scenarios": [
			{"suite": "idp", "scenario": "clean", "artifacts": [{"path": "artifacts/idp.posture.json", "schema": "evidencepack/idp-posture@v1"}]},
			{"suite": "idp", "scenario": "empty", "artifacts": [{"path": "artifacts/idp.posture.json", "schema": "evidencepack/idp-posture@v1"}]}]}`,
		"idp/clean/artifacts/idp.posture.json": `{"mfa_pct": 100, "admin_mfa_pct": 95, "sso_pct": 50}`,
		"idp/clean/artifacts/notes.txt":        "not JSON, so no schema",
		"idp/empty/artifacts/idp.posture.json": `{"mfa_pct": 100, "admin_mfa_pct": 95, "sso_pct": 50}`,
	})
	head = writeTree(t, map[string]string{
		"idp/scenarios.json": `{"artifacts": [
			{"path": "idp/clean/artifacts/idp.posture.json", "schema": "evidencepack/idp-posture@v1"},
			{"path": "empty/artifacts/idp.posture.json", "schema": "evidencepack/idp-posture@v1"}]}`,
		"idp/clean/artifacts/idp.posture.json": `{"mfa_pct": 100, "admin_mfa_pct": 80, "sso_pct": 50}`,
		"idp/clean/artifacts/notes.txt":        "not JSON, so no schema",
		"idp/empty/artifacts/idp.posture.json": `{"mfa_pct": null, "admin_mfa_pct": 95, "sso_pct": 5}`,
	})
	profile = filepath.Join(writeTree(t, map[string]string{"profile.json": `{
		"id": "test", "name": "Test Controls", "version": "1.0.0",
		"requirements": [
			{"id": "MFA-1", "name": "MFA coverage", "schema": "evidencepack/idp-posture@v1", "pointer": "/mfa_pct", "pass": 100, "low": 90},
			{"id": "ADMIN-1", "name": "Admin MFA", "schema": "evidencepack/idp-posture@v1", "pointer": "/admin_mfa_pct", "pass": 100, "low": 90},
			{"id": "SSO-1", "name": "SSO <coverage>", "schema": "evidencepack/idp-posture@v1", "pointer": "/sso_pct", "pass": 40, "low": 10}
		]}`}), "profile.json")
	return base, head, profile
}

func testExecutable(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

func TestControlOutcomes(t *testing.T) {
	base, head, profile := controlTrees(t)
	res := runDiff(t, "--base", base, "--head", head, "--profile", profile, "--validate", testExecutable(t))
	if res.code != exitOK {
		t.Fatalf("exit %d: %s", res.code, res.stderr)
	}
	assertLines(t, lines(t, res.report, "idp/clean"), []string{
		"value_changed artifacts/idp.posture.json/admin_mfa_pct 95 80",
		`severity_changed ADMIN-1 {"status":"fail","severity":"low"} {"status":"fail","severity":"high"}`,
	})
	assertLines(t, lines(t, res.report, "idp/empty"), []string{
		"newly_null artifacts/idp.posture.json/mfa_pct 100 null",
		"value_changed artifacts/idp.posture.json/sso_pct 50 5",
		`status_changed MFA-1 {"status":"pass"} {"status":"unknown"}`,
		`status_changed SSO-1 {"status":"pass"} {"status":"fail","severity":"high"}`,
	})
	if p := res.report.Profile; !res.report.ControlsCompared || p == nil || p.Name != "Test Controls" || p.Version != "1.0.0" {
		t.Errorf("controls_compared = %v, profile = %+v", res.report.ControlsCompared, p)
	}
	md := res.markdown
	for _, want := range []string{
		"6 changes in 2 of 2 scenarios: 3 in evidence and 3 in control outcomes. Control outcomes come from the Test Controls profile, version 1.0.0.\n",
		"| idp/clean | `ADMIN-1` Admin MFA | fail (low) | fail (high) | Severity changed |\n",
		"| idp/empty | `SSO-1` SSO &lt;coverage&gt; | pass | fail (high) | Status changed |\n",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown is missing %q:\n%s", want, md)
		}
	}
	lastControl := strings.LastIndex(md, "Status changed")
	firstEvidence := strings.Index(md, "Value changed")
	if lastControl < 0 || firstEvidence < 0 || lastControl > firstEvidence {
		t.Errorf("control rows should come before evidence rows:\n%s", md)
	}
}

func TestHeadIndexSchemas(t *testing.T) {
	base, _, profile := controlTrees(t)
	posture := `{"mfa_pct": 100, "admin_mfa_pct": 80, "sso_pct": 50}`
	// A head index that lists the artifact with an empty schema dropped it,
	// so its controls cannot keep passing on the base's.
	dropped := writeTree(t, map[string]string{
		"idp/scenarios.json":                   `{"artifacts": [{"path": "idp/clean/artifacts/idp.posture.json", "schema": ""}]}`,
		"idp/clean/artifacts/idp.posture.json": posture,
		"idp/clean/artifacts/notes.txt":        "not JSON, so no schema",
	})
	res := runDiff(t, "--base", base, "--head", dropped, "--profile", profile, "--validate", testExecutable(t))
	if res.code != exitOK {
		t.Fatalf("exit %d: %s", res.code, res.stderr)
	}
	assertLines(t, lines(t, res.report, "idp/clean"), []string{
		"value_changed artifacts/idp.posture.json/admin_mfa_pct 95 80",
		`status_changed MFA-1 {"status":"pass"} {"status":"unknown"}`,
		`status_changed ADMIN-1 {"status":"fail","severity":"low"} {"status":"unknown"}`,
		`status_changed SSO-1 {"status":"pass"} {"status":"unknown"}`,
	})
	// Schemas belong to a scenario: one that keeps an artifact's schema
	// says nothing about another that dropped it at the same path.
	shared := `{"mfa_pct": 100, "admin_mfa_pct": 95, "sso_pct": 50}`
	index := func(otherSchema string) string {
		return `{"suite": "idp", "scenarios": [
			{"name": "clean", "dir": "clean", "artifacts": [{"path": "artifacts/idp.posture.json", "schema": "evidencepack/idp-posture@v1"}]},
			{"name": "Other run", "dir": "other", "artifacts": [{"path": "artifacts/idp.posture.json", "schema": "` + otherSchema + `"}]}]}`
	}
	twoBase := writeTree(t, map[string]string{
		"idp/scenarios.json":                   index("evidencepack/idp-posture@v1"),
		"idp/clean/artifacts/idp.posture.json": shared,
		"idp/other/artifacts/idp.posture.json": shared,
	})
	twoHead := writeTree(t, map[string]string{
		"idp/scenarios.json":                   index(""),
		"idp/clean/artifacts/idp.posture.json": shared,
		"idp/other/artifacts/idp.posture.json": shared,
	})
	res = runDiff(t, "--base", twoBase, "--head", twoHead, "--profile", profile, "--validate", testExecutable(t))
	if res.code != exitOK {
		t.Fatalf("exit %d: %s", res.code, res.stderr)
	}
	assertLines(t, lines(t, res.report, "idp/other"), []string{
		`status_changed MFA-1 {"status":"pass"} {"status":"unknown"}`,
		`status_changed ADMIN-1 {"status":"fail","severity":"low"} {"status":"unknown"}`,
		`status_changed SSO-1 {"status":"pass"} {"status":"unknown"}`,
	})
	// A head with no index says nothing about schemas, so the base's apply.
	unindexed := writeTree(t, map[string]string{
		"idp/clean/artifacts/idp.posture.json": posture,
		"idp/clean/artifacts/notes.txt":        "not JSON, so no schema",
	})
	res = runDiff(t, "--base", base, "--head", unindexed, "--profile", profile, "--validate", testExecutable(t))
	if res.code != exitOK {
		t.Fatalf("exit %d: %s", res.code, res.stderr)
	}
	assertLines(t, lines(t, res.report, "idp/clean"), []string{
		"value_changed artifacts/idp.posture.json/admin_mfa_pct 95 80",
		`severity_changed ADMIN-1 {"status":"fail","severity":"low"} {"status":"fail","severity":"high"}`,
	})
}

func TestValidatorFailureIsBadInput(t *testing.T) {
	base, head, _ := controlTrees(t)
	profile := filepath.Join(writeTree(t, map[string]string{"profile.json": `{"id": "x", "fail": "profile missing required field: name"}`}), "profile.json")
	res := runDiff(t, "--base", base, "--head", head, "--profile", profile, "--validate", testExecutable(t))
	if res.code != exitBadInput {
		t.Fatalf("exit %d, want %d", res.code, exitBadInput)
	}
	if !strings.Contains(res.stderr, "profile missing required field: name") {
		t.Errorf("stderr = %q, want the validator's error", res.stderr)
	}
}

func TestRowCap(t *testing.T) {
	base := writeTree(t, map[string]string{"s/a/artifacts/x.json": `{"a": 1, "b": 1, "c": 1, "d": 1, "e": 1}`})
	head := writeTree(t, map[string]string{"s/a/artifacts/x.json": `{"a": 2, "b": 2, "c": 2, "d": 2, "e": 2}`})

	res := runDiff(t, "--base", base, "--head", head, "--max-rows", "2")
	if res.code != exitOK {
		t.Fatalf("exit %d: %s", res.code, res.stderr)
	}
	if rows := strings.Count(res.markdown, "| Value changed |"); rows != 2 {
		t.Errorf("table has %d rows, want 2:\n%s", rows, res.markdown)
	}
	if !strings.Contains(res.markdown, "\nThe table shows the first 2 of 5 changes.\n") {
		t.Errorf("markdown does not count the rows left out:\n%s", res.markdown)
	}
	if n := len(lines(t, res.report, "s/a")); n != 5 {
		t.Errorf("JSON report lists %d changes, want all 5", n)
	}

	res = runDiff(t, "--base", base, "--head", head, "--max-rows", "0")
	if res.code != exitOK {
		t.Fatalf("exit %d: %s", res.code, res.stderr)
	}
	want := "5 changes in 1 of 1 scenario. Control outcomes were not compared because no profile was given.\n"
	if res.markdown != want {
		t.Errorf("markdown = %q, want only %q", res.markdown, want)
	}
}

func TestNoChangesToStdout(t *testing.T) {
	files := map[string]string{
		"s/a/artifacts/x.json": `{"a": 1}`,
		"s/b/artifacts/x.json": `{"a": 1}`,
	}
	base, head := writeTree(t, files), writeTree(t, files)
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--base", base, "--head", head}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	want := "No changes in 2 scenarios. Control outcomes were not compared because no profile was given.\n"
	if stdout.String() != want {
		t.Errorf("stdout = %q, want %q", stdout.String(), want)
	}
}

func TestBadInput(t *testing.T) {
	tree := writeTree(t, map[string]string{"s/a/artifacts/x.json": `{}`})
	brokenIndex := writeTree(t, map[string]string{"scenarios.json": `{`, "s/a/artifacts/x.json": `{}`})
	file := filepath.Join(tree, "s", "a", "artifacts", "x.json")
	missing := filepath.Join(tree, "missing")
	for name, args := range map[string][]string{
		"no flags":                   {},
		"no head":                    {"--base", tree},
		"head missing":               {"--base", tree, "--head", missing},
		"base is a file":             {"--base", file, "--head", tree},
		"profile without validate":   {"--base", tree, "--head", tree, "--profile", file},
		"validate without profile":   {"--base", tree, "--head", tree, "--validate", file},
		"negative max rows":          {"--base", tree, "--head", tree, "--max-rows", "-1"},
		"extra argument":             {"--base", tree, "--head", tree, "extra"},
		"unknown flag":               {"--base", tree, "--head", tree, "--nope"},
		"malformed index":            {"--base", brokenIndex, "--head", tree},
		"profile missing":            {"--base", tree, "--head", tree, "--profile", missing, "--validate", testExecutable(t)},
		"validate binary missing":    {"--base", tree, "--head", tree, "--profile", file, "--validate", missing},
		"validate not found on PATH": {"--base", tree, "--head", tree, "--profile", file, "--validate", "epack-tool-validate-not-installed"},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(context.Background(), args, &stdout, &stderr); code != exitBadInput {
				t.Errorf("exit %d, want %d; stderr: %s", code, exitBadInput, stderr.String())
			}
			if stderr.Len() == 0 {
				t.Error("stderr is empty, want the reason")
			}
		})
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-h"}, &stdout, &stderr); code != exitOK {
		t.Errorf("-h exits %d, want 0", code)
	}
}

func TestMarkdownEscaping(t *testing.T) {
	for in, want := range map[string]string{
		"plain":   "`plain`",
		"a|b":     "`a\\|b`",
		"a`b":     "``a`b``",
		"`edge`":  "`` `edge` ``",
		"x``y`z":  "```x``y`z```",
		"line\nb": "`line b`",
	} {
		if got := code(in); got != want {
			t.Errorf("code(%q) = %s, want %s", in, got, want)
		}
	}
	if got := truncate(strings.Repeat("é", 130), 120); got != strings.Repeat("é", 117)+"..." {
		t.Errorf("truncate kept %d runes", len([]rune(got)))
	}
	names := make([]string, 12)
	for i := range names {
		names[i] = fmt.Sprintf("s/%d", i)
	}
	if got, want := nameList(names), "s/0, s/1, s/2, s/3, s/4, s/5, s/6, s/7, s/8, s/9, and 2 more"; got != want {
		t.Errorf("nameList = %q, want %q", got, want)
	}
}

func TestBuildFilesAreNotEvidence(t *testing.T) {
	index := `{"suite": "s", "scenarios": [{"name": "clean", "dir": "clean", "artifacts": [
		{"path": "artifacts/s.json", "schema": ""},
		{"path": "artifacts/s.collector-build.json", "schema": "evidencepack/collector-build@v1"}]}]}`
	base := writeTree(t, map[string]string{
		"s/scenarios.json":                         index,
		"s/clean/artifacts/s.json":                 `{"x": 1}`,
		"s/clean/artifacts/s.collector-build.json": `{"trace_map": {"lines": {"a.go:1": "old"}}}`,
	})
	head := writeTree(t, map[string]string{
		"s/scenarios.json":                         index,
		"s/clean/artifacts/s.json":                 `{"x": 2}`,
		"s/clean/artifacts/s.collector-build.json": `{"trace_map": {"lines": {"a.go:2": "moved"}}}`,
	})
	res := runDiff(t, "--base", base, "--head", head)
	if res.code != exitOK {
		t.Fatalf("exit %d: %s", res.code, res.stderr)
	}
	assertLines(t, lines(t, res.report, "s/clean"), []string{"value_changed artifacts/s.json/x 1 2"})
}
