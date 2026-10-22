// Package collectortest checks a collector against canned vendor responses,
// DNS records, and endpoints: the scenarios its author supplies, and a
// matrix of faults injected into each operation it calls.
//
// Under an injected fault, each value in the collector's artifacts must keep
// its clean value, or be left out with a gap whose code matches the fault.
// A fault may make the output less complete, as long as the output says so,
// but it may never move a value, except within a list that a partial gap
// says was read in part. A fault that reaches its operation must leave a new
// gap, so a failure read as "no record" shows even where the clean answer
// was none. Only operations listed in Suite.Required, such as the sign-in,
// may fail the whole run.
//
// Each run's artifacts are also checked against their schemas and the
// x-epack annotations in them, and the clean scenario runs at every
// collection level to check that output only grows with the level.
//
// Every run goes through componentsdk.RunInProcess, in process and without
// network access, so the collector must make its vendor calls with
// componentsdk.NewHTTPClient or componentsdk.NewTransport, its DNS lookups
// with componentsdk.NewResolver, and its own connections with
// componentsdk.NewDialer.
//
// Record makes a scenario from one run against the real vendor, scrubbed of
// credentials and identifying values, and LoadScenario loads it back. When
// COLLECTORTEST_OUT names a directory, each scenario run's output is written
// there for comparison with another version of the collector.
package collectortest

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/internal/outputcheck"
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/safefile"
	"github.com/locktivity/epack/internal/tracemap"
)

// Suite describes a collector to check.
type Suite struct {
	// Spec and Run are what the collector passes to RunCollector.
	Spec componentsdk.CollectorSpec
	Run  componentsdk.CollectorHandler

	// Name is the collector's configured name. It defaults to Spec.Name. It
	// also names the suite's directory under COLLECTORTEST_OUT, so two
	// suites of one collector in a package need names of their own.
	Name string

	// Config is the configuration every run gets. A scenario's Config
	// overrides it key by key, except that a recording's Config, the whole
	// configuration of the run it was recorded from, replaces it.
	Config map[string]any

	// Secrets holds the values Secret returns. A scenario's Secrets override
	// them key by key. They double as canaries: none may appear in any
	// output.
	Secrets map[string]string

	// Env holds other environment variables the collector reads. A
	// scenario's Env overrides them key by key.
	Env map[string]string

	// Clock is the time the runs of scenarios built in code see through
	// componentsdk.Now. It defaults to the moment the first scenario was
	// recorded, when LoadScenario loaded it, and otherwise to
	// 2026-01-01T00:00:00Z. A recording always runs at the moment it was
	// recorded, so it sends the time-based requests its responses answer.
	Clock time.Time

	// Scenarios are tenant states as canned responses. The first must
	// succeed; the fault matrix, determinism, levels, credentials, and
	// sensitivity checks run on it.
	Scenarios []Scenario

	// Codec encodes the JSON bodies of a recording made with
	// RecordOptions.Codec. It also decodes request bodies for RequestBody to
	// match, and response bodies for the sensitivity check to change. See
	// BodyCodec.
	Codec BodyCodec

	// Required names the operations allowed to fail the whole run, such as
	// the sign-in.
	Required []string

	// Semantics lists faults that carry a meaning rather than a failure,
	// such as a 404 that says a feature is not configured.
	Semantics []Semantic

	// Schemas maps an artifact path or schema ID to a JSON Schema file the
	// artifact must validate against. Its x-epack annotations take
	// precedence over those in Spec.Schemas and the SDK's normalized schemas.
	// The result artifact is always checked against
	// componentsdk.ResultSchemaJSON.
	Schemas map[string]string

	// Ignore lists JSON pointer prefixes, by artifact path, whose values may
	// change without a gap, such as a warnings list kept for older readers.
	Ignore map[string][]string

	// Operations lists every operation the collector can call. When set, an
	// operation no scenario reaches, or one missing from the list, fails the
	// coverage check.
	Operations []string

	// Insensitive lists operations whose responses never change a value,
	// such as a token exchange, so the sensitivity check skips them and a
	// fault on one need not leave a gap.
	Insensitive []string

	// SkipChecks turns off checks by name: "determinism", "coverage",
	// "levels", "population", "nulls", "rollups", "ratios", "credentials",
	// "faults", "sensitivity", or "tracemap".
	SkipChecks []string

	// SkipFaults leaves faults out of the matrix by name. A name such as
	// "timeout" leaves out the fault of that name for every kind of call.
	SkipFaults []string

	// Faults adds faults to the matrix after the built-in ones, such as a
	// vendor's throttle sent as a 400 (see StatusFault and
	// componentsdk.HTTPOptions.ClassifyResponse).
	Faults []Fault

	// GapOperations turns on a check that every gap a fault leaves names
	// the faulted operation, as a gap recorded from an error the SDK's
	// client returned, or from one built with componentsdk.ResponseError,
	// does. A gap recorded from a failed DNS lookup or dial, or from a
	// timeout or reset on a dialed connection, names it too. Faults a
	// Semantics entry declares are exempt.
	GapOperations bool
}

// Semantic declares what a fault on an operation means, for the cases where
// a status is an answer rather than a failure, or a failure of its own kind.
type Semantic struct {
	Operation string
	Fault     string

	// Meaning says what the response means, in a few words.
	Meaning string

	// Expect pins values the fault must produce, by artifact path and JSON
	// pointer. Values compare as JSON, as in Scenario.Expect.
	Expect map[string]map[string]any

	// Positions limits Expect to faults at these positions, such as
	// PositionAll for an operation called once per item, where a fault at
	// one position leaves the other items' values in place. Empty means
	// every position. At the other positions the meaning still exempts the
	// fault from the outcome rule.
	Positions []string

	// ExpectFailure declares that the fault fails the run with this code,
	// such as a 404 on the organization read, which means config_invalid.
	// The operation must be one of Suite.Required.
	ExpectFailure componentsdk.Code
}

// Report is the outcome of Check.
type Report struct {
	// Runs counts the collector runs the check made.
	Runs int
	// Operations lists the operations the clean scenario called.
	Operations []string
	// Violations lists every rule a run broke.
	Violations []Violation
	// Unmutated lists operations whose responses the sensitivity check could
	// not change, such as XML bodies, so it proved nothing for them.
	Unmutated []string
}

// Violation is one broken rule.
type Violation struct {
	// Check names the check: "scenario", "secrets", "schema",
	// "schema_unusable", "population", "nulls", "rollups", "ratios",
	// "determinism", "coverage", "levels", "credentials", "faults",
	// "sensitivity", "tracemap", "recording", or "export".
	Check string
	// Case names the run within the check, such as
	// "graph.users.list/500/first" for a fault.
	Case    string
	Message string
}

// Run checks the suite and reports each violation as a failing subtest.
func Run(t *testing.T, s Suite) {
	t.Helper()
	report, err := Check(s)
	if err != nil {
		t.Fatalf("collectortest: %v", err)
	}
	t.Logf("collectortest: %d runs over %d operations", report.Runs, len(report.Operations))
	if len(report.Unmutated) > 0 {
		t.Logf("collectortest: the sensitivity check could not change the responses of %s", strings.Join(report.Unmutated, ", "))
	}
	var order []string
	byCase := map[string][]string{}
	for _, v := range report.Violations {
		name := v.Check
		if v.Case != "" {
			name += "/" + v.Case
		}
		if _, ok := byCase[name]; !ok {
			order = append(order, name)
		}
		byCase[name] = append(byCase[name], v.Message)
	}
	for _, name := range order {
		messages := byCase[name]
		t.Run(name, func(t *testing.T) {
			for _, m := range messages {
				t.Error(m)
			}
		})
	}
}

// Check runs the suite and returns what it found. It returns an error only
// for a suite it cannot run.
func Check(s Suite) (*Report, error) {
	if s.Run == nil {
		return nil, errors.New("Suite.Run is required")
	}
	if s.Spec.Name == "" {
		return nil, errors.New("Suite.Spec.Name is required")
	}
	if len(s.Scenarios) == 0 {
		return nil, errors.New("Suite.Scenarios needs at least the clean scenario")
	}
	if s.Scenarios[0].ExpectFailure != "" {
		return nil, errors.New("the first scenario is the clean one and must expect success")
	}
	for _, sc := range s.Scenarios {
		if sc.ExpectFailure != "" && len(sc.Expect) > 0 {
			return nil, fmt.Errorf("scenario %q expects a failure, which emits nothing for Expect to pin", sc.Name)
		}
	}
	for _, f := range s.Faults {
		if f.apply == nil && f.lookup == nil && f.dial == nil {
			return nil, fmt.Errorf("fault %q in Suite.Faults has no response; build it with StatusFault, BodyFault, or ErrorFault", f.Name)
		}
	}
	for _, sem := range s.Semantics {
		switch {
		case sem.ExpectFailure == "":
		case !containsString(s.Required, sem.Operation):
			return nil, fmt.Errorf("the semantic for %s/%s expects a failure, which only operations in Suite.Required may cause", sem.Operation, sem.Fault)
		case len(sem.Expect) > 0:
			return nil, fmt.Errorf("the semantic for %s/%s expects a failure, which emits nothing for Expect to pin", sem.Operation, sem.Fault)
		}
		for _, pos := range sem.Positions {
			if !containsString([]string{PositionAll, PositionFirst, PositionMiddle, PositionLast}, pos) {
				return nil, fmt.Errorf("the semantic for %s/%s lists position %q, which is not all, first, middle, or last", sem.Operation, sem.Fault, pos)
			}
		}
	}
	for i, a := range s.Semantics {
		for _, b := range s.Semantics[i+1:] {
			if a.Operation == b.Operation && a.Fault == b.Fault && positionsOverlap(a.Positions, b.Positions) {
				return nil, fmt.Errorf("Suite.Semantics has two entries for %s/%s that apply at the same position; give each its own Positions", a.Operation, a.Fault)
			}
		}
	}
	k := &kit{suite: s, report: &Report{}, seen: map[string]bool{}, reported: map[Violation]bool{}, canaries: canariesOf(s), ignore: newIgnoreSet(s.Ignore)}
	if tracing(s) {
		k.trace = newTracer()
	}
	if k.suite.Clock.IsZero() {
		k.suite.Clock = cmp.Or(s.Scenarios[0].recordedAt, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	}
	if err := k.loadSchemas(); err != nil {
		return nil, err
	}
	k.checkRecordings()
	moments := []time.Time{k.suite.Clock}
	for _, sc := range s.Scenarios {
		moments = append(moments, endpointMoments(k.clockFor(sc), sc.Endpoints)...)
	}
	ca, err := newTestCA(moments...)
	if err != nil {
		return nil, fmt.Errorf("test CA: %w", err)
	}
	k.ca = ca
	k.runScenarios()
	if k.baseline == nil {
		return k.report, nil
	}
	for _, op := range k.baseline.Result.Calls.Operations {
		k.report.Operations = append(k.report.Operations, op.Name)
	}
	if !k.skipped("determinism") {
		k.checkDeterminism()
	}
	if !k.skipped("coverage") {
		k.checkCoverage()
	}
	if !k.skipped("levels") {
		k.checkLevels()
	}
	if !k.skipped("credentials") {
		k.checkCredentials()
	}
	if !k.skipped("faults") {
		k.runFaultMatrix()
	}
	if !k.skipped("sensitivity") {
		k.checkSensitivity()
	}
	if k.trace != nil {
		if dir := os.Getenv(tracemap.Env); dir != "" {
			if err := k.writeTrace(dir); err != nil {
				k.violate("export", "", "writing the suite's trace under %s: %v", tracemap.Env, err)
			}
		} else if !k.skipped("tracemap") {
			k.checkTraceMap()
		}
	}
	return k.report, nil
}

type kit struct {
	suite        Suite
	report       *Report
	schemas      map[string]*outputcheck.Schema
	resultSchema *outputcheck.Schema
	buildSchema  *outputcheck.Schema
	ca           *testCA
	baseline     *componentsdk.InProcessResult
	baselineNet  *network
	seen         map[string]bool
	reported     map[Violation]bool
	canaries     []canary
	ignore       ignoreSet
	export       *exporter
	trace        *tracer
	// checkedBuild is the build file checkSchemas validated. Every run of a
	// suite emits the same one, so it is validated once.
	checkedBuild []byte
}

// canary is a secret's value, which no output may contain.
type canary struct{ key, value string }

// canariesOf lists the values of Suite.Secrets and every scenario's Secrets,
// sorted. Values too short to tell from ordinary text are left out.
func canariesOf(s Suite) []canary {
	seen := map[canary]bool{}
	var out []canary
	add := func(secrets map[string]string) {
		for key, value := range secrets {
			c := canary{key: key, value: value}
			if len(value) >= 6 && !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
	}
	add(s.Secrets)
	for _, sc := range s.Scenarios {
		add(sc.Secrets)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].key != out[j].key {
			return out[i].key < out[j].key
		}
		return out[i].value < out[j].value
	})
	return out
}

// violate records a violation once, so a finding the SDK and the kit both
// make is reported a single time.
func (k *kit) violate(check, name, format string, args ...any) {
	v := Violation{Check: check, Case: name, Message: fmt.Sprintf(format, args...)}
	if k.reported[v] {
		return
	}
	k.reported[v] = true
	k.report.Violations = append(k.report.Violations, v)
}

func (k *kit) skipped(check string) bool {
	for _, c := range k.suite.SkipChecks {
		if c == check {
			return true
		}
	}
	return false
}

func (k *kit) faultSkipped(name string) bool {
	for _, f := range k.suite.SkipFaults {
		if f == name {
			return true
		}
	}
	return false
}

// runOnce runs the collector against scenario, with wrap given the run's
// network to put a fault or a redirect in when set, and applies the checks
// every run gets.
func (k *kit) runOnce(check, name string, scenario Scenario, wrap func(*network)) (componentsdk.InProcessResult, *network) {
	return k.runWith(check, name, scenario, wrap, k.configFor(scenario))
}

// configFor is the configuration a scenario's runs get: Suite.Config with
// the scenario's keys over it, or a recording's own config, copied so a run
// cannot change either.
func (k *kit) configFor(s Scenario) map[string]any {
	if s.source != "" && len(s.Config) > 0 {
		return copyConfig(s.Config)
	}
	config := copyConfig(k.suite.Config)
	if len(s.Config) == 0 {
		return config
	}
	if config == nil {
		config = map[string]any{}
	}
	maps.Copy(config, copyConfig(s.Config))
	return config
}

// clockFor is the time a scenario's runs see: the moment a recording was
// made, or Suite.Clock.
func (k *kit) clockFor(s Scenario) time.Time {
	return cmp.Or(s.recordedAt, k.suite.Clock)
}

// overlay returns base with over's entries over it.
func overlay(base, over map[string]string) map[string]string {
	if len(over) == 0 {
		return base
	}
	out := maps.Clone(base)
	if out == nil {
		out = map[string]string{}
	}
	maps.Copy(out, over)
	return out
}

// runWith is runOnce with the configuration the run gets. Each run stages
// file artifacts in a directory of its own, removed once the secrets check
// has read the staged files.
func (k *kit) runWith(check, name string, scenario Scenario, wrap func(*network), config map[string]any) (componentsdk.InProcessResult, *network) {
	n, err := k.newNetwork(scenario)
	if err != nil {
		k.violate(check, name, "%v", err)
		return componentsdk.InProcessResult{ExitCode: -1}, nil
	}
	outputDir, err := os.MkdirTemp("", "collectortest-output-")
	if err != nil {
		k.violate(check, name, "creating the staging directory: %v", err)
		return componentsdk.InProcessResult{ExitCode: -1}, nil
	}
	defer func() { _ = os.RemoveAll(outputDir) }()
	if wrap != nil {
		wrap(n)
	}
	clock := k.clockFor(scenario)
	spec := k.suite.Spec
	if check != "scenario" {
		// The trace map changes nothing a run does, and only the scenario
		// runs' build files are kept, so the other runs, the fault matrix's
		// hundreds among them, leave its bytes out of theirs.
		spec.TraceMap = nil
	}
	res := componentsdk.RunInProcess(spec, k.suite.Run, componentsdk.InProcessOptions{
		Name:      k.suite.Name,
		Config:    config,
		Secrets:   overlay(k.suite.Secrets, scenario.Secrets),
		Env:       overlay(k.suite.Env, scenario.Env),
		OutputDir: outputDir,
		RunID:     "collectortest",
		Transport: n.transport,
		Resolver:  n.dns,
		Dial:      n.endpoints.dial,
		RootCAs:   k.ca.pool,
		Seed:      1,
		Sleep:     func(ctx context.Context, _ time.Duration) error { return ctx.Err() },
		Clock:     func() time.Time { return clock },
	})
	n.close()
	k.report.Runs++
	if res.Panic != "" {
		k.violate(check, name, "the collector panicked: %s", res.Panic)
	}
	if check == "scenario" && k.export != nil {
		if err := k.export.add(name, res, outputDir); err != nil {
			k.violate("export", name, "writing the scenario's output under %s: %v", outEnv, err)
		}
	}
	k.checkSecrets(check, name, res, outputDir)
	k.checkSchemas(check, name, res)
	k.checkOutput(check, name, res, componentsdk.LevelOf(config))
	if !k.skipped("credentials") {
		k.checkHostLists(res)
	}
	if res.Result != nil {
		for _, op := range res.Result.Calls.Operations {
			k.seen[op.Name] = true
		}
	}
	return res, n
}

// runScenarios runs each scenario once and, when COLLECTORTEST_OUT is set,
// writes each run's output there.
func (k *kit) runScenarios() {
	export, err := newExporter(k.suite)
	if err != nil {
		k.violate("export", "", "preparing %s: %v", outEnv, err)
	}
	k.export = export
	defer func() {
		if k.export == nil {
			return
		}
		if err := k.export.finish(); err != nil {
			k.violate("export", "", "writing the scenario index under %s: %v", outEnv, err)
		}
		k.export = nil
	}()
	for i, sc := range k.suite.Scenarios {
		label := scenarioLabel(sc, i)
		res, n := k.runOnce("scenario", label, sc, nil)
		for _, miss := range n.unmatched() {
			k.violate("scenario", label, "%s", miss)
		}
		if sc.ExpectFailure != "" {
			switch {
			case res.ExitCode == 0:
				k.violate("scenario", label, "the run succeeded, want a failure with code %s", sc.ExpectFailure)
			case res.Failure == nil || res.Failure.Code != sc.ExpectFailure:
				k.violate("scenario", label, "the run failed with %s, want %s", failureLabel(res), sc.ExpectFailure)
			}
			continue
		}
		if res.ExitCode != 0 {
			k.violate("scenario", label, "the run failed with exit %d and %s: %s", res.ExitCode, failureLabel(res), strings.TrimSpace(res.Stderr))
			continue
		}
		if res.Result == nil || len(res.Result.Calls.Operations) == 0 {
			k.violate("scenario", label, "the collector made no calls through the SDK; make them with componentsdk.NewHTTPClient, NewResolver, or NewDialer")
		}
		for _, p := range pinned(res.Artifacts, sc.Expect) {
			k.violate("scenario", label, "%s", p)
		}
		if i == 0 && res.Result != nil {
			r := res
			k.baseline = &r
			k.baselineNet = n
		}
		switch {
		case k.trace == nil || res.Result == nil:
		case i == 0:
			k.trace.setBaseline(res)
		default:
			k.trace.addFields(res)
		}
	}
}

func scenarioLabel(sc Scenario, i int) string {
	if sc.Name == "" {
		return fmt.Sprintf("scenario-%d", i)
	}
	return sc.Name
}

// checkRecordings runs the scrub check on each scenario LoadScenario loaded,
// with every scenario's secrets as the values to look for.
func (k *kit) checkRecordings() {
	for i, sc := range k.suite.Scenarios {
		if sc.source == "" {
			continue
		}
		for _, l := range scanScenario(sc, k.canaries, nil) {
			k.violate("recording", scenarioLabel(sc, i), "%s %s holds %s; scrub it out of the recording", sc.source, l.where, l.what)
		}
	}
}

// checkSecrets looks for each canary in the run's stdout and stderr and in
// every file it staged, emitted or not.
func (k *kit) checkSecrets(check, name string, res componentsdk.InProcessResult, outputDir string) {
	for _, c := range k.canaries {
		if strings.Contains(res.Stdout, c.value) {
			k.violate("secrets", check+"/"+name, "the value of %s appears in the collector's output", c.key)
		}
		if strings.Contains(res.Stderr, c.value) {
			k.violate("secrets", check+"/"+name, "the value of %s appears in stderr", c.key)
		}
	}
	if len(k.canaries) == 0 {
		return
	}
	_ = filepath.WalkDir(outputDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(outputDir, path)
		if err != nil {
			return nil
		}
		data, err := safefile.ReadFileBeneath(outputDir, rel, limits.Artifact)
		if err != nil {
			return nil
		}
		for _, c := range k.canaries {
			if bytes.Contains(data, []byte(c.value)) {
				k.violate("secrets", check+"/"+name, "the value of %s appears in staged file %s", c.key, filepath.ToSlash(rel))
			}
		}
		return nil
	})
}

// checkHostLists reports each CredentialHosts wildcard of the run's clients
// that covers a public suffix, such as "*.com".
func (k *kit) checkHostLists(res componentsdk.InProcessResult) {
	for _, hosts := range res.CredentialHosts {
		for _, host := range hosts {
			if suffix, ok := publicSuffixWildcard(host); ok {
				k.violate("credentials", "", "CredentialHosts entry %q lets credentials go to every host under %s, a public suffix; list the vendor's own hosts", host, suffix)
			}
		}
	}
}

func (k *kit) loadSchemas() error {
	var err error
	if k.resultSchema, err = outputcheck.Compile(componentsdk.ResultSchemaJSON()); err != nil {
		return fmt.Errorf("result schema: %w", err)
	}
	if k.buildSchema, err = outputcheck.Compile(componentsdk.BuildSchemaJSON()); err != nil {
		return fmt.Errorf("build file schema: %w", err)
	}
	k.schemas = map[string]*outputcheck.Schema{}
	for key, file := range k.suite.Schemas {
		abs, err := filepath.Abs(file)
		if err != nil {
			return err
		}
		sch, err := outputcheck.CompileFile(abs)
		if err != nil {
			return fmt.Errorf("schema for %s: %w", key, err)
		}
		k.schemas[key] = sch
	}
	return nil
}

func (k *kit) checkSchemas(check, name string, res componentsdk.InProcessResult) {
	for _, a := range res.Artifacts {
		if a.File != "" {
			continue
		}
		sch := k.suiteSchema(a.Path, a.Schema)
		switch a.Schema {
		case componentsdk.ResultSchema:
			sch = k.resultSchema
		case componentsdk.BuildSchema:
			if bytes.Equal(a.Data, k.checkedBuild) {
				continue
			}
			k.checkedBuild = a.Data
			sch = k.buildSchema
		}
		if sch == nil {
			continue
		}
		doc, err := outputcheck.Decode(a.Data)
		if err != nil {
			k.violate("schema", check+"/"+name, "%s is not JSON: %v", a.Path, err)
			continue
		}
		for _, f := range outputcheck.Validate(sch, a.Path, doc) {
			k.violateFinding(check, name, f.Check, f.Path, f.Pointer, f.Message)
		}
	}
}

func (k *kit) checkDeterminism() {
	a, _ := k.runOnce("determinism", "", k.suite.Scenarios[0], nil)
	b, _ := k.runOnce("determinism", "", k.suite.Scenarios[0], nil)
	first := map[string]componentsdk.EmittedArtifact{}
	for _, art := range a.Artifacts {
		first[art.Path] = art
	}
	second := map[string]bool{}
	for _, art := range b.Artifacts {
		second[art.Path] = true
		prior, ok := first[art.Path]
		switch {
		case !ok:
			k.violate("determinism", "", "of two runs of the same scenario, only the second emitted %s", art.Path)
		case !sameArtifact(prior, art):
			k.violate("determinism", "", "two runs of the same scenario produced different %s", art.Path)
		}
	}
	for _, art := range a.Artifacts {
		if !second[art.Path] {
			k.violate("determinism", "", "of two runs of the same scenario, only the first emitted %s", art.Path)
		}
	}
	if len(a.Artifacts) != len(b.Artifacts) {
		k.violate("determinism", "", "two runs of the same scenario emitted %d and %d artifacts", len(a.Artifacts), len(b.Artifacts))
	}
}

// sameArtifact reports whether two runs emitted the same artifact: the same
// data and, for a file artifact, whose data is empty, staged bytes of the
// same size and SHA-256.
func sameArtifact(a, b componentsdk.EmittedArtifact) bool {
	return bytes.Equal(a.Data, b.Data) && a.SHA256 == b.SHA256 && a.Size == b.Size
}

func (k *kit) checkCoverage() {
	if k.seen[componentsdk.UnnamedOperation] {
		k.violate("coverage", "", "some calls carry no operation name; name each call with componentsdk.WithOperation")
	}
	if len(k.suite.Operations) == 0 {
		return
	}
	declared := map[string]bool{}
	for _, op := range k.suite.Operations {
		declared[op] = true
		if !k.seen[op] {
			k.violate("coverage", "", "no scenario reaches operation %s", op)
		}
	}
	seen := make([]string, 0, len(k.seen))
	for op := range k.seen {
		seen = append(seen, op)
	}
	sort.Strings(seen)
	for _, op := range seen {
		if !declared[op] && op != componentsdk.UnnamedOperation {
			k.violate("coverage", "", "operation %s is missing from Suite.Operations", op)
		}
	}
}

// checkCredentials redirects the first HTTP operation's first call to a
// foreign host, then, one operation at a time, points the links its
// responses give to their own host at that host, and reports any credential
// that reaches it. The client drops Authorization and Cookie on a redirect
// to another domain, but nothing drops them from a request the collector
// makes to a link it was given, such as a next page.
func (k *kit) checkCredentials() {
	for _, op := range k.baseline.UnlistedCredentials {
		k.violate("credentials", op, "%s sent a credential through a client built without HTTPOptions.CredentialHosts, so no host check guards it; list the hosts that may receive it", op)
	}
	var ops []string
	for _, op := range k.baseline.Result.Calls.Operations {
		if op.Name != componentsdk.UnnamedOperation && op.Calls > 0 && k.baselineNet.kindOf(op.Name) == kindHTTP {
			ops = append(ops, op.Name)
		}
	}
	if len(ops) == 0 {
		return
	}
	rd := &redirector{foreignWatch: foreignWatch{canaries: k.canaries}, op: ops[0]}
	k.runOnce("credentials", ops[0], k.suite.Scenarios[0], func(n *network) {
		rd.base = n.transport
		n.transport = rd
	})
	if leaked := rd.leaks(); len(leaked) > 0 {
		k.violate("credentials", ops[0], "a redirect from %s sent %s to %s; list the vendor's hosts in HTTPOptions.CredentialHosts", ops[0], strings.Join(leaked, ", "), foreignHost)
	}
	answered, hosts := k.baselineNet.replay.operationsFor(), k.baselineNet.replay.hostsFor()
	for _, op := range ops {
		scenario, ok := foreignLinks(k.suite.Scenarios[0], op, answered, hosts)
		if !ok {
			continue
		}
		watch := &foreignWatch{canaries: k.canaries}
		k.runOnce("credentials", op+"/link", scenario, func(n *network) {
			watch.base = n.transport
			n.transport = watch
		})
		if leaked := watch.leaks(); len(leaked) > 0 {
			k.violate("credentials", op+"/link", "following a link in a response to %s sent %s to %s; list the vendor's hosts in HTTPOptions.CredentialHosts", op, strings.Join(leaked, ", "), foreignHost)
		}
	}
}

func (k *kit) runFaultMatrix() {
	faults := append(Faults(), k.suite.Faults...)
	for _, op := range k.baseline.Result.Calls.Operations {
		if op.Name == componentsdk.UnnamedOperation || op.Calls == 0 {
			continue
		}
		kind := k.baselineNet.kindOf(op.Name)
		for _, f := range faults {
			if f.kind() != kind || k.faultSkipped(f.Name) || (len(f.Operations) > 0 && !containsString(f.Operations, op.Name)) {
				continue
			}
			for _, pos := range positionsFor(op.Calls, f.Transient) {
				label := op.Name + "/" + f.Name + "/" + pos
				in := &injector{op: op.Name, fault: f, position: pos, total: op.Calls}
				res, _ := k.runOnce("faults", label, k.suite.Scenarios[0], in.install)
				if in.hitCount() == 0 {
					k.violate("faults", label, "the fault never reached %s: no call in the run matched it, so this case proves nothing", op.Name)
					continue
				}
				k.judgeFault(label, op.Name, pos, f, res, in.changedCalls())
				if k.trace != nil {
					k.trace.addFault(op.Name, res)
				}
			}
		}
	}
}

// judgeFault applies the rules to a run with a fault injected. changed lists
// the calls whose answers the fault altered, which a fault that passes some
// responses through may not have.
func (k *kit) judgeFault(label, op, position string, f Fault, res componentsdk.InProcessResult, changed []int) {
	base := k.baseline
	if f.Transient {
		if res.ExitCode != 0 {
			k.violate("faults", label, "a fault that clears on retry failed the run with %s", failureLabel(res))
			return
		}
		for _, p := range compareRuns(base.Artifacts, res.Artifacts, nil, k.ignore) {
			k.violate("faults", label, "a fault that clears on retry changed the output: %s", p)
		}
		for _, g := range newGaps(base.Result, res.Result) {
			k.violate("faults", label, "a fault that clears on retry left a gap at %s %s (%s)", g.Path, g.Pointer, g.Code)
		}
		return
	}
	sem, pin := k.semantic(op, f.Name, position)
	if sem != nil && sem.ExpectFailure != "" {
		switch {
		case res.ExitCode == 0:
			k.violate("faults", label, "%s (%s): the run succeeded, want a failure with code %s", sem.Fault, sem.Meaning, sem.ExpectFailure)
		case res.Failure == nil || res.Failure.Code != sem.ExpectFailure:
			k.violate("faults", label, "%s (%s): the run failed with %s, want %s", sem.Fault, sem.Meaning, failureLabel(res), sem.ExpectFailure)
		}
		return
	}
	if res.ExitCode != 0 {
		if !k.required(op) {
			k.violate("faults", label, "the fault failed the whole run with exit %d and %s; only Suite.Required operations may, others record a gap", res.ExitCode, failureLabel(res))
			return
		}
		if f.Expect != "" && (res.Failure == nil || res.Failure.Code != f.Expect) {
			k.violate("faults", label, "the run failed with %s, want %s", failureLabel(res), f.Expect)
		}
		return
	}
	if sem != nil {
		if pin {
			k.checkSemantic(label, *sem, res)
		}
		return
	}
	for _, p := range compareRuns(base.Artifacts, res.Artifacts, gapsOf(res.Result), k.ignore) {
		k.violate("faults", label, "%s", p)
	}
	left := newGaps(base.Result, res.Result)
	if k.suite.GapOperations {
		for _, g := range left {
			if g.Operation != op {
				k.violate("faults", label, "%s", misnamedGap(g, op))
			}
		}
	}
	wrongCode := false
	for _, g := range left {
		if f.Expect != "" && g.Code != f.Expect {
			wrongCode = true
			k.violate("faults", label, "the gap at %s %s has code %s, want %s", g.Path, g.Pointer, g.Code, f.Expect)
		}
	}
	// A fault that changed an answer must leave a new gap with its code,
	// unless one of the cases before the default excuses it.
	switch {
	case len(changed) == 0, wrongCode, k.insensitive(op), leftGap(base.Result, res.Result, f.Expect):
	case k.baselineNet.answers.failedWith(op, changed, f.Expect):
		// Each call the fault changed already failed with its code in the
		// clean run, which recorded that failure's gap.
	default:
		k.violate("faults", label, "%s", unrecorded(op, f.Expect))
	}
}

// leftGap reports whether faulted has a gap with code, or with any code when
// code is "", that clean does not have with that code.
func leftGap(clean, faulted *componentsdk.CollectorResult, code componentsdk.Code) bool {
	for _, g := range gapsOf(faulted) {
		if code != "" && g.Code != code {
			continue
		}
		had := false
		for _, c := range gapsOf(clean) {
			if c.Path == g.Path && c.Pointer == g.Pointer && c.Code == g.Code {
				had = true
				break
			}
		}
		if !had {
			return true
		}
	}
	return false
}

// misnamedGap explains a gap a fault on op left that names another operation
// or none.
func misnamedGap(g componentsdk.Gap, op string) string {
	if g.Operation == "" {
		return fmt.Sprintf("the gap at %s %s names no operation, want %s: record it from the error the call returned, or from one built with componentsdk.ResponseError", g.Path, pointerLabel(g.Pointer), op)
	}
	return fmt.Sprintf("the gap at %s %s names operation %s, want %s, whose fault left it", g.Path, pointerLabel(g.Pointer), g.Operation, op)
}

// unrecorded explains a fault that reached op and left no new gap: the run
// looks like one where the call answered, which hides a failure read as an
// answer whenever the clean answer was empty.
func unrecorded(op string, code componentsdk.Code) string {
	gap := "no new gap"
	if code != "" {
		gap = "no new gap with code " + string(code)
	}
	return fmt.Sprintf("the fault reached %s but left %s; a failed call must leave out what it would have read, with a gap, even where the clean run found nothing. "+
		"Declare a fault that is an answer in Suite.Semantics, or list an operation whose responses change no value in Suite.Insensitive", op, gap)
}

func (k *kit) checkSemantic(label string, sem Semantic, res componentsdk.InProcessResult) {
	for _, p := range pinned(res.Artifacts, sem.Expect) {
		k.violate("faults", label, "%s (%s): %s", sem.Fault, sem.Meaning, p)
	}
}

func (k *kit) checkSensitivity() {
	ops := k.baselineNet.replay.operationsFor()
	for _, op := range k.baseline.Result.Calls.Operations {
		if op.Name == componentsdk.UnnamedOperation || k.insensitive(op.Name) || k.baselineNet.kindOf(op.Name) != kindHTTP {
			continue
		}
		mutated := k.suite.Scenarios[0]
		mutated.Responses = append([]Response(nil), mutated.Responses...)
		changed := false
		var failure error
		for i := range mutated.Responses {
			if !containsString(ops[i], op.Name) {
				continue
			}
			body, ok, err := k.mutateBody(op.Name, mutated.Responses[i])
			if err != nil {
				failure = fmt.Errorf("response %d: %w", i, err)
				break
			}
			if ok {
				mutated.Responses[i].Body = body
				changed = true
			}
		}
		if failure != nil {
			k.violate("sensitivity", op.Name, "the check cannot change %s's responses: %v", op.Name, failure)
			continue
		}
		if !changed {
			k.report.Unmutated = append(k.report.Unmutated, op.Name)
			continue
		}
		res, _ := k.runOnce("sensitivity", op.Name, mutated, nil)
		if res.ExitCode != 0 {
			continue
		}
		if len(compareRuns(k.baseline.Artifacts, res.Artifacts, nil, k.ignore)) == 0 && reflect.DeepEqual(signedInAs(k.baseline), signedInAs(&res)) {
			k.violate("sensitivity", op.Name, "changing %s's responses changed no value and not the result's signed_in_as, so the faults injected into it prove nothing; check that its data is used, or list it in Suite.Insensitive", op.Name)
		}
	}
}

func signedInAs(res *componentsdk.InProcessResult) *componentsdk.Principal {
	if res.Result == nil {
		return nil
	}
	return res.Result.SignedInAs
}

func (k *kit) required(op string) bool    { return containsString(k.suite.Required, op) }
func (k *kit) insensitive(op string) bool { return containsString(k.suite.Insensitive, op) }

// semantic returns the Semantic that declares what fault on op means at
// position, and whether its Expect applies there. A Semantic for op and fault
// whose Positions leave position out still exempts the run from the outcome
// rule, without pinning values.
func (k *kit) semantic(op, fault, position string) (*Semantic, bool) {
	var other *Semantic
	for i := range k.suite.Semantics {
		s := &k.suite.Semantics[i]
		if s.Operation != op || s.Fault != fault {
			continue
		}
		if len(s.Positions) == 0 || containsString(s.Positions, position) {
			return s, true
		}
		if other == nil {
			other = s
		}
	}
	return other, false
}

// positionsOverlap reports whether two Semantics' Positions share a position,
// where an empty list means every position.
func positionsOverlap(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return true
	}
	for _, p := range a {
		if containsString(b, p) {
			return true
		}
	}
	return false
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func failureLabel(res componentsdk.InProcessResult) string {
	if res.Failure == nil {
		return "no failure record"
	}
	return fmt.Sprintf("code %s (%s)", res.Failure.Code, res.Failure.Message)
}

func copyConfig(cfg map[string]any) map[string]any {
	if cfg == nil {
		return nil
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return cfg
	}
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil {
		return cfg
	}
	return out
}

// mutateJSON flips every boolean, empties every array, and adds one to every
// number in body, and reports whether anything changed. Strings stay, so IDs
// and next-page links keep working.
func mutateJSON(body string) (string, bool) {
	dec := json.NewDecoder(strings.NewReader(body))
	dec.UseNumber()
	var doc any
	if dec.Decode(&doc) != nil {
		return body, false
	}
	changed := false
	var walk func(v any) any
	walk = func(v any) any {
		switch node := v.(type) {
		case map[string]any:
			for key, child := range node {
				node[key] = walk(child)
			}
			return node
		case []any:
			if len(node) > 0 {
				changed = true
			}
			return []any{}
		case bool:
			changed = true
			return !node
		case json.Number:
			changed = true
			if i, err := node.Int64(); err == nil {
				return json.Number(strconv.FormatInt(i+1, 10))
			}
			if f, err := node.Float64(); err == nil {
				return json.Number(strconv.FormatFloat(f+1, 'f', -1, 64))
			}
			return node
		default:
			return node
		}
	}
	doc = walk(doc)
	if !changed {
		return body, false
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return body, false
	}
	return string(raw), true
}
