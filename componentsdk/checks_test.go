package componentsdk

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk/internal/outputcheck"
)

const annotatedSchema = `{
	"$schema": "https://json-schema.org/draft/2020-12/schema",
	"type": "object",
	"required": ["org"],
	"properties": {
		"org": {"type": "string"},
		"users": {"type": "array", "items": {"type": "object", "properties": {"mfa": {"type": "boolean"}}}},
		"users_count": {"type": ["integer", "null"], "x-epack-rollup": {"rows": "users"}},
		"mfa_pct": {"type": ["integer", "null"], "x-epack-denominator": "users_count"},
		"admins_count": {"type": ["integer", "null"]},
		"admin_mfa_pct": {"type": ["integer", "null"], "x-epack-denominator": "admins_count"},
		"lockout": {"type": ["boolean", "null"]},
		"score": {"type": ["integer", "null"]}
	}
}`

func emitOnce(spec CollectorSpec, artifacts []CollectedArtifact, gaps ...Location) InProcessResult {
	return RunInProcess(spec, func(ctx CollectorContext) error {
		ctx.Secret("DEMO_TOKEN")
		for _, at := range gaps {
			Records(ctx).NotCollectedCode(at, CodeVendorError, "unavailable")
		}
		return ctx.Emit(artifacts)
	}, InProcessOptions{Secrets: map[string]string{"DEMO_TOKEN": "tok-secret-value-1234"}})
}

func checksOf(res InProcessResult) []string {
	if res.Result == nil {
		return nil
	}
	var out []string
	for _, f := range res.Result.Checks {
		out = append(out, f.Check+" "+f.Path+" "+f.Pointer)
	}
	return out
}

func TestEmitChecksArtifactsAgainstTheirSchemas(t *testing.T) {
	spec := CollectorSpec{Name: "demo", Schemas: map[string][]byte{"artifacts/demo.json": []byte(annotatedSchema)}}
	data := map[string]any{
		"users":         []any{map[string]any{"mfa": true}, map[string]any{"mfa": false}},
		"users_count":   3,
		"mfa_pct":       50,
		"admins_count":  0,
		"admin_mfa_pct": 100,
		"lockout":       nil,
		"score":         nil,
	}
	res := emitOnce(spec, []CollectedArtifact{{Data: data, Path: "artifacts/demo.json"}}, Location{Path: "artifacts/demo.json", Pointer: "/score"})
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("exit = %d stderr = %s", res.ExitCode, res.Stderr)
	}
	want := []string{
		"schema artifacts/demo.json ",
		"population artifacts/demo.json /admin_mfa_pct",
		"nulls artifacts/demo.json /lockout",
		"rollups artifacts/demo.json /users_count",
	}
	if got := checksOf(res); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("checks = %q, want %q", got, want)
	}
	if res.Result.Outcome.Status != OutcomePartial || res.Result.Outcome.Code != CodeVendorError {
		t.Errorf("outcome = %+v, want it to follow the gap alone", res.Result.Outcome)
	}

	clean := emitOnce(spec, []CollectedArtifact{{Data: map[string]any{"org": "acme", "users": []any{}, "users_count": 0, "mfa_pct": nil}, Path: "artifacts/demo.json"}})
	if len(checksOf(clean)) != 0 || clean.Result.Outcome.Status != OutcomeCollected {
		t.Errorf("a clean artifact got checks %q and outcome %+v", checksOf(clean), clean.Result.Outcome)
	}
	raw, _ := json.Marshal(clean.Result)
	if strings.Contains(string(raw), `"checks"`) {
		t.Errorf("a result without findings should leave checks out: %s", raw)
	}

	unchecked := emitOnce(CollectorSpec{Name: "demo"}, []CollectedArtifact{{Data: data, Path: "artifacts/demo.json"}})
	if len(checksOf(unchecked)) != 0 {
		t.Errorf("an artifact without a schema got checks %q", checksOf(unchecked))
	}
}

func TestNormalizedSchemasApplyUnlessTheCollectorHasItsOwn(t *testing.T) {
	posture := map[string]any{
		"schema_version": "1.0.0",
		"collected_at":   "2026-01-01T00:00:00Z",
		"org_domain":     "example.test",
		"user_security":  map[string]any{"mfa_coverage_pct": 80, "inactive_pct": nil},
	}
	artifact := CollectedArtifact{Data: posture, Schema: "evidencepack/idp-posture@v1", Path: "artifacts/demo.idp-posture.json"}
	res := emitOnce(CollectorSpec{Name: "demo"}, []CollectedArtifact{artifact})
	want := "schema artifacts/demo.idp-posture.json |nulls artifacts/demo.idp-posture.json /user_security/inactive_pct"
	if got := strings.Join(checksOf(res), "|"); got != want {
		t.Errorf("checks = %q, want %q", got, want)
	}
	if res.Result.Checks[0].Message != "missing property 'provider'" {
		t.Errorf("message = %q", res.Result.Checks[0].Message)
	}

	permissive := []byte(`{"type": "object"}`)
	for _, key := range []string{"evidencepack/idp-posture@v1", "artifacts/demo.idp-posture.json"} {
		res := emitOnce(CollectorSpec{Name: "demo", Schemas: map[string][]byte{key: permissive}}, []CollectedArtifact{artifact})
		if got := checksOf(res); len(got) != 0 {
			t.Errorf("a schema keyed by %s should replace the SDK's, got %q", key, got)
		}
	}
}

func TestAnUnusableSchemaNeverFailsTheRun(t *testing.T) {
	spec := CollectorSpec{Name: "demo", Schemas: map[string][]byte{
		"artifacts/demo.json":         []byte(`{"type": 5}`),
		"evidencepack/idp-posture@v1": []byte(`{`),
	}}
	artifacts := []CollectedArtifact{
		{Data: map[string]any{"users": nil}, Path: "artifacts/demo.json"},
		{Data: map[string]any{}, Schema: "evidencepack/idp-posture@v1", Path: "a.json"},
		{Data: map[string]any{}, Schema: "evidencepack/idp-posture@v1", Path: "b.json"},
	}
	res := emitOnce(spec, artifacts)
	if res.ExitCode != 0 || res.Result == nil || res.Result.Outcome.Status != OutcomeCollected {
		t.Fatalf("exit = %d result = %+v stderr = %s", res.ExitCode, res.Result, res.Stderr)
	}
	if n := strings.Count(res.Stderr, "warning: "); n != 2 {
		t.Errorf("stderr has %d warnings, want one per schema: %s", n, res.Stderr)
	}
	want := "schema_unusable  |schema_unusable  "
	if got := strings.Join(checksOf(res), "|"); got != want {
		t.Fatalf("checks = %q, want only the two schema_unusable findings", got)
	}
	if !strings.Contains(res.Result.Checks[0].Message, "artifacts/demo.json") || !strings.Contains(res.Result.Checks[1].Message, "evidencepack/idp-posture@v1") {
		t.Errorf("messages should name the schemas: %+v", res.Result.Checks)
	}
}

func TestRunCollectorCompilesSchemasWhenItStarts(t *testing.T) {
	t.Setenv("EPACK_COLLECTOR_CONFIG", "")
	var c *collectorContext
	stderr := captureStderr(t, func() {
		ctx, cancel, code := buildCollectorContext(CollectorSpec{Name: "demo", Schemas: map[string][]byte{
			"artifacts/broken.json": []byte(`{"type": 5}`),
			"artifacts/demo.json":   []byte(annotatedSchema),
		}})
		if code != 0 {
			t.Fatalf("exit code %d", code)
		}
		cancel()
		c = ctx
	})
	if strings.Count(stderr, "warning: ") != 1 || !strings.Contains(stderr, "artifacts/broken.json") {
		t.Errorf("stderr = %q, want one warning naming the broken schema", stderr)
	}
	if s := c.run.schemas["artifacts/demo.json"]; s == nil || s.schema == nil {
		t.Error("a schema that compiles should be ready for Emit")
	}
	if s := c.run.schemas["artifacts/broken.json"]; s == nil || s.err == nil {
		t.Error("a schema that does not compile should keep its error for the finding")
	}
}

func TestCheckFindingsAreCapped(t *testing.T) {
	schema := []byte(`{"type": "object", "additionalProperties": {"type": ["boolean", "null"]}}`)
	data := map[string]any{}
	for i := 0; i < 150; i++ {
		data[fmt.Sprintf("flag_%03d", i)] = nil
	}
	res := emitOnce(CollectorSpec{Name: "demo", Schemas: map[string][]byte{"artifacts/demo.json": schema}}, []CollectedArtifact{{Data: data, Path: "artifacts/demo.json"}})
	if res.Result == nil || len(res.Result.Checks) != maxCheckFindings || res.Result.ChecksDropped != 50 {
		t.Fatalf("result = %+v", res.Result)
	}
	if res.Result.Checks[0].Pointer != "/flag_000" {
		t.Errorf("the first findings should be kept, got %+v", res.Result.Checks[0])
	}
	resultSchema, err := outputcheck.Compile(ResultSchemaJSON())
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range res.Artifacts {
		if a.Schema != ResultSchema {
			continue
		}
		doc, err := outputcheck.Decode(a.Data)
		if err != nil {
			t.Fatal(err)
		}
		if got := outputcheck.Validate(resultSchema, a.Path, doc); len(got) != 0 {
			t.Errorf("a result with findings does not match the result schema: %+v", got)
		}
	}
}

func TestCheckMessagesNeverCarrySecrets(t *testing.T) {
	schema := []byte(`{"properties": {"id": {"type": "string", "pattern": "^[0-9]+$"}}}`)
	res := emitOnce(CollectorSpec{Name: "demo", Schemas: map[string][]byte{"artifacts/demo.json": schema}},
		[]CollectedArtifact{{Data: map[string]any{"id": "user-tok-secret-value-1234"}, Path: "artifacts/demo.json"}})
	if res.Result == nil || len(res.Result.Checks) != 1 {
		t.Fatalf("result = %+v", res.Result)
	}
	if msg := res.Result.Checks[0].Message; strings.Contains(msg, "tok-secret-value-1234") || !strings.Contains(msg, "does not match pattern") {
		t.Errorf("message = %q, want the pattern failure with the secret redacted", msg)
	}
}

func TestNormalizedSchemas(t *testing.T) {
	if NormalizedSchemaJSON("evidencepack/unknown@v1") != nil {
		t.Error("an unknown type should have no schema")
	}
	cases := []struct {
		id      string
		valid   string
		invalid string
	}{
		{
			"evidencepack/idp-posture@v1",
			`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "entra", "org_domain": "example.test",
			  "user_security": {"mfa_coverage_pct": 91, "inactive_pct": null}, "policy": null}`,
			`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "entra"}`,
		},
		{
			"evidencepack/cloud-posture@v1",
			`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "azure",
			  "accounts": [{"account_id": "sub-1", "iam": {"mfa_coverage_pct": null}, "storage": null}]}`,
			`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "azure", "accounts": [{"iam": {}}]}`,
		},
		{
			"evidencepack/vcs-posture@v1",
			`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "github", "organization": "acme",
			  "repo_coverage_pct": null, "branch_protection": {"pr_required_pct": 100}}`,
			`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "github"}`,
		},
		{
			"evidencepack/email-dns@v1",
			`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z",
			  "domains": [{"domain": "example.test", "dmarc": {"record": "v=DMARC1", "pct": null}}], "summary": {"with_spf_pct": null}}`,
			`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "domains": [{"mx": []}]}`,
		},
		{
			"evidencepack/tls@v1",
			`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z",
			  "endpoints": [{"host": "example.test", "port": 443, "reachable": null, "tls": {"protocol_support": {"tls_1_3": true}}}]}`,
			`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "endpoints": [{"host": "example.test", "port": null}]}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			s, err := outputcheck.Compile(NormalizedSchemaJSON(tc.id))
			if err != nil {
				t.Fatal(err)
			}
			valid, _ := outputcheck.Decode([]byte(tc.valid))
			if got := outputcheck.Validate(s, "a.json", valid); len(got) != 0 {
				t.Errorf("an artifact that leaves metrics out should match: %+v", got)
			}
			invalid, _ := outputcheck.Decode([]byte(tc.invalid))
			if got := outputcheck.Validate(s, "a.json", invalid); len(got) == 0 {
				t.Error("an artifact without its identifying fields should not match")
			}
		})
	}
}

func TestCloudPostureCountsAndWorkforceSignInAreOptional(t *testing.T) {
	s, err := outputcheck.Compile(NormalizedSchemaJSON("evidencepack/cloud-posture@v1"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		doc  string
		bad  string
	}{
		{
			"with the counts and workforce sign-in",
			`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "aws",
			  "accounts": [
			    {"account_id": "111111111111", "iam": {"user_count": 0, "root_mfa_enabled": true, "access_key_user_count": 0, "saml_provider_count": 0}},
			    {"account_id": "222222222222", "iam": {"user_count": 4, "mfa_coverage_pct": 50, "access_key_user_count": 2, "access_key_rotation_compliant_pct": 100, "saml_provider_count": 1}}],
			  "workforce_sign_in": {"in_use": true, "user_count": 12, "mfa_source": "sign_in_service"}}`,
			"",
		},
		{
			"with them null",
			`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "aws",
			  "accounts": [{"account_id": "111111111111", "iam": {"user_count": null, "access_key_user_count": null, "saml_provider_count": null}}],
			  "workforce_sign_in": {"in_use": null, "user_count": null, "mfa_source": null}}`,
			"",
		},
		{
			"without them",
			`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "aws",
			  "accounts": [{"account_id": "111111111111", "iam": {"mfa_coverage_pct": 100, "access_key_rotation_compliant_pct": 95}}]}`,
			"",
		},
		{
			"a negative count",
			`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "aws",
			  "accounts": [{"account_id": "111111111111", "iam": {"user_count": -1}}]}`,
			"/accounts/0/iam/user_count",
		},
		{
			"an unknown mfa source",
			`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "aws",
			  "accounts": [], "workforce_sign_in": {"in_use": true, "mfa_source": "okta"}}`,
			"/workforce_sign_in/mfa_source",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := outputcheck.Decode([]byte(tc.doc))
			if err != nil {
				t.Fatal(err)
			}
			got := outputcheck.Validate(s, "a.json", doc)
			switch {
			case tc.bad == "" && len(got) != 0:
				t.Errorf("findings %+v, want none", got)
			case tc.bad != "" && (len(got) != 1 || got[0].Pointer != tc.bad):
				t.Errorf("findings %+v, want one at %s", got, tc.bad)
			}
		})
	}
}

const mfaSchema = `{
	"$schema": "https://json-schema.org/draft/2020-12/schema",
	"type": "object",
	"properties": {
		"total_count": {"type": "integer"},
		"mfa_enrolled_count": {"type": ["integer", "null"], "x-epack-rollup": {"rows": "people", "where": "/has_active_mfa"}},
		"mfa_coverage": {"type": ["integer", "null"], "x-epack-denominator": "total_count", "x-epack-numerator": "mfa_enrolled_count", "x-epack-rounding": "floor",
			"x-epack-rollup": {"rows": "people", "where": "/has_active_mfa", "as": "pct"}},
		"people": {
			"type": "array",
			"x-epack-level": "audit",
			"items": {"type": "object", "properties": {"login": {"type": "string"}, "has_active_mfa": {"type": ["boolean", "null"], "x-epack-level": "internal"}}}
		}
	}
}`

func TestEmitChecksRatiosAndLevelAwareRollups(t *testing.T) {
	spec := CollectorSpec{Name: "demo", Schemas: map[string][]byte{"artifacts/demo.json": []byte(mfaSchema)}}
	emitAt := func(level Level, coverage int) InProcessResult {
		return RunInProcess(spec, func(ctx CollectorContext) error {
			people := []any{map[string]any{"login": "a"}, map[string]any{"login": "b"}, map[string]any{"login": "c"}}
			if ctx.Level().AtLeast(LevelInternal) {
				people = []any{
					map[string]any{"login": "a", "has_active_mfa": true},
					map[string]any{"login": "b", "has_active_mfa": true},
					map[string]any{"login": "c", "has_active_mfa": false},
				}
			}
			data := map[string]any{"total_count": 3, "mfa_enrolled_count": 2, "mfa_coverage": coverage}
			if ctx.Level().AtLeast(LevelAudit) {
				data["people"] = people
			}
			return ctx.Emit([]CollectedArtifact{{Data: data, Path: "artifacts/demo.json"}})
		}, InProcessOptions{Config: map[string]any{"level": string(level)}})
	}
	for _, level := range []Level{LevelTrust, LevelAudit, LevelInternal} {
		if got := checksOf(emitAt(level, 66)); len(got) != 0 {
			t.Errorf("%s: checks = %v, want none: 66 is 2 of 3 rounded down, and the MFA rollups need internal rows", level, got)
		}
	}
	if got := checksOf(emitAt(LevelAudit, 67)); strings.Join(got, ",") != "ratios artifacts/demo.json /mfa_coverage" {
		t.Errorf("checks = %v, want a ratios finding for 67", got)
	}
}
