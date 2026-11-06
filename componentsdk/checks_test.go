package componentsdk

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/outputcheck"
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
			  "accounts": [{"account_id": "sub-1", "storage": {"encryption_pct": null}, "database": null}]}`,
			`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "accounts": [{"storage": {}}]}`,
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
		{
			"evidencepack/endpoint-posture@v1",
			`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "jumpcloud",
			  "scope": {"discovery_complete": true, "description": "provider_visible_devices", "max_observation_age_seconds": 604800},
			  "hardening": {"disk_encryption_pct": null}, "availability": []}`,
			`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "jumpcloud", "availability": []}`,
		},
		{
			"evidencepack/access-posture@v1",
			`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "clickhouse", "system_type": "database",
			  "sign_in": {"sso_required": false, "mfa_required": true, "scim_enabled": null}, "members": {"members_present": true, "inactive_pct": null}, "root": null}`,
			`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "clickhouse"}`,
		},
		{
			"evidencepack/vuln-scanning@v1",
			`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "github",
			  "scanners": [{"scanner": "dependabot", "category": "dependencies", "enabled": true, "coverage_pct": null}]}`,
			`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "github", "scanners": [{"enabled": true}]}`,
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

// TestNormalizedPercentagesRoundTowardTheGap checks that every percentage in
// the normalized schemas rounds in the direction that keeps a shortfall
// visible. A percentage where more is better rounds down, so 996 of 1,000 is
// 99 and not 100. A percentage where more is worse rounds up, so 1 open rule
// of 201 is 1 and not 0. A deprecated field keeps the definition it had
// before epack v0.10.0, so the test skips it.
func TestNormalizedPercentagesRoundTowardTheGap(t *testing.T) {
	for id := range normalizedFiles {
		var doc any
		if err := json.Unmarshal(NormalizedSchemaJSON(id), &doc); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		var walk func(node any, at string)
		walk = func(node any, at string) {
			switch n := node.(type) {
			case map[string]any:
				if n["deprecated"] == true {
					return
				}
				if strings.HasSuffix(at, "_pct") {
					if r := n["x-epack-rounding"]; r != "floor" && r != "ceil" {
						t.Errorf("%s %s: x-epack-rounding is %v, want floor or ceil", id, at, r)
					}
				}
				for key, child := range n {
					walk(child, at+"/"+key)
				}
			case []any:
				for i, child := range n {
					walk(child, fmt.Sprintf("%s/%d", at, i))
				}
			}
		}
		walk(doc, "")
	}
}

func TestNormalizedSummariesCheckTheirPercentages(t *testing.T) {
	cases := []struct {
		id, doc string
		check   string
		pointer string
	}{
		{
			"evidencepack/tls@v1",
			`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "endpoints": [],
			  "summary": {"total_endpoints": 201, "legacy_protocol_supported_count": 1, "legacy_protocol_supported_pct": 0}}`,
			outputcheck.CheckRatios, "/summary/legacy_protocol_supported_pct",
		},
		{
			"evidencepack/tls@v1",
			`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "endpoints": [],
			  "summary": {"total_endpoints": 4, "certificate_valid_count": 3, "all_certificates_valid": true}}`,
			outputcheck.CheckRatios, "/summary/all_certificates_valid",
		},
		{
			"evidencepack/email-dns@v1",
			`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "domains": [],
			  "summary": {"total_domains": 1000, "with_dmarc_count": 996, "with_dmarc_pct": 100}}`,
			outputcheck.CheckRatios, "/summary/with_dmarc_pct",
		},
		{
			"evidencepack/cloud-posture@v1",
			`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "aws",
			  "accounts": [{"storage": {"storage_resources_present": false, "encryption_pct": 100, "public_access_blocked_pct": null}}]}`,
			outputcheck.CheckPopulation, "/accounts/0/storage/encryption_pct",
		},
		{
			"evidencepack/idp-posture@v1",
			`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "entra", "org_domain": "example.test",
			  "privileged_access": {"privileged_users_count": 0, "privileged_mfa_coverage_pct": 100, "privileged_phishing_resistant_pct": null}}`,
			outputcheck.CheckPopulation, "/privileged_access/privileged_mfa_coverage_pct",
		},
	}
	for _, tc := range cases {
		t.Run(tc.pointer, func(t *testing.T) {
			s, err := outputcheck.Compile(NormalizedSchemaJSON(tc.id))
			if err != nil {
				t.Fatal(err)
			}
			doc, err := outputcheck.Decode([]byte(tc.doc))
			if err != nil {
				t.Fatal(err)
			}
			if got := outputcheck.Validate(s, "a.json", doc); len(got) != 0 {
				t.Fatalf("the artifact should match its schema: %+v", got)
			}
			got := outputcheck.Check(s, "a.json", doc, nil, "trust")
			if len(got) != 1 || got[0].Check != tc.check || got[0].Pointer != tc.pointer {
				t.Errorf("findings %+v, want one %s finding at %s", got, tc.check, tc.pointer)
			}
		})
	}
}

// TestDeprecatedBlocksKeepTheirOldFields checks that cloud-posture and
// vcs-posture artifacts written the way collectors wrote them before epack
// v0.10.0 still match, with every old field kept at the trust level, as
// profiles written then read them. It also checks that each field in those
// blocks names the type that holds its value now.
func TestDeprecatedBlocksKeepTheirOldFields(t *testing.T) {
	cases := []struct{ id, doc string }{
		{"evidencepack/cloud-posture@v1", `{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "aws",
		  "accounts": [{"account_label": "production",
		    "iam": {"user_count": 2, "mfa_coverage_pct": 50, "root_mfa_enabled": true, "root_access_protected": true,
		      "access_key_user_count": 1, "access_key_rotation_compliant_pct": 100, "saml_provider_count": 0},
		    "vuln_scanning": {"enabled": true, "unpatched_pct": 10}}],
		  "workforce_sign_in": {"in_use": true, "user_count": 4, "mfa_source": "external_idp"}}`},
		{"evidencepack/vcs-posture@v1", `{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "github", "organization": "acme",
		  "org_security": {"two_factor_required": true},
		  "security_features": {"vuln_alerts_pct": 90, "secret_scanning_pct": 80, "code_scanning_pct": 70}}`},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			s, err := outputcheck.Compile(NormalizedSchemaJSON(tc.id))
			if err != nil {
				t.Fatal(err)
			}
			doc, err := outputcheck.Decode([]byte(tc.doc))
			if err != nil {
				t.Fatal(err)
			}
			if got := outputcheck.Validate(s, "a.json", doc); len(got) != 0 {
				t.Errorf("findings %+v, want none", got)
			}
			if got := outputcheck.AboveLevel(s, "a.json", doc, "trust"); len(got) != 0 {
				t.Errorf("above trust: %+v, want none", got)
			}
			var raw map[string]any
			if err := json.Unmarshal(NormalizedSchemaJSON(tc.id), &raw); err != nil {
				t.Fatal(err)
			}
			moved := map[string]bool{"iam": true, "vuln_scanning": true, "workforce_sign_in": true, "org_security": true, "security_features": true}
			var walk func(node map[string]any, at string, inMoved bool)
			walk = func(node map[string]any, at string, inMoved bool) {
				props, _ := node["properties"].(map[string]any)
				if inMoved && node["deprecated"] != true {
					t.Errorf("%s should be marked deprecated", at)
				}
				if inMoved && props == nil {
					if desc, _ := node["description"].(string); !strings.Contains(desc, "evidencepack/") {
						t.Errorf("%s should name the type that holds its value now: %q", at, desc)
					}
				}
				if items, ok := node["items"].(map[string]any); ok {
					walk(items, at+"/*", inMoved)
				}
				for name, child := range props {
					if c, ok := child.(map[string]any); ok {
						walk(c, at+"/"+name, inMoved || moved[name])
					}
				}
			}
			walk(raw, "", false)
		})
	}
}

func TestCloudPostureTrustLevelLeavesOutCountsAndAccountIDs(t *testing.T) {
	s, err := outputcheck.Compile(NormalizedSchemaJSON("evidencepack/cloud-posture@v1"))
	if err != nil {
		t.Fatal(err)
	}
	full := `{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "aws",
	  "accounts_expected": 2, "all_accounts_collected": true,
	  "accounts": [{"account_id": "111111111111", "account_label": "production",
	    "storage": {"storage_resources_present": true, "storage_resource_count": 4, "encrypted_storage_resource_count": 2, "encryption_pct": 50}}]}`
	doc, err := outputcheck.Decode([]byte(full))
	if err != nil {
		t.Fatal(err)
	}
	if got := outputcheck.Validate(s, "a.json", doc); len(got) != 0 {
		t.Fatalf("findings %+v, want none", got)
	}
	if got := outputcheck.AboveLevel(s, "a.json", doc, "audit"); len(got) != 0 {
		t.Errorf("at audit: %+v, want none", got)
	}
	var pointers []string
	for _, f := range outputcheck.AboveLevel(s, "a.json", doc, "trust") {
		pointers = append(pointers, f.Pointer)
	}
	want := []string{
		"/accounts/0/account_id",
		"/accounts/0/storage/encrypted_storage_resource_count",
		"/accounts/0/storage/storage_resource_count",
		"/accounts_expected",
	}
	if !reflect.DeepEqual(pointers, want) {
		t.Errorf("above trust = %q, want %q", pointers, want)
	}

	trust := `{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "aws",
	  "all_accounts_collected": true,
	  "accounts": [{"account_label": "production", "storage": {"storage_resources_present": true, "encryption_pct": 50}}]}`
	doc, err = outputcheck.Decode([]byte(trust))
	if err != nil {
		t.Fatal(err)
	}
	if got := outputcheck.Validate(s, "a.json", doc); len(got) != 0 {
		t.Errorf("a trust artifact without account IDs or counts should match: %+v", got)
	}
	if got := outputcheck.AboveLevel(s, "a.json", doc, "trust"); len(got) != 0 {
		t.Errorf("trust artifact: %+v, want nothing above trust", got)
	}
}

func TestCloudPostureCountsAreOptional(t *testing.T) {
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
			"with the counts",
			`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "aws",
			  "accounts": [
			    {"account_id": "111111111111", "storage": {"storage_resources_present": false, "storage_resource_count": 0, "encrypted_storage_resource_count": 0}},
			    {"account_id": "222222222222", "storage": {"storage_resources_present": true, "storage_resource_count": 4, "encrypted_storage_resource_count": 2, "encryption_pct": 50},
			     "database": {"databases_present": true, "database_count": 2, "encrypted_database_count": 2, "encryption_pct": 100}}]}`,
			"",
		},
		{
			"with them null",
			`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "aws",
			  "accounts": [{"account_id": "111111111111", "storage": {"storage_resource_count": null, "encrypted_storage_resource_count": null}}]}`,
			"",
		},
		{
			"without them",
			`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "aws",
			  "accounts": [{"account_id": "111111111111", "storage": {"encryption_pct": 100, "public_access_blocked_pct": 95}}]}`,
			"",
		},
		{
			"a negative count",
			`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "aws",
			  "accounts": [{"account_id": "111111111111", "storage": {"storage_resource_count": -1}}]}`,
			"/accounts/0/storage/storage_resource_count",
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

func TestEndpointPostureKeepsFleetCountsAtTheAuditLevel(t *testing.T) {
	s, err := outputcheck.Compile(NormalizedSchemaJSON("evidencepack/endpoint-posture@v1"))
	if err != nil {
		t.Fatal(err)
	}
	decode := func(raw string) any {
		doc, err := outputcheck.Decode([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		return doc
	}
	scope := `"scope": {"discovery_complete": true, "observed_device_count": 4, "description": "provider_visible_devices", "max_observation_age_seconds": 604800}`
	audit := decode(`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "jumpcloud", ` + scope + `,
	  "fleet": {"devices_present": true, "device_count": 4, "managed_device_count": 4, "mdm_enrolled_device_count": 3, "mdm_enrolled_pct": 75, "devices_by_os": {"macos": 3, "windows": 1}},
	  "hardening": {"disk_encryption_pct": 50},
	  "metric_coverage": {"hardening.disk_encryption_pct": {"passing_device_count": 1, "failing_device_count": 1, "unknown_device_count": 2, "not_applicable_device_count": 0}},
	  "availability": [], "devices": [{"device_id": "d1", "os_family": "macos", "in_scope": true}]}`)
	if got := outputcheck.Validate(s, "a.json", audit); len(got) != 0 {
		t.Fatalf("an audit artifact should match: %+v", got)
	}
	if got := outputcheck.Check(s, "a.json", audit, nil, "audit"); len(got) != 0 {
		t.Errorf("3 of 4 devices enrolled is 75: %+v", got)
	}
	var above []string
	for _, f := range outputcheck.AboveLevel(s, "a.json", audit, "trust") {
		above = append(above, f.Pointer)
	}
	want := []string{"/devices", "/fleet/device_count", "/fleet/devices_by_os", "/fleet/managed_device_count",
		"/fleet/mdm_enrolled_device_count", "/metric_coverage", "/scope/observed_device_count"}
	if !reflect.DeepEqual(above, want) {
		t.Errorf("above trust = %q, want %q", above, want)
	}

	trust := decode(`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "jumpcloud",
	  "scope": {"discovery_complete": true, "description": "provider_visible_devices", "max_observation_age_seconds": 604800},
	  "fleet": {"devices_present": true, "mdm_enrolled_pct": 75}, "hardening": {"disk_encryption_pct": 50}, "availability": []}`)
	if got := outputcheck.Validate(s, "a.json", trust); len(got) != 0 {
		t.Errorf("a trust artifact without counts or coverage should match: %+v", got)
	}
	if got := outputcheck.AboveLevel(s, "a.json", trust, "trust"); len(got) != 0 {
		t.Errorf("trust artifact: %+v, want nothing above trust", got)
	}

	empty := decode(`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "jumpcloud",
	  "scope": {"discovery_complete": true, "description": "provider_visible_devices", "max_observation_age_seconds": 604800},
	  "fleet": {"devices_present": false, "mdm_enrolled_pct": null},
	  "hardening": {"disk_encryption_pct": 100, "screen_lock_compliant_pct": null, "firewall_enabled_pct": null}, "availability": []}`)
	got := outputcheck.Check(s, "a.json", empty, nil, "trust")
	if len(got) != 1 || got[0].Check != outputcheck.CheckPopulation || got[0].Pointer != "/hardening/disk_encryption_pct" {
		t.Errorf("a percentage over a fleet with no devices: %+v, want one population finding", got)
	}

	wrong := decode(strings.Replace(string(mustJSONText(t, audit)), `"mdm_enrolled_pct":75`, `"mdm_enrolled_pct":76`, 1))
	if got := outputcheck.Check(s, "a.json", wrong, nil, "audit"); len(got) != 1 || got[0].Check != outputcheck.CheckRatios {
		t.Errorf("76 for 3 of 4 enrolled: %+v, want one ratios finding", got)
	}
}

func TestAccessPostureKeepsCountsAndScopesAtTheAuditLevel(t *testing.T) {
	s, err := outputcheck.Compile(NormalizedSchemaJSON("evidencepack/access-posture@v1"))
	if err != nil {
		t.Fatal(err)
	}
	sections := `"sign_in": {"sso_configured": true, "sso_required": false},
	  "members": {"members_present": true, "member_count": 9, "sso_member_count": 6, "sso_coverage_pct": 66,
	    "local_members_present": true, "local_member_count": 3, "local_mfa_member_count": 3, "local_mfa_coverage_pct": 100},
	  "admins": {"admins_present": true, "admin_count": 2, "admin_share_pct": 23},
	  "root": {"root_accounts_present": true, "root_account_count": 1, "root_mfa_account_count": 1, "root_mfa_coverage_pct": 100, "root_access_keys_present": false},
	  "credentials": {"credentials_present": true, "credential_count": 6, "unused_credential_count": 1, "unused_pct": 17}`
	audit := decode(t, `{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "aws", "system_type": "cloud", `+sections+`,
	  "scopes": [{"id": "111111111111", "name": "prod", "kind": "account", `+sections+`}]}`)
	if got := outputcheck.Validate(s, "a.json", audit); len(got) != 0 {
		t.Fatalf("an audit artifact should match: %+v", got)
	}
	if got := outputcheck.Check(s, "a.json", audit, nil, "audit"); len(got) != 0 {
		t.Errorf("each percentage matches its counts: %+v", got)
	}
	var above []string
	for _, f := range outputcheck.AboveLevel(s, "a.json", audit, "trust") {
		above = append(above, f.Pointer)
	}
	want := []string{"/admins/admin_count", "/credentials/credential_count", "/credentials/unused_credential_count",
		"/members/local_member_count", "/members/local_mfa_member_count", "/members/member_count", "/members/sso_member_count",
		"/root/root_account_count", "/root/root_mfa_account_count", "/scopes"}
	if !reflect.DeepEqual(above, want) {
		t.Errorf("above trust = %q, want %q", above, want)
	}

	// admin_share_pct's denominator is member_count in the members section
	// beside it, so a scope's share is checked against that scope's members.
	wrong := decode(t, strings.Replace(string(mustJSONText(t, audit)), `"admin_share_pct":23`, `"admin_share_pct":22`, 1))
	got := outputcheck.Check(s, "a.json", wrong, nil, "audit")
	if len(got) != 1 || got[0].Check != outputcheck.CheckRatios || got[0].Pointer != "/admins/admin_share_pct" {
		t.Errorf("2 admins of 9 members rounds up to 23: %+v, want one ratios finding", got)
	}

	sso := decode(t, `{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "github", "system_type": "code_host",
	  "members": {"members_present": true, "local_members_present": false, "local_mfa_coverage_pct": 100, "sso_coverage_pct": 100}}`)
	got = outputcheck.Check(s, "a.json", sso, nil, "trust")
	if len(got) != 1 || got[0].Check != outputcheck.CheckPopulation || got[0].Pointer != "/members/local_mfa_coverage_pct" {
		t.Errorf("local MFA coverage with no local members: %+v, want one population finding", got)
	}
}

func TestVulnScanningKeepsCountsAndScopesAtTheAuditLevel(t *testing.T) {
	s, err := outputcheck.Compile(NormalizedSchemaJSON("evidencepack/vuln-scanning@v1"))
	if err != nil {
		t.Fatal(err)
	}
	scanner := `{"scanner": "inspector", "category": "hosts", "enabled": true, "resources_present": true, "resource_count": 40, "scanned_resource_count": 39,
	  "coverage_pct": 97, "open_critical_present": true, "open_high_present": false, "overdue_present": true,
	  "open_critical_count": 2, "open_high_count": 0, "overdue_critical_count": 1}`
	doc := decode(t, `{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "aws",
	  "scanners": [`+scanner+`], "scopes": [{"id": "111111111111", "kind": "account", "scanners": [`+scanner+`]}]}`)
	if got := outputcheck.Validate(s, "a.json", doc); len(got) != 0 {
		t.Fatalf("an audit artifact should match: %+v", got)
	}
	if got := outputcheck.Check(s, "a.json", doc, nil, "audit"); len(got) != 0 {
		t.Errorf("39 of 40 covered rounds down to 97: %+v", got)
	}
	up := decode(t, strings.ReplaceAll(string(mustJSONText(t, doc)), `"coverage_pct":97`, `"coverage_pct":98`))
	got := outputcheck.Check(s, "a.json", up, nil, "audit")
	if len(got) != 2 || got[0].Check != outputcheck.CheckRatios || got[0].Pointer != "/scanners/0/coverage_pct" ||
		got[1].Pointer != "/scopes/0/scanners/0/coverage_pct" {
		t.Errorf("98 for 39 of 40: %+v, want a ratios finding in the summary and in the scope", got)
	}
	var above []string
	for _, f := range outputcheck.AboveLevel(s, "a.json", doc, "trust") {
		above = append(above, f.Pointer)
	}
	want := []string{"/scanners/0/open_critical_count", "/scanners/0/open_high_count", "/scanners/0/overdue_critical_count",
		"/scanners/0/resource_count", "/scanners/0/scanned_resource_count", "/scopes"}
	if !reflect.DeepEqual(above, want) {
		t.Errorf("above trust = %q, want %q", above, want)
	}
}

func decode(t *testing.T, raw string) any {
	t.Helper()
	doc, err := outputcheck.Decode([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func mustJSONText(t *testing.T, doc any) []byte {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCloudPostureDatabaseFields(t *testing.T) {
	s, err := outputcheck.Compile(NormalizedSchemaJSON("evidencepack/cloud-posture@v1"))
	if err != nil {
		t.Fatal(err)
	}
	doc := func(database string) any {
		d, err := outputcheck.Decode([]byte(`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "aws",
		  "accounts": [{"database": ` + database + `, "threat_detection": {"enabled": true}}]}`))
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	audit := doc(`{"databases_present": true, "database_count": 3, "encrypted_database_count": 2, "encryption_pct": 66,
	  "public_access_blocked_database_count": 3, "public_access_blocked_pct": 100, "multi_az_database_count": 1, "multi_az_pct": 33}`)
	if got := outputcheck.Validate(s, "a.json", audit); len(got) != 0 {
		t.Fatalf("schema: %+v", got)
	}
	if got := outputcheck.Check(s, "a.json", audit, nil, "audit"); len(got) != 0 {
		t.Errorf("2 of 3 encrypted rounds down to 66: %+v", got)
	}
	var above []string
	for _, f := range outputcheck.AboveLevel(s, "a.json", audit, "trust") {
		above = append(above, f.Pointer)
	}
	want := []string{"/accounts/0/database/database_count", "/accounts/0/database/encrypted_database_count",
		"/accounts/0/database/multi_az_database_count", "/accounts/0/database/multi_az_pct", "/accounts/0/database/public_access_blocked_database_count"}
	if !reflect.DeepEqual(above, want) {
		t.Errorf("above trust = %q, want %q", above, want)
	}
	none := doc(`{"databases_present": false, "encryption_pct": 100, "public_access_blocked_pct": null}`)
	got := outputcheck.Check(s, "a.json", none, nil, "trust")
	if len(got) != 1 || got[0].Check != outputcheck.CheckPopulation || got[0].Pointer != "/accounts/0/database/encryption_pct" {
		t.Errorf("an account with no databases: %+v, want one population finding for the percentage it set", got)
	}
}

// TestNormalizedPercentagesNameTheirCounts checks that every normalized
// percentage has x-epack-numerator and x-epack-denominator, so the ratio and
// population checks run on it. It also checks that each reference points to a
// property the schema defines. Endpoint posture's control percentages may
// leave the references out. Each is taken over the devices that passed or
// failed, and metric_coverage holds those counts. A deprecated field keeps
// the definition it had before epack v0.10.0, so the test skips it.
func TestNormalizedPercentagesNameTheirCounts(t *testing.T) {
	for id := range normalizedFiles {
		var doc map[string]any
		if err := json.Unmarshal(NormalizedSchemaJSON(id), &doc); err != nil {
			t.Fatal(err)
		}
		// deref follows a local $ref, so a section defined once in $defs is
		// checked wherever it is used.
		deref := func(node map[string]any) map[string]any {
			ref, _ := node["$ref"].(string)
			name, ok := strings.CutPrefix(ref, "#/$defs/")
			if !ok {
				return node
			}
			defs, _ := doc["$defs"].(map[string]any)
			target, _ := defs[name].(map[string]any)
			return target
		}
		lookup := func(node map[string]any, path string) bool {
			for _, token := range strings.Split(path, "/") {
				props, _ := deref(node)["properties"].(map[string]any)
				next, ok := props[token].(map[string]any)
				if !ok {
					return false
				}
				node = next
			}
			return true
		}
		// defined reports whether ref points to a property the schema
		// defines. objects holds the schemas from the root down to the one
		// holding the value. A ref is a sibling's name, an absolute pointer
		// through properties from the root, or a relative pointer "N/path"
		// that goes up N levels first.
		defined := func(objects []map[string]any, ref string) bool {
			if path, ok := strings.CutPrefix(ref, "/"); ok {
				return lookup(doc, path)
			}
			if up, path, ok := strings.Cut(ref, "/"); ok {
				if n, err := strconv.Atoi(up); err == nil {
					return n < len(objects) && lookup(objects[len(objects)-1-n], path)
				}
			}
			return lookup(objects[len(objects)-1], ref)
		}
		var walk func(objects []map[string]any, at string)
		walk = func(objects []map[string]any, at string) {
			props, _ := deref(objects[len(objects)-1])["properties"].(map[string]any)
			for name, raw := range props {
				child, ok := raw.(map[string]any)
				if !ok || child["deprecated"] == true {
					continue
				}
				path := at + "/" + name
				if strings.HasSuffix(name, "_pct") {
					endpointControl := id == "evidencepack/endpoint-posture@v1" && name != "mdm_enrolled_pct"
					for _, keyword := range []string{"x-epack-numerator", "x-epack-denominator"} {
						ref, _ := child[keyword].(string)
						switch {
						case ref == "" && !endpointControl:
							t.Errorf("%s %s has no %s", id, path, keyword)
						case ref != "" && !defined(objects, ref):
							t.Errorf("%s %s: %s %q points to no property", id, path, keyword, ref)
						}
					}
					if ref, _ := child["x-epack-present"].(string); ref != "" && !defined(objects, ref) {
						t.Errorf("%s %s: x-epack-present %q points to no property", id, path, ref)
					}
				}
				below := append(append([]map[string]any(nil), objects...), child)
				walk(below, path)
				if items, ok := deref(child)["items"].(map[string]any); ok {
					walk(append(below, items), path+"/*")
				}
			}
		}
		walk([]map[string]any{doc}, "")
	}
}

// TestNormalizedSchemasLabelEveryField checks that every field of every
// normalized schema has an x-epack-label, and that each number and
// true-or-false value also has an x-epack-summary. A collector's normalized
// artifact then passes the kit's labels check with no annotations of its own.
// It also checks that each x-epack-goal fits its value.
func TestNormalizedSchemasLabelEveryField(t *testing.T) {
	for id := range normalizedFiles {
		var doc map[string]any
		if err := json.Unmarshal(NormalizedSchemaJSON(id), &doc); err != nil {
			t.Fatal(err)
		}
		defs, _ := doc["$defs"].(map[string]any)
		// view lists node and the schemas its $ref and its branches reach,
		// skipping the conditions of an if or a not.
		view := func(node map[string]any) []map[string]any {
			var out []map[string]any
			todo := []map[string]any{node}
			for len(todo) > 0 {
				n := todo[0]
				todo = todo[1:]
				out = append(out, n)
				if name, ok := strings.CutPrefix(fmt.Sprint(n["$ref"]), "#/$defs/"); ok {
					if target, ok := defs[name].(map[string]any); ok {
						todo = append(todo, target)
					}
				}
				for _, keyword := range []string{"oneOf", "anyOf", "allOf"} {
					branches, _ := n[keyword].([]any)
					for _, raw := range branches {
						b, _ := raw.(map[string]any)
						if b["$ref"] != nil || b["properties"] != nil || b["items"] != nil || b["type"] != nil {
							todo = append(todo, b)
						}
					}
				}
			}
			return out
		}
		first := func(v []map[string]any, key string) any {
			for _, n := range v {
				if val, ok := n[key]; ok {
					return val
				}
			}
			return nil
		}
		seen := map[uintptr]bool{}
		var walk func(node map[string]any, path string, row bool)
		walk = func(node map[string]any, path string, row bool) {
			if seen[reflect.ValueOf(node).Pointer()] {
				return
			}
			seen[reflect.ValueOf(node).Pointer()] = true
			v := view(node)
			if path != "" {
				var types []string
				for _, n := range v {
					switch tv := n["type"].(type) {
					case string:
						types = append(types, tv)
					case []any:
						for _, x := range tv {
							types = append(types, fmt.Sprint(x))
						}
					}
				}
				measured := slices.Contains(types, "number") || slices.Contains(types, "integer") || slices.Contains(types, "boolean")
				if label, _ := first(v, "x-epack-label").(string); label == "" && (!row || measured) {
					t.Errorf("%s %s has no x-epack-label", id, path)
				}
				if summary, _ := first(v, "x-epack-summary").(string); summary == "" && measured {
					t.Errorf("%s %s has no x-epack-summary", id, path)
				}
				rounding, _ := first(v, "x-epack-rounding").(string)
				boolean := slices.Contains(types, "boolean") && !slices.Contains(types, "number") && !slices.Contains(types, "integer")
				if problem := outputcheck.GoalProblem(outputcheck.Measured{Goal: first(v, "x-epack-goal"), Rounding: rounding, Boolean: boolean}); problem != "" {
					t.Errorf("%s %s: %s", id, path, problem)
				}
			}
			for _, n := range v {
				props, _ := n["properties"].(map[string]any)
				for name, raw := range props {
					if child, ok := raw.(map[string]any); ok {
						walk(child, path+"/"+name, false)
					}
				}
				if items, ok := n["items"].(map[string]any); ok {
					walk(items, path+"/*", true)
				}
				if values, ok := n["additionalProperties"].(map[string]any); ok {
					walk(values, path+"/{key}", false)
				}
			}
		}
		walk(doc, "", false)
	}
}

// TestNormalizedSchemasNameWhatReplacesEachDeprecatedField checks that every
// deprecated field of every normalized schema has an x-epack-replaced-by that
// names a normalized schema, and that a path it gives reaches a field there.
// Readers such as a profile editor show a test on a deprecated field what to
// test instead, from the schema alone.
func TestNormalizedSchemasNameWhatReplacesEachDeprecatedField(t *testing.T) {
	docs := map[string]map[string]any{}
	for id := range normalizedFiles {
		var doc map[string]any
		if err := json.Unmarshal(NormalizedSchemaJSON(id), &doc); err != nil {
			t.Fatal(err)
		}
		docs[id] = doc
	}
	deprecated := 0
	for id, doc := range docs {
		var walk func(node map[string]any, path string)
		walk = func(node map[string]any, path string) {
			if node["deprecated"] == true {
				deprecated++
				replaced, ok := node["x-epack-replaced-by"].(map[string]any)
				target, _ := replaced["schema"].(string)
				switch {
				case !ok:
					t.Errorf("%s %s is deprecated with no x-epack-replaced-by", id, path)
				case docs[target] == nil:
					t.Errorf("%s %s: x-epack-replaced-by names %q, which is not a normalized schema", id, path, target)
				default:
					if to, ok := replaced["path"].(string); ok && schemaAt(docs[target], to) == nil {
						t.Errorf("%s %s: x-epack-replaced-by path %s is not a field of %s", id, path, to, target)
					}
					if same, ok := replaced["same"]; ok && same != true {
						t.Errorf("%s %s: x-epack-replaced-by same is %v, want true or no same", id, path, same)
					}
					if replaced["same"] == true && replaced["path"] == nil {
						t.Errorf("%s %s: x-epack-replaced-by is the same value with no path", id, path)
					}
				}
			}
			props, _ := node["properties"].(map[string]any)
			for name, raw := range props {
				if child, ok := raw.(map[string]any); ok {
					walk(child, path+"."+name)
				}
			}
			if items, ok := node["items"].(map[string]any); ok {
				walk(items, path+"[*]")
			}
		}
		walk(doc, "$")
	}
	if deprecated == 0 {
		t.Fatal("no normalized schema has a deprecated field, so the test checks nothing")
	}
}

// schemaAt returns the schema of the field a simple JSONPath such as
// $.accounts[*].iam.user_count names in doc, following local $refs and the
// branches of allOf, anyOf and oneOf. It returns nil when no field matches.
func schemaAt(doc map[string]any, path string) map[string]any {
	defs, _ := doc["$defs"].(map[string]any)
	var resolve func(node map[string]any) []map[string]any
	resolve = func(node map[string]any) []map[string]any {
		out := []map[string]any{node}
		if name, ok := strings.CutPrefix(fmt.Sprint(node["$ref"]), "#/$defs/"); ok {
			if target, ok := defs[name].(map[string]any); ok {
				out = append(out, resolve(target)...)
			}
		}
		for _, keyword := range []string{"allOf", "anyOf", "oneOf"} {
			branches, _ := node[keyword].([]any)
			for _, raw := range branches {
				if b, ok := raw.(map[string]any); ok {
					out = append(out, resolve(b)...)
				}
			}
		}
		return out
	}
	rest, ok := strings.CutPrefix(path, "$")
	if !ok {
		return nil
	}
	current := []map[string]any{doc}
	for rest != "" {
		var next []map[string]any
		switch {
		case strings.HasPrefix(rest, "[*]"):
			rest = rest[3:]
			for _, node := range current {
				for _, n := range resolve(node) {
					if items, ok := n["items"].(map[string]any); ok {
						next = append(next, items)
					}
				}
			}
		case strings.HasPrefix(rest, "."):
			rest = rest[1:]
			end := strings.IndexAny(rest, ".[")
			if end < 0 {
				end = len(rest)
			}
			name := rest[:end]
			rest = rest[end:]
			for _, node := range current {
				for _, n := range resolve(node) {
					props, _ := n["properties"].(map[string]any)
					if child, ok := props[name].(map[string]any); ok {
						next = append(next, child)
					}
				}
			}
		default:
			return nil
		}
		if len(next) == 0 {
			return nil
		}
		current = next
	}
	return current[0]
}

func TestIdentityPercentagesCheckAgainstTheirCounts(t *testing.T) {
	s, err := outputcheck.Compile(NormalizedSchemaJSON("evidencepack/idp-posture@v1"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := outputcheck.Decode([]byte(`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "okta", "org_domain": "example.test",
	  "user_security": {"users_present": true, "user_count": 400, "mfa_user_count": 398, "mfa_coverage_pct": 100},
	  "policy": {"mfa_required_user_count": 398, "mfa_required_coverage_pct": 99}}`))
	if err != nil {
		t.Fatal(err)
	}
	got := outputcheck.Check(s, "a.json", doc, nil, "audit")
	if len(got) != 1 || got[0].Check != outputcheck.CheckRatios || got[0].Pointer != "/user_security/mfa_coverage_pct" {
		t.Errorf("398 of 400 should round down to 99: %+v", got)
	}
}

func TestIdentityCountsAreLeftOutAtTrust(t *testing.T) {
	s, err := outputcheck.Compile(NormalizedSchemaJSON("evidencepack/idp-posture@v1"))
	if err != nil {
		t.Fatal(err)
	}
	decode := func(raw string) any {
		doc, err := outputcheck.Decode([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		return doc
	}
	audit := decode(`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "entra", "org_domain": "example.test",
	  "app_security": {"authorized_third_party_apps_count": 12},
	  "privileged_access": {"privileged_users_present": true, "privileged_users_count": 4, "super_admin_count": 2,
	    "standing_privileged_users_present": true, "standing_privileged_users_count": 1, "privileged_mfa_coverage_pct": 100}}`)
	var above []string
	for _, f := range outputcheck.AboveLevel(s, "a.json", audit, "trust") {
		above = append(above, f.Pointer)
	}
	want := []string{"/app_security/authorized_third_party_apps_count", "/privileged_access/privileged_users_count",
		"/privileged_access/standing_privileged_users_count", "/privileged_access/super_admin_count"}
	if !reflect.DeepEqual(above, want) {
		t.Errorf("above trust = %q, want %q", above, want)
	}
	none := decode(`{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "provider": "entra", "org_domain": "example.test",
	  "privileged_access": {"privileged_users_present": false, "privileged_mfa_coverage_pct": 100, "privileged_phishing_resistant_pct": null}}`)
	got := outputcheck.Check(s, "a.json", none, nil, "trust")
	if len(got) != 1 || got[0].Check != outputcheck.CheckPopulation || got[0].Pointer != "/privileged_access/privileged_mfa_coverage_pct" {
		t.Errorf("a tenant with no privileged users at trust: %+v, want one population finding", got)
	}
}
