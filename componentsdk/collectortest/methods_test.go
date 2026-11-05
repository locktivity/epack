package collectortest

import (
	"net/http"
	"testing"

	"github.com/locktivity/epack/componentsdk"
)

// methodsProbe reads its organization and writes a detailed and a
// normalized artifact. It records the normalized value as a copy when
// mirror is set, and its schema describes the detailed value when method is.
// fieldAudit marks the detailed value for the audit level, and wholeAudit
// the whole detailed artifact.
type methodsProbe struct{ mirror, method, fieldAudit, wholeAudit bool }

func (p methodsProbe) run(ctx componentsdk.CollectorContext) error {
	client := componentsdk.NewHTTPClient(ctx, componentsdk.HTTPOptions{})
	req, err := http.NewRequestWithContext(componentsdk.WithOperation(ctx.Context(), componentsdk.Operation{Name: "demo.org.get"}), http.MethodGet, demoHost+"/org", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if p.mirror {
		componentsdk.Records(ctx).Mirror(componentsdk.Location{Path: "artifacts/probe.json", Pointer: "/two_factor"},
			componentsdk.Location{Path: "artifacts/probe.access-posture.json", Pointer: "/sign_in/mfa_required"})
	}
	return ctx.Emit([]componentsdk.CollectedArtifact{
		{Path: "artifacts/probe.json", Data: map[string]any{"name": "probe", "two_factor": true}},
		{Path: "artifacts/probe.access-posture.json", Schema: "evidencepack/access-posture@v1", Data: map[string]any{
			"schema_version": "1.0.0", "collected_at": "2026-11-03T00:00:00Z", "provider": "github", "system_type": "code_host",
			"sign_in": map[string]any{"mfa_required": true},
		}},
	})
}

func methodSuite(p methodsProbe) Suite {
	method := ""
	if p.method {
		method = `, "x-epack-method": "Reads whether the organization requires two-factor authentication."`
	}
	if p.fieldAudit {
		method += `, "x-epack-level": "audit"`
	}
	whole := ""
	if p.wholeAudit {
		whole = `"x-epack-level": "audit", `
	}
	detailed := `{"type": "object", ` + whole + `"properties": {"name": {"type": "string"}, "two_factor": {"type": "boolean"` + method + `}}}`
	return Suite{
		Spec: componentsdk.CollectorSpec{Name: "probe", Schemas: map[string][]byte{"artifacts/probe.json": []byte(detailed)}},
		Run:  p.run,
		Scenarios: []Scenario{{Name: "clean", Responses: []Response{
			{URL: demoHost + "/org", Body: `{"name": "probe"}`},
		}}},
		SkipChecks: []string{"faults", "levels", "determinism", "credentials", "sensitivity", "order", "pages", "nulls"},
	}
}

func TestTheMethodsCheckFollowsCopiesToTheDetailedSchema(t *testing.T) {
	if got := violationsOf(checkSuite(t, methodSuite(methodsProbe{mirror: true, method: true})), "methods"); len(got) != 0 {
		t.Errorf("a copied value whose source has a method: %+v", got)
	}
	want := "artifacts/probe.access-posture.json has no x-epack-method for /sign_in/mfa_required"
	expectViolation(t, checkSuite(t, methodSuite(methodsProbe{mirror: false, method: true})), "methods", want)
	expectViolation(t, checkSuite(t, methodSuite(methodsProbe{mirror: true, method: false})), "methods", want)
}

func TestTheMethodsCheckCoversDetailedValuesATrustRunWrites(t *testing.T) {
	expectViolation(t, checkSuite(t, methodSuite(methodsProbe{mirror: true})), "methods",
		"artifacts/probe.json has no x-epack-method for /two_factor, which a trust run writes")
	for _, p := range []methodsProbe{{mirror: true, fieldAudit: true}, {mirror: true, wholeAudit: true}} {
		for _, v := range violationsOf(checkSuite(t, methodSuite(p)), "methods") {
			if v.Case == "artifacts/probe.json" {
				t.Errorf("%+v: a value marked for the audit level needs no method: %+v", p, v)
			}
		}
	}
}

func TestACopyFindsItsMethodWhenItsSourceIsNotWritten(t *testing.T) {
	res := checkSuite(t, methodSuite(methodsProbe{mirror: true, method: true, wholeAudit: true}))
	if got := violationsOf(res, "methods"); len(got) != 0 {
		t.Errorf("the trust run leaves out the detailed artifact, and its schema still gives the copy's method: %+v", got)
	}
	expectViolation(t, checkSuite(t, methodSuite(methodsProbe{mirror: true, wholeAudit: true})), "methods",
		"artifacts/probe.access-posture.json has no x-epack-method for /sign_in/mfa_required")
}

func TestAnyIndex(t *testing.T) {
	if got := anyIndex("/accounts/0/iam/mfa_pct"); got != "/accounts/*/iam/mfa_pct" {
		t.Errorf("anyIndex = %q", got)
	}
}
