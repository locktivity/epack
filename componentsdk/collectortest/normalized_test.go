package collectortest

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/internal/outputcheck"
)

func TestTheNormalizedCheckReportsACopyOfANormalizedSchema(t *testing.T) {
	s := demoSuite(demo{})
	s.Spec.Schemas = map[string][]byte{"evidencepack/tls@v1": componentsdk.NormalizedSchemaJSON("evidencepack/tls@v1")}
	expectViolation(t, checkSuite(t, s), "normalized",
		"CollectorSpec.Schemas holds its own copy of the SDK's evidencepack/tls@v1 schema. A copy replaces the SDK's schema and falls behind it. Give the collector's x-epack-method sentences in CollectorSpec.Methods instead")

	s.Waivers = waiving("normalized")
	if got := violationsOf(checkSuite(t, s), "normalized"); len(got) != 0 {
		t.Errorf("a skipped check: %+v", got)
	}
}

func TestTheNormalizedCheckReportsMethodsItCannotPlace(t *testing.T) {
	s := demoSuite(demo{})
	s.Spec.Methods = map[string]map[string]string{
		"evidencepack/tls@v1":       {"/summary/reachable_pct": "Connects to each endpoint once.", "/summary/scanned_at": "Reads the clock."},
		"evidencepack/nope@v1":      {"/x": "Reads x."},
		"evidencepack/email-dns@v1": {"/summary/total_domains": "Counts the configured domains."},
	}
	report := checkSuite(t, s)
	expectViolation(t, report, "normalized", "CollectorSpec.Methods for evidencepack/tls@v1: /summary/scanned_at names no field of the schema")
	expectViolation(t, report, "normalized", "CollectorSpec.Methods names evidencepack/nope@v1, which is not one of the SDK's normalized types")
	if got := violationsOf(report, "normalized"); len(got) != 2 {
		t.Errorf("violations = %+v, want one for the unplaced method and one for the unknown type", got)
	}
}

func TestMethodsGoOnTheSDKsNormalizedSchema(t *testing.T) {
	spec := componentsdk.CollectorSpec{
		Schemas: map[string][]byte{"artifacts/demo.json": []byte(`{"type": "object"}`)},
		Methods: map[string]map[string]string{"evidencepack/tls@v1": {
			"/summary/reachable_pct":                   "Connects to each endpoint once.",
			"/endpoints/*/certificate/expires_in_days": "Reads the leaf certificate's notAfter date.",
		}},
	}
	schemas := spec.ArtifactSchemas()
	if string(schemas["artifacts/demo.json"]) != `{"type": "object"}` {
		t.Errorf("the collector's own schema = %s", schemas["artifacts/demo.json"])
	}
	sch, err := outputcheck.Compile(schemas["evidencepack/tls@v1"])
	if err != nil {
		t.Fatal(err)
	}
	for ptr, want := range map[string]string{
		"/summary/reachable_pct":                   "Connects to each endpoint once.",
		"/endpoints/0/certificate/expires_in_days": "Reads the leaf certificate's notAfter date.",
		"/summary/total_endpoints":                 "",
	} {
		if got := outputcheck.MethodAt(sch, ptr); got != want {
			t.Errorf("method at %s = %q, want %q", ptr, got, want)
		}
	}
	var got, want any
	if err := json.Unmarshal(schemas["evidencepack/tls@v1"], &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(componentsdk.NormalizedSchemaJSON("evidencepack/tls@v1"), &want); err != nil {
		t.Fatal(err)
	}
	if stripped := withoutMethods(got); !reflect.DeepEqual(stripped, want) {
		t.Error("apart from the methods, the composed schema differs from the SDK's")
	}
}

// withoutMethods returns doc with every x-epack-method removed.
func withoutMethods(doc any) any {
	switch n := doc.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, v := range n {
			if k != "x-epack-method" {
				out[k] = withoutMethods(v)
			}
		}
		return out
	case []any:
		out := make([]any, len(n))
		for i, v := range n {
			out[i] = withoutMethods(v)
		}
		return out
	}
	return doc
}
