package collectortest

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/internal/outputcheck"
)

// apiTokenSchema is the schema of the answer to listing API tokens, in the
// shape of the ApiToken in Okta's OpenAPI document. It has no status field,
// since the list returns only active tokens.
const apiTokenSchema = `{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "array",
  "items": {"type": "object", "required": ["id", "name"], "properties": {
    "id": {"type": "string"}, "name": {"type": "string"}, "userId": {"type": "string"},
    "clientName": {"type": "string"}, "created": {"type": "string", "format": "date-time"},
    "network": {"type": "object", "properties": {"connection": {"enum": ["ANYWHERE", "ZONE"]}}}}}}`

// tokenProbe counts active API tokens by a status field, as Okta's collector
// did. The vendor never sends that field.
func tokenProbe(ctx componentsdk.CollectorContext) error {
	client := componentsdk.NewHTTPClient(ctx, componentsdk.HTTPOptions{})
	req, err := http.NewRequestWithContext(componentsdk.WithOperation(ctx.Context(), componentsdk.Operation{Name: "demo.tokens.list"}), http.MethodGet, demoHost+"/api-tokens", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	var tokens []struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		return err
	}
	active := 0
	for _, tok := range tokens {
		if tok.Status == "ACTIVE" {
			active++
		}
	}
	return ctx.Emit([]componentsdk.CollectedArtifact{{Path: "artifacts/probe.json", Data: map[string]any{"active_tokens": active}}})
}

func tokenSuite(body string) Suite {
	return Suite{
		Spec:            componentsdk.CollectorSpec{Name: "probe"},
		Run:             tokenProbe,
		Scenarios:       []Scenario{{Name: "clean", Responses: []Response{{URL: demoHost + "/api-tokens", Body: body}}}},
		ResponseSchemas: map[string][]byte{"demo.tokens.list": []byte(apiTokenSchema)},
		SkipChecks:      []string{"faults", "levels", "determinism", "credentials", "sensitivity", "order"},
	}
}

func TestTheResponsesCheckCatchesAFieldTheVendorNeverSends(t *testing.T) {
	expectViolation(t, checkSuite(t, tokenSuite(`[{"id":"00T1","name":"ci","status":"ACTIVE"}]`)), "responses",
		"the canned answer to demo.tokens.list at https://api.demo.test/api-tokens does not match the vendor's schema at /0/status: a field the vendor's schema does not define")
	if got := violationsOf(checkSuite(t, tokenSuite(`[{"id":"00T1","name":"ci","network":{"connection":"ANYWHERE"}}]`)), "responses"); len(got) != 0 {
		t.Errorf("an answer as the vendor sends it: %+v", got)
	}
	got := violationsOf(checkSuite(t, tokenSuite(`[{"id":"00T1","name":"ci","network":{"connection":"SOMEWHERE"}}]`)), "responses")
	if len(got) != 1 || !strings.Contains(got[0].Message, "/0/network/connection") {
		t.Errorf("a value the vendor's schema does not allow: %+v", got)
	}
	bad := tokenSuite(`[]`)
	bad.ResponseSchemas = map[string][]byte{"demo.tokens.list": []byte(`{"type": 7}`)}
	if _, err := Check(bad); err == nil {
		t.Error("Check should reject a response schema that does not compile")
	}
}

func TestStrictSchemaKeepsCompositionWorking(t *testing.T) {
	schema := `{"type": "object", "allOf": [
	  {"properties": {"id": {"type": "string"}}},
	  {"properties": {"name": {"type": "string"}, "meta": {"type": "object", "properties": {"etag": {"type": "string"}}}}}]}`
	compiled, err := compileResponseSchemas(map[string][]byte{"op": []byte(schema)})
	if err != nil {
		t.Fatal(err)
	}
	check := func(body string) int {
		doc, _ := decodeJSON(body)
		return len(validateFindings(compiled["op"], doc))
	}
	if n := check(`{"id": "1", "name": "x", "meta": {"etag": "e"}}`); n != 0 {
		t.Errorf("fields each branch defines: %d findings", n)
	}
	if n := check(`{"id": "1", "extra": true}`); n == 0 {
		t.Error("a field no branch defines should fail")
	}
	if n := check(`{"id": "1", "meta": {"etag": "e", "extra": 1}}`); n == 0 {
		t.Error("a nested field the schema does not define should fail")
	}
	open := `{"type": "object", "properties": {"id": {"type": "string"}}, "additionalProperties": true}`
	compiled, _ = compileResponseSchemas(map[string][]byte{"op": []byte(open)})
	if n := check(`{"id": "1", "extra": true}`); n != 0 {
		t.Error("a schema that allows other fields keeps allowing them")
	}
}

func TestStrictSchemaKeepsInheritanceThroughRefsWorking(t *testing.T) {
	schema := `{"$defs": {
	    "Base": {"type": "object", "properties": {"id": {"type": "string"}}},
	    "User": {"type": "object", "properties": {"login": {"type": "string"}}}},
	  "allOf": [{"$ref": "#/$defs/Base"}, {"properties": {"name": {"type": "string"}, "owner": {"$ref": "#/$defs/User"}}}]}`
	compiled, err := compileResponseSchemas(map[string][]byte{"op": []byte(schema)})
	if err != nil {
		t.Fatal(err)
	}
	check := func(body string) []outputcheck.Finding {
		doc, _ := decodeJSON(body)
		return validateFindings(compiled["op"], doc)
	}
	if got := check(`{"id": "1", "name": "x", "owner": {"login": "a"}}`); len(got) != 0 {
		t.Errorf("fields a referenced base and its sibling branch define: %+v", got)
	}
	if got := check(`{"id": "1", "extra": true}`); len(got) == 0 {
		t.Error("a field no branch defines should fail")
	}
	if got := check(`{"id": "1", "owner": {"login": "a", "extra": 1}}`); len(got) == 0 {
		t.Error("a field a referenced schema does not define should fail")
	}
}

// validateFindings validates doc against a compiled response schema.
func validateFindings(s *outputcheck.Schema, doc any) []outputcheck.Finding {
	return outputcheck.Validate(s, "", doc)
}
