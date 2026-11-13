package collectortest

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/locktivity/epack/componentsdk"
)

var methods = componentsdk.MustLoadVocabulary([]byte(`{"name": "demo.methods", "source": "https://docs.demo.test/methods",
  "values": ["totp", "webauthn", "sms"]}`))

// methodProbe counts users with a weak MFA method. It checks each method it
// reads against the vendor's vocabulary.
func methodProbe(ctx componentsdk.CollectorContext) error {
	client := componentsdk.NewHTTPClient(ctx, componentsdk.HTTPOptions{})
	req, err := http.NewRequestWithContext(componentsdk.WithOperation(ctx.Context(), componentsdk.Operation{Name: "demo.methods.list"}), http.MethodGet, demoHost+"/methods", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	var users []struct {
		Method string `json:"method"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return err
	}
	weak := 0
	for _, u := range users {
		methods.Seen(ctx, u.Method)
		if u.Method == methods.Must("sms")[0] {
			weak++
		}
	}
	return ctx.Emit([]componentsdk.CollectedArtifact{{Path: "artifacts/probe.json", Data: map[string]any{"weak": weak}}})
}

func TestTheVocabularyCheckCatchesAValueTheVendorAdded(t *testing.T) {
	suite := func(body string) Suite {
		return Suite{
			Spec:      componentsdk.CollectorSpec{Name: "probe"},
			Run:       methodProbe,
			Config:    map[string]any{"level": "audit"},
			Scenarios: []Scenario{{Name: "clean", Responses: []Response{{URL: demoHost + "/methods", Body: body}}}},
			Waivers:   waiving("faults", "levels", "determinism", "credentials", "sensitivity", "order"),
		}
	}
	if got := violationsOf(checkSuite(t, suite(`[{"method":"totp"},{"method":"sms"}]`)), "vocabulary"); len(got) != 0 {
		t.Errorf("known values: %+v", got)
	}
	expectViolation(t, checkSuite(t, suite(`[{"method":"totp"},{"method":"mobilePhone"}]`)), "vocabulary",
		`the run read 1 values that are not in the demo.methods vocabulary, such as "mobilePhone"`)
}
