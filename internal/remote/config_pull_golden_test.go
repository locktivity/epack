package remote

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// The adapter's tests decode the same files, so a field renamed or dropped
// on either side of config.pull fails both.
func readGolden(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "config_pull", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func assertSameJSON(t *testing.T, got, want []byte) {
	t.Helper()
	var gotValue, wantValue any
	if err := json.Unmarshal(got, &gotValue); err != nil {
		t.Fatalf("decoding %s: %v", got, err)
	}
	if err := json.Unmarshal(want, &wantValue); err != nil {
		t.Fatalf("decoding the golden file: %v", err)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Errorf("JSON differs from the golden file:\n got %s\nwant %s", got, want)
	}
}

func TestConfigPullGolden_RequestIsWhatEpackSends(t *testing.T) {
	request := ConfigPullRequest{
		Type:            TypeConfigPull,
		ProtocolVersion: ProtocolVersion,
		RequestID:       "req_1",
		Remote:          "locktivity",
		Config: ConfigPullTarget{
			Name:    "northwind-production",
			Purpose: ConfigPurposeRun,
			Fallback: &ConfigFallback{Revision: 3, Missing: []Requirement{
				{Kind: RequirementVariable, Name: "SENTRY_AUTH_TOKEN"},
				{Kind: RequirementPublisher, Name: "acme"},
			}},
		},
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	assertSameJSON(t, encoded, readGolden(t, "request.json"))
}

func TestConfigPullGolden_ResultDecodesWithoutLosingAField(t *testing.T) {
	golden := readGolden(t, "answer.json")
	var resp ConfigPullResponse
	if err := json.Unmarshal(golden, &resp); err != nil {
		t.Fatal(err)
	}
	cfg := resp.Config
	if cfg.Revision != 2 || cfg.ChangesSince != 1 || cfg.Requirements == nil || cfg.Requirements.Epack != "v0.5.0" || cfg.Requirements.Hints[0].URL == "" {
		t.Fatalf("decoded %+v", cfg)
	}
	encoded, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	assertSameJSON(t, encoded, golden)
}

func TestConfigPullGolden_NoFallbackIsAnAnswer(t *testing.T) {
	var resp ConfigPullResponse
	if err := json.Unmarshal(readGolden(t, "no_fallback.json"), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.OK || resp.NoFallback == nil || resp.NoFallback.Reason == "" {
		t.Fatalf("decoded %+v, want the remote's reason", resp)
	}
}
