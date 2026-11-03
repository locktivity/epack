package componentsdk

import (
	"reflect"
	"strings"
	"testing"
)

const methodsVocabulary = `{"name": "graph.registration_methods", "source": "https://learn.microsoft.com/graph/api/resources/userregistrationdetails",
  "fetched_at": "2026-11-03", "values": ["mobilePhone", "email", "fido2", "microsoftAuthenticatorPush", "softwareOneTimePasscode"]}`

func TestLoadVocabulary(t *testing.T) {
	v, err := LoadVocabulary([]byte(methodsVocabulary))
	if err != nil {
		t.Fatal(err)
	}
	if !v.Has("fido2") || v.Has("sms") || v.Name != "graph.registration_methods" {
		t.Errorf("vocabulary = %+v", v)
	}
	for _, bad := range []string{`{}`, `{"name": "x", "values": ["a"]}`, `{"name": "x", "source": "s"}`, `not json`} {
		if _, err := LoadVocabulary([]byte(bad)); err == nil {
			t.Errorf("LoadVocabulary(%s) should fail", bad)
		}
	}
}

func TestMustCatchesAConstantTheVendorNeverSends(t *testing.T) {
	v := MustLoadVocabulary([]byte(methodsVocabulary))
	if got := v.Must("mobilePhone", "fido2"); !reflect.DeepEqual(got, []string{"mobilePhone", "fido2"}) {
		t.Errorf("Must = %v", got)
	}
	defer func() {
		if p := recover(); p == nil || !strings.Contains(p.(string), `["sms"]`) {
			t.Errorf("Must should panic naming the missing value, got %v", p)
		}
	}()
	v.Must("mobilePhone", "sms")
}

func TestSeenRecordsValuesTheVocabularyLacks(t *testing.T) {
	v := MustLoadVocabulary([]byte(methodsVocabulary))
	run := func(level Level) InProcessResult {
		return RunInProcess(CollectorSpec{Name: "probe"}, func(ctx CollectorContext) error {
			for _, m := range []string{"mobilePhone", "passKeyDeviceBound", "fido2", "passKeyDeviceBound", "hardwareOneTimePasscode"} {
				v.Seen(ctx, m)
			}
			return ctx.Emit([]CollectedArtifact{{Path: "artifacts/probe.json", Data: map[string]any{"ok": true}}})
		}, InProcessOptions{Config: map[string]any{"level": string(level)}, OutputDir: t.TempDir()})
	}
	audit := run(LevelAudit)
	want := []Unrecognized{{Vocabulary: "graph.registration_methods", Count: 2, Values: []string{"hardwareOneTimePasscode", "passKeyDeviceBound"}}}
	if audit.Result == nil || !reflect.DeepEqual(audit.Result.Unrecognized, want) {
		t.Errorf("audit result lists %+v, want %+v", audit.Result.Unrecognized, want)
	}
	trust := run(LevelTrust)
	if trust.Result == nil || len(trust.Result.Unrecognized) != 1 || trust.Result.Unrecognized[0].Count != 2 || trust.Result.Unrecognized[0].Values != nil {
		t.Errorf("trust result lists %+v, want the count without the values", trust.Result.Unrecognized)
	}
}
