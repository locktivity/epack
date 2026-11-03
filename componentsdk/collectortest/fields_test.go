package collectortest

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/locktivity/epack/componentsdk"
)

// flowLogProbe counts the VPCs whose flow logs capture traffic. With
// ignoreStatus it counts every active flow log, as AWS's collector did. A
// flow log whose delivery failed then counts as capturing.
type flowLogProbe struct{ ignoreStatus bool }

func (p flowLogProbe) run(ctx componentsdk.CollectorContext) error {
	client := componentsdk.NewHTTPClient(ctx, componentsdk.HTTPOptions{})
	req, err := http.NewRequestWithContext(componentsdk.WithOperation(ctx.Context(), componentsdk.Operation{Name: "demo.flowlogs.list"}), http.MethodGet, demoHost+"/flow-logs", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	var page struct {
		FlowLogs []struct {
			VPC    string `json:"vpcId"`
			Status string `json:"deliverLogsStatus"`
			State  string `json:"flowLogStatus"`
		} `json:"flowLogs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return err
	}
	capturing := map[string]bool{}
	for _, f := range page.FlowLogs {
		if f.State != "ACTIVE" {
			continue
		}
		if p.ignoreStatus || f.Status == "SUCCESS" {
			capturing[f.VPC] = true
		}
	}
	return ctx.Emit([]componentsdk.CollectedArtifact{{Path: "artifacts/probe.json", Data: map[string]any{"capturing_vpcs": len(capturing)}}})
}

func flowLogSuite(p flowLogProbe) Suite {
	return Suite{
		Spec: componentsdk.CollectorSpec{Name: "probe"},
		Run:  p.run,
		Scenarios: []Scenario{{Name: "clean", Responses: []Response{{URL: demoHost + "/flow-logs",
			Body: `{"flowLogs":[{"vpcId":"vpc-1","deliverLogsStatus":"SUCCESS","flowLogStatus":"ACTIVE"},{"vpcId":"vpc-2","deliverLogsStatus":"SUCCESS","flowLogStatus":"ACTIVE"}]}`}}}},
		FieldSensitivity: true,
		SkipChecks:       []string{"faults", "levels", "determinism", "credentials", "sensitivity", "order"},
	}
}

func TestTheFieldsCheckCatchesAStateTheCollectorIgnores(t *testing.T) {
	if got := violationsOf(checkSuite(t, flowLogSuite(flowLogProbe{})), "fields"); len(got) != 0 {
		t.Errorf("a collector that reads both states: %+v", got)
	}
	report := checkSuite(t, flowLogSuite(flowLogProbe{ignoreStatus: true}))
	expectViolation(t, report, "fields", "changing /flowLogs/*/deliverLogsStatus in demo.flowlogs.list's answers changed no value")
	if got := violationsOf(report, "fields"); len(got) != 1 {
		t.Errorf("only the ignored state should be reported: %+v", got)
	}

	exempt := flowLogSuite(flowLogProbe{ignoreStatus: true})
	exempt.IgnoredFields = map[string][]string{"demo.flowlogs.list": {"/flowLogs/*/deliverLogsStatus"}}
	report = checkSuite(t, exempt)
	if got := violationsOf(report, "fields"); len(got) != 0 {
		t.Errorf("Suite.IgnoredFields exempts a field: %+v", got)
	}
	if len(report.IgnoredFields) != 1 || report.IgnoredFields[0] != "demo.flowlogs.list /flowLogs/*/deliverLogsStatus" {
		t.Errorf("the report still lists the exempt field: %q", report.IgnoredFields)
	}

	off := flowLogSuite(flowLogProbe{ignoreStatus: true})
	off.FieldSensitivity = false
	if got := violationsOf(checkSuite(t, off), "fields"); len(got) != 0 {
		t.Errorf("the check is off unless FieldSensitivity turns it on: %+v", got)
	}
}

func TestStateFieldsAndTheirChanges(t *testing.T) {
	var got []string
	for _, f := range stateFields(`{"value":[{"state":"enabled","grantControls":{"operator":"OR","builtInControls":["mfa"]},"conditions":{"users":{}}}],"name":"x"}`) {
		got = append(got, f.pattern)
	}
	want := map[string]bool{"/value/*/state": true, "/value/*/grantControls/operator": true, "/value/*/conditions": true}
	if len(got) != len(want) {
		t.Errorf("stateFields = %q", got)
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("unexpected state field %s", p)
		}
	}

	body, ok := changeJSONField(`{"value":[{"grantControls":{"operator":"OR"}},{"grantControls":{"operator":"AND"}}]}`, "/value/*/grantControls/operator")
	if !ok || body != `{"value":[{"grantControls":{"operator":"AND"}},{"grantControls":{"operator":"OR"}}]}` {
		t.Errorf("the two values of a field should swap: %s", body)
	}
	body, ok = changeJSONField(`{"items":[{"status":"active"},{"status":null}]}`, "/items/*/status")
	if !ok || body != `{"items":[{"status":"inactive"},{"status":null}]}` {
		t.Errorf("a null after a changed value should not undo the change: %s, %v", body, ok)
	}
	for in, want := range map[string]string{"ACTIVE": "INACTIVE", "Enabled": "Disabled", "on": "off", "SUCCESS": changedValue} {
		if got := otherValue(in, []string{in}); got != want {
			t.Errorf("otherValue(%q) = %q, want %q", in, got, want)
		}
	}
	xml, ok := changeXMLField(`<Subscriptions><member><Status>no-permission</Status></member><member><Status>active</Status></member></Subscriptions>`, "Status")
	if !ok || xml != `<Subscriptions><member><Status>active</Status></member><member><Status>no-permission</Status></member></Subscriptions>` {
		t.Errorf("changeXMLField = %s", xml)
	}
}
