package remote_test

import (
	"context"
	"testing"

	"github.com/locktivity/epack/internal/remote"
)

func TestExecutor_RunProgressSendsTheEvent(t *testing.T) {
	script, dir := recordingAdapter(t, `{"ok":true,"type":"run.progress.result","request_id":"req-1"}`, 0)

	err := remote.NewExecutor(script, "test").RunProgress(context.Background(), &remote.RunProgressRequest{
		Remote: "locktivity",
		Target: remote.TargetConfig{Workspace: "acme", Environment: "prod"},
		Run:    remote.ProgressRun{ID: "20261014T150211Z-9f3a1c2b", StartedAt: "2026-10-14T15:02:11Z"},
		Event:  remote.ProgressEvent{At: "2026-10-14T15:02:40Z", Stage: "collect", Step: "okta", Index: 2, Total: 5, State: "started"},
	})
	if err != nil {
		t.Fatalf("RunProgress: %v", err)
	}

	command, request := recordedRequest(t, dir)
	if command != "run.progress" || request["type"] != "run.progress" || request["protocol_version"] != float64(remote.ProtocolVersion) || request["request_id"] == "" {
		t.Errorf("command = %q, request = %v", command, request)
	}
	run, _ := request["run"].(map[string]any)
	event, _ := request["event"].(map[string]any)
	if run["id"] != "20261014T150211Z-9f3a1c2b" || event["stage"] != "collect" || event["step"] != "okta" || event["index"] != float64(2) || event["total"] != float64(5) || event["state"] != "started" {
		t.Errorf("run = %v, event = %v", run, event)
	}
	if _, ok := event["note"]; ok {
		t.Error("an empty note must be left out")
	}
}

func TestExecutor_RunProgressFailsOnAnErrorResponse(t *testing.T) {
	script, _ := recordingAdapter(t, `{"ok":false,"type":"error","error":{"code":"forbidden","message":"no"}}`, 1)

	err := remote.NewExecutor(script, "test").RunProgress(context.Background(), &remote.RunProgressRequest{Remote: "locktivity"})
	if err == nil {
		t.Fatal("expected an error")
	}
}
