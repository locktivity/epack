package componentsdk

import (
	"context"
	"io"
	"net/http"
	"reflect"
	"testing"
	"time"
)

func TestStepsRecordTheirCallsTimesAndCounts(t *testing.T) {
	base := newScript().
		on("api.example.com/me", respond(200, "{}", nil)).
		on("api.example.com/users", respond(503, "busy", nil), respond(200, "[]", nil)).
		on("api.example.com/users/1/factors", respond(403, "{}", nil)).
		on("api.example.com/groups", respond(200, "[]", nil))
	clock := time.Date(2026, 10, 20, 6, 0, 0, 0, time.UTC)
	handler := func(ctx CollectorContext) error {
		client := NewHTTPClient(ctx, HTTPOptions{})
		call := func(c context.Context, op, path string) {
			req, _ := http.NewRequestWithContext(WithOperation(c, Operation{Name: op}), http.MethodGet, "https://api.example.com"+path, nil)
			resp, err := client.Do(req)
			if err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}
		call(ctx.Context(), "me.get", "/me")
		_ = Wait(ctx, 300*time.Millisecond)
		people, step := StartStep(ctx.Context(), "people", "People and sign-in methods")
		call(people, "users.list", "/users")
		call(people, "users.factors.list", "/users/1/factors")
		_ = Wait(ctx, 2*time.Second)
		step.End()
		step.End()
		groups, _ := StartStep(ctx.Context(), "groups", "")
		call(groups, "groups.list", "/groups")
		_ = Wait(ctx, time.Second)
		return ctx.Emit([]CollectedArtifact{{Data: map[string]any{}, Path: "artifacts/demo.json"}})
	}
	res := RunInProcess(CollectorSpec{Name: "demo"}, handler, InProcessOptions{
		Transport: base, Config: map[string]any{"level": "audit"},
		Clock: func() time.Time { return clock },
		Sleep: func(ctx context.Context, _ time.Duration) error { return ctx.Err() },
	})
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("exit = %d failure = %+v stderr = %s", res.ExitCode, res.Failure, res.Stderr)
	}
	want := []ResultStep{
		{Name: "people", Title: "People and sign-in methods", StartMS: 300, EndMS: 2300, Requests: 3, Calls: 2, Retries: 1, Failed: 2,
			Operations: []StepOperation{{Name: "users.list", Calls: 1}, {Name: "users.factors.list", Calls: 1}}},
		{Name: "groups", Title: "groups", StartMS: 2300, EndMS: 3300, Requests: 1, Calls: 1,
			Operations: []StepOperation{{Name: "groups.list", Calls: 1}}},
	}
	if !reflect.DeepEqual(res.Result.Steps, want) {
		t.Errorf("steps =\n%+v\nwant\n%+v", res.Result.Steps, want)
	}
	var steps []string
	for _, row := range res.Result.Calls.Requests {
		steps = append(steps, row.Step)
	}
	if !reflect.DeepEqual(steps, []string{"", "people", "people", "people", "groups"}) {
		t.Errorf("row steps = %q, want the sign-in outside every step", steps)
	}
	var statuses []string
	for _, p := range res.Progress {
		statuses = append(statuses, p.Message)
	}
	if !reflect.DeepEqual(statuses, []string{"People and sign-in methods", "groups"}) {
		t.Errorf("status lines = %q, want each step's title", statuses)
	}

	trust := RunInProcess(CollectorSpec{Name: "demo"}, handler, InProcessOptions{
		Transport: base, Clock: func() time.Time { return clock },
		Sleep: func(ctx context.Context, _ time.Duration) error { return ctx.Err() },
	})
	if len(trust.Result.Steps) != 2 || len(trust.Result.Calls.Requests) != 0 {
		t.Errorf("trust result = %+v, want the steps without the rows", trust.Result)
	}
}

func TestStepWithoutARunRecordsNothing(t *testing.T) {
	ctx, step := StartStep(context.Background(), "people", "People")
	step.End()
	if ctx != context.Background() {
		t.Error("StartStep with a context the SDK did not create should return it unchanged")
	}
	var nilStep *Step
	nilStep.End()
}

func TestStepOfAnotherRunIsIgnored(t *testing.T) {
	a := newRun(CollectorSpec{Name: "a"}, "a", "", nil, 1)
	b := newRun(CollectorSpec{Name: "b"}, "b", "", nil, 1)
	ctx, step := StartStep(withRun(context.Background(), a), "people", "People")
	defer step.End()
	if stepIn(ctx, b) != nil || stepIn(ctx, a) == nil {
		t.Error("a call should belong to a step only within the step's own run")
	}
}

func TestCollectorStepCarriesTheStepAndTheRun(t *testing.T) {
	base := newScript().
		on("api.example.com/users", respond(200, "[]", nil)).
		on("api.example.com/groups", respond(200, "[]", nil))
	handler := func(ctx CollectorContext) error {
		client := NewHTTPClient(ctx, HTTPOptions{})
		call := func(c CollectorContext, op, path string) {
			req, _ := http.NewRequestWithContext(WithOperation(c.Context(), Operation{Name: op}), http.MethodGet, "https://api.example.com"+path, nil)
			resp, err := client.Do(req)
			if err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}
		people, step := StartCollectorStep(ctx, "people", "People")
		call(people, "users.list", "/users")
		Records(people).NotCollectedCode(Location{Path: "artifacts/demo.json", Pointer: "/users"}, CodeNotLicensed, "")
		if _, ok := Staging(people); !ok || people.Level() != LevelAudit {
			t.Error("a step's context should keep its collector context's staging and level")
		}
		groups, inner := StartCollectorStep(people, "groups", "Groups")
		call(groups, "groups.list", "/groups")
		inner.End()
		step.End()
		return ctx.Emit([]CollectedArtifact{{Data: map[string]any{}, Path: "artifacts/demo.json"}})
	}
	res := RunInProcess(CollectorSpec{Name: "demo"}, handler, InProcessOptions{Transport: base, Config: map[string]any{"level": "audit"}})
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("exit = %d failure = %+v stderr = %s", res.ExitCode, res.Failure, res.Stderr)
	}
	var steps []string
	for _, row := range res.Result.Calls.Requests {
		steps = append(steps, row.Step)
	}
	if !reflect.DeepEqual(steps, []string{"people", "groups"}) {
		t.Errorf("row steps = %q, want each call in the step its context carries", steps)
	}
	if len(res.Result.Gaps) != 1 || res.Result.Gaps[0].Pointer != "/users" {
		t.Errorf("gaps = %+v, want the gap recorded through the step's context", res.Result.Gaps)
	}

	ctx, s := StartCollectorStep(baseOnlyContext{}, "people", "People")
	s.End()
	if ctx != (baseOnlyContext{}) {
		t.Error("StartCollectorStep with a context the SDK did not create should return it unchanged")
	}
}
