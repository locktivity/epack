package componentsdk

import (
	"errors"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRecorderMirror(t *testing.T) {
	const detailed, normalized = "artifacts/demo.json", "artifacts/demo.idp-posture.json"
	at := func(path, pointer string) Location { return Location{Path: path, Pointer: pointer} }
	rec := &Recorder{}
	rec.NotCollected(at(detailed, "/policy"), &apiErr{status: 403, vendor: "E0000006"})
	rec.Partial(at(detailed, "/users/mfa_pct"), 7, errors.New("page 3 failed"))
	rec.NotCollectedCode(at(detailed, "/users"), CodeNotLicensed, "no user report")
	rec.NotCollectedCode(Location{Schema: "evidencepack/idp-posture@v1", Pointer: "/sso"}, CodeTimeout, "slow")

	rec.Mirror(at(detailed, "/policy/mfa_required"), at(normalized, "/policy/mfa_required"))
	rec.Mirror(at(detailed, "/users/mfa_pct"), at(normalized, "/mfa_coverage_pct"))
	rec.Mirror(at(detailed, "/users/count"), at(normalized, "/users_total"))
	rec.Mirror(at(detailed, "/score"), at(normalized, "/score"))
	rec.Mirror(at(detailed, "/policyx"), at(normalized, "/policyx"))
	rec.Mirror(at(detailed, "/sso"), at(normalized, "/sso"))
	rec.Mirror(Location{Schema: "evidencepack/idp-posture@v1", Pointer: "/sso"}, at(normalized, "/sso_enabled"))
	rec.Mirror(at(detailed, "/users/count"), at(normalized, "/mfa_coverage_pct"))

	want := []Gap{
		{Path: normalized, Pointer: "/policy/mfa_required", Status: GapNotCollected, Code: CodePermissionDenied, Owner: OwnerCustomer, VendorCode: "E0000006", Detail: "status 403"},
		{Path: normalized, Pointer: "/mfa_coverage_pct", Status: GapPartial, Code: CodeInternal, Owner: OwnerPublisher, Unmeasured: 7, Detail: "page 3 failed"},
		{Path: normalized, Pointer: "/users_total", Status: GapNotCollected, Code: CodeNotLicensed, Owner: OwnerNobody, Detail: "no user report"},
		{Path: normalized, Pointer: "/sso_enabled", Status: GapNotCollected, Code: CodeTimeout, Owner: OwnerVendorOrRunner, Detail: "slow"},
	}
	got := rec.Gaps()[4:]
	for i := range got {
		if got[i].Source != rec.Gaps()[[]int{0, 1, 2, 3}[i]].Source {
			t.Errorf("mirrored gap %d has source %q, want the source of the gap it copies", i, got[i].Source)
		}
		got[i].Source = ""
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("mirrored gaps =\n%+v\nwant\n%+v", got, want)
	}

	rec.Mirror(at(detailed, "/users"), at(detailed, "/users/mfa_pct"))
	if got := rec.Gaps()[1]; got.Status != GapPartial || len(rec.Gaps()) != 8 {
		t.Errorf("mirroring onto a location with a gap replaced it: %+v", rec.Gaps())
	}
}

func TestRecorderMirrorPrefersTheNearestGap(t *testing.T) {
	rec := &Recorder{}
	rec.NotCollectedCode(Location{Path: "a.json"}, CodeVendorError, "whole artifact")
	rec.NotCollectedCode(Location{Path: "a.json", Pointer: "/x/y"}, CodeTimeout, "nearest")
	rec.NotCollectedCode(Location{Path: "a.json", Pointer: "/x"}, CodeRateLimited, "outer")
	rec.Mirror(Location{Path: "a.json", Pointer: "/x/y/z"}, Location{Path: "b.json", Pointer: "/z"})
	rec.Mirror(Location{Path: "a.json", Pointer: "/w"}, Location{Path: "b.json", Pointer: "/w"})
	gaps := rec.Gaps()
	if len(gaps) != 5 || gaps[3].Code != CodeTimeout || gaps[4].Code != CodeVendorError {
		t.Errorf("gaps = %+v, want /z from the gap at /x/y and /w from the whole artifact's", gaps)
	}
}

// recordThrough records a gap through a helper, as a collector's gap log does.
func recordThrough(rec *Recorder, at Location, err error) {
	rec.Helper()
	rec.NotCollected(at, err)
}

func TestGapSourceNamesTheCollectorsLine(t *testing.T) {
	rec := &Recorder{}
	_, _, line, _ := runtime.Caller(0)
	rec.NotCollected(Location{Path: "a.json", Pointer: "/direct"}, errors.New("x"))
	recordThrough(rec, Location{Path: "a.json", Pointer: "/helped"}, errors.New("x"))
	gaps := rec.Gaps()
	if want := "componentsdk/records_test.go:" + strconv.Itoa(line+1); gaps[0].Source != want {
		t.Errorf("source = %q, want %q, the line that recorded the gap, relative to the module root", gaps[0].Source, want)
	}
	if want := "componentsdk/records_test.go:" + strconv.Itoa(line+2); gaps[1].Source != want {
		t.Errorf("source = %q, want %q, the line that called the helper", gaps[1].Source, want)
	}
}

func TestFunctionPackage(t *testing.T) {
	for fn, want := range map[string]string{
		"github.com/locktivity/epack-collector-okta/internal/collector.(*Collector).collectSystemLog.func1": "github.com/locktivity/epack-collector-okta/internal/collector",
		"github.com/locktivity/epack-collector-okta/internal/collector.list[...]":                           "github.com/locktivity/epack-collector-okta/internal/collector",
		"gopkg.in/yaml%2ev3.Unmarshal": "gopkg.in/yaml.v3",
		"main.main":                    "main",
		"nodot":                        "",
	} {
		if got := functionPackage(fn); got != want {
			t.Errorf("functionPackage(%q) = %q, want %q", fn, got, want)
		}
	}
}

func TestGapOptions(t *testing.T) {
	rec := &Recorder{}
	denied := &apiErr{status: 403}
	rec.NotCollected(Location{Path: "a.json", Pointer: "/logs"}, denied, MissingPermission("okta.logs.read"), Warning("system log: grant okta.logs.read"))
	rec.NotCollected(Location{Path: "a.json", Pointer: "/apps"}, &apiErr{status: 500}, MissingPermission("okta.apps.read"))
	rec.NotCollected(Location{Path: "a.json", Pointer: "/roles"}, denied, MissingPermission("read roles for jane"))
	rec.NotCollectedCode(Location{Path: "a.json", Pointer: "/zones"}, CodeNotLicensed, "no zones", Warning("the plan lacks network zones"))
	gaps := rec.Gaps()
	if gaps[0].MissingPermission != "okta.logs.read" || gaps[0].Warning != "system log: grant okta.logs.read" {
		t.Errorf("denied gap = %+v", gaps[0])
	}
	if gaps[1].MissingPermission != "" || gaps[2].MissingPermission != "" {
		t.Errorf("gaps = %+v, %+v; want a permission only on a permission_denied gap, and never one with spaces", gaps[1], gaps[2])
	}
	if gaps[3].Warning == "" || gaps[3].Operation != "" || gaps[3].Call != 0 {
		t.Errorf("chosen-code gap = %+v, want its warning and no call", gaps[3])
	}
}

func TestBuildResultGatesGapWarningsAndKeepsSignInDetails(t *testing.T) {
	r := newRun(CollectorSpec{Name: "demo"}, "demo", "", nil, 1)
	r.secrets.add("s3cr3t-token-value")
	r.records.NotCollected(Location{Path: "artifacts/demo.json", Pointer: "/logs"}, &apiErr{status: 403},
		MissingPermission("okta.logs.read"), Warning("user 00u1 (s3cr3t-token-value) cannot read the log"))
	r.records.SignedInAs(Principal{Provider: "okta", Kind: "service_app", AuthMethod: AuthPrivateKeyJWT, ReadOnly: true,
		RequestedScopes: []string{"okta.users.read", "okta.logs.read"}, Scopes: []string{"okta.users.read"}, ID: "0oa1"})
	artifacts := []CollectedArtifact{{Data: map[string]any{}, Path: "artifacts/demo.json"}}
	build := func(level Level) CollectorResult {
		res, err := buildResult(resultInput{run: r, level: level, artifacts: artifacts, getenv: func(string) string { return "" }, finished: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	trust, audit := build(LevelTrust), build(LevelAudit)
	if g := trust.Gaps[0]; g.Warning != "" || g.MissingPermission != "okta.logs.read" || g.Source == "" {
		t.Errorf("trust gap = %+v, want no warning but the permission and source", g)
	}
	if g := audit.Gaps[0]; strings.Contains(g.Warning, "s3cr3t") || !strings.Contains(g.Warning, "cannot read the log") {
		t.Errorf("audit warning = %q, want it redacted", g.Warning)
	}
	p := trust.SignedInAs
	if p.AuthMethod != AuthPrivateKeyJWT || !p.ReadOnly || strings.Join(p.RequestedScopes, ",") != "okta.logs.read,okta.users.read" || p.ID != "" {
		t.Errorf("trust sign-in = %+v, want the method, sorted requested scopes, and read_only at every level", p)
	}
	if audit.Calls.ProblemRequestsDropped == nil || *audit.Calls.ProblemRequestsDropped != 0 || trust.Calls.ProblemRequestsDropped != nil {
		t.Errorf("problem_requests_dropped = %v at audit and %v at trust, want 0 wherever the rows are", audit.Calls.ProblemRequestsDropped, trust.Calls.ProblemRequestsDropped)
	}
}

func TestMirrorListsEveryCopy(t *testing.T) {
	rec := &Recorder{}
	from, to := Location{Path: "a.json", Pointer: "/x"}, Location{Path: "b.json", Pointer: "/y"}
	rec.Mirror(from, to)
	rec.Mirror(from, to)
	if got := rec.mirrored(); len(got) != 1 || got[0] != (Mirrored{From: from, To: to}) || len(rec.Gaps()) != 0 {
		t.Errorf("mirrors = %+v, want the copy listed once although no gap covers it", got)
	}
}
