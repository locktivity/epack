package componentsdk

import (
	"errors"
	"reflect"
	"testing"
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
	if got := rec.Gaps()[4:]; !reflect.DeepEqual(got, want) {
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
