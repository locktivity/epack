package collectortest

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk"
)

// bucketProbe reads one bucket's encryption. When access is denied, it
// records a gap with a fix. With nameInFix set, the fix names the bucket.
type bucketProbe struct{ nameInFix bool }

func (p bucketProbe) run(ctx componentsdk.CollectorContext) error {
	client := componentsdk.NewHTTPClient(ctx, componentsdk.HTTPOptions{})
	get := func(op, path string, out any) (*http.Response, error) {
		req, err := http.NewRequestWithContext(componentsdk.WithOperation(ctx.Context(), componentsdk.Operation{Name: op, Permission: "s3:GetEncryptionConfiguration"}), http.MethodGet, demoHost+path, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		if out != nil && resp.StatusCode == http.StatusOK {
			return resp, json.NewDecoder(resp.Body).Decode(out)
		}
		return resp, nil
	}
	var buckets []struct {
		BucketName string `json:"bucketName"`
	}
	if _, err := get("demo.buckets.list", "/buckets", &buckets); err != nil {
		return err
	}
	rec := componentsdk.Records(ctx)
	out := map[string]any{}
	for _, b := range buckets {
		resp, err := get("demo.encryption.get", "/buckets/"+b.BucketName+"/encryption", nil)
		if err != nil {
			return err
		}
		if resp.StatusCode == http.StatusForbidden {
			fix := "Allow s3:GetEncryptionConfiguration in the collector's IAM policy."
			if p.nameInFix {
				fix = "Allow s3:GetEncryptionConfiguration on " + b.BucketName + "."
			}
			rec.NotCollected(componentsdk.Location{Path: "artifacts/probe.json", Pointer: "/encrypted"},
				componentsdk.ResponseError(resp, componentsdk.CodeError(componentsdk.CodePermissionDenied, errFor(resp))),
				componentsdk.Fix(fix), componentsdk.Scope("bucket "+b.BucketName))
			out["encrypted"] = nil
		}
	}
	return ctx.Emit([]componentsdk.CollectedArtifact{{Path: "artifacts/probe.json", Data: out}})
}

func errFor(resp *http.Response) error { return &demoAPIError{status: resp.StatusCode} }

func bucketSuite(p bucketProbe) Suite {
	return Suite{
		Spec: componentsdk.CollectorSpec{Name: "probe"},
		Run:  p.run,
		Scenarios: []Scenario{{Name: "denied", Responses: []Response{
			{URL: demoHost + "/buckets", Body: `[{"bucketName":"northwind-logs"}]`},
			{URL: demoHost + "/buckets/northwind-logs/encryption", Status: http.StatusForbidden, Body: `{"code":"AccessDenied"}`},
		}}},
		SkipChecks: []string{"faults", "levels", "determinism", "credentials", "sensitivity", "order", "pages", "nulls"},
	}
}

func TestTheGuidanceCheckKeepsNamesOutOfAdvice(t *testing.T) {
	if got := violationsOf(checkSuite(t, bucketSuite(bucketProbe{})), "guidance"); len(got) != 0 {
		t.Errorf("advice in fixed wording, the bucket in its scope: %+v", got)
	}
	expectViolation(t, checkSuite(t, bucketSuite(bucketProbe{nameInFix: true})), "guidance",
		`the advice for the gap at artifacts/probe.json /encrypted names "northwind-logs" from the scenario`)
}

// roleProbe reads the role it signs in as. It then records a denied gap for
// the key's policy, with fix as the advice.
type roleProbe struct{ fix string }

func (p roleProbe) run(ctx componentsdk.CollectorContext) error {
	client := componentsdk.NewHTTPClient(ctx, componentsdk.HTTPOptions{})
	req, err := http.NewRequestWithContext(componentsdk.WithOperation(ctx.Context(), componentsdk.Operation{Name: "demo.identity.get"}), http.MethodGet, demoHost+"/identity", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	componentsdk.Records(ctx).NotCollectedCode(componentsdk.Location{Path: "artifacts/probe.json", Pointer: "/key_policy"},
		componentsdk.CodePermissionDenied, "denied", componentsdk.Fix(p.fix))
	return ctx.Emit([]componentsdk.CollectedArtifact{{Path: "artifacts/probe.json", Data: map[string]any{"key_policy": nil}}})
}

func TestTheGuidanceCheckFindsTheScrubbersFakesInAnyField(t *testing.T) {
	suite := func(fix string) Suite {
		return Suite{
			Spec: componentsdk.CollectorSpec{Name: "probe"},
			Run:  roleProbe{fix: fix}.run,
			Scenarios: []Scenario{{Name: "recorded", Responses: []Response{
				{URL: demoHost + "/identity", Body: `{"roleArn":"arn:aws:iam::123456789012:role/collector","principal":"00000000-0000-4000-8000-000000000001","contact":"user1@example.com"}`},
			}}},
			SkipChecks: []string{"faults", "levels", "determinism", "credentials", "sensitivity", "order", "pages", "nulls"},
		}
	}
	if got := violationsOf(checkSuite(t, suite("Allow kms:GetKeyPolicy in the collector's role.")), "guidance"); len(got) != 0 {
		t.Errorf("advice in fixed wording: %+v", got)
	}
	for _, named := range []string{"123456789012", "00000000-0000-4000-8000-000000000001", "user1@example.com"} {
		expectViolation(t, checkSuite(t, suite("Allow kms:GetKeyPolicy for "+named+".")), "guidance",
			`the advice for the gap at artifacts/probe.json /key_policy names "`+named+`" from the scenario`)
	}
}

func TestScrubbedFakes(t *testing.T) {
	got := scrubbedFakes(`arn:aws:iam::123456789012:role/x 123456789010 user2%40example.com jane@example.com 00000000-0000-4000-8000-000000000003 00000000-0000-0000-0000-000000000000`)
	want := []string{"user2%40example.com", "00000000-0000-4000-8000-000000000003", "123456789012"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("scrubbedFakes = %q, want %q", got, want)
	}
}

func TestIdentifierFields(t *testing.T) {
	for name, want := range map[string]bool{
		"bucketName": true, "userId": true, "email": true, "Arn": true, "displayName": true, "hostname": true,
		"regionName": false, "status": false, "roleName": false, "skuPartNumber": false, "permission": false, "eventType": false,
	} {
		if got := identifierField(name); got != want {
			t.Errorf("identifierField(%q) = %v, want %v", name, got, want)
		}
	}
}
