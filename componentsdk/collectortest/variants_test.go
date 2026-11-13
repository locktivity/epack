package collectortest

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk"
)

// trustProbe reads a role from the regional endpoint its config sets. It
// reports whether the role's trust policy has another account as a
// principal, as AWS's collector does.
type trustProbe struct {
	hardcoded bool // tells another account by the arn:aws:iam:: prefix, as AWS's collector did
	fixedHost bool // calls the endpoint for us-east-1 whatever the config says
}

func (p trustProbe) run(ctx componentsdk.CollectorContext) error {
	region, _ := ctx.Config()["region"].(string)
	host := "iam." + region + ".cloud.test"
	if p.fixedHost {
		host = "iam.us-east-1.cloud.test"
	}
	client := componentsdk.NewHTTPClient(ctx, componentsdk.HTTPOptions{})
	req, err := http.NewRequestWithContext(componentsdk.WithOperation(ctx.Context(), componentsdk.Operation{Name: "probe.role.get"}), http.MethodGet, "https://"+host+"/role", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	var role struct {
		ARN       string `json:"arn"`
		Principal string `json:"principal"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&role); err != nil {
		return err
	}
	own := strings.Split(role.ARN, ":")[4]
	var external bool
	if p.hardcoded {
		external = strings.HasPrefix(role.Principal, "arn:aws:iam::") && !strings.HasPrefix(role.Principal, "arn:aws:iam::"+own+":")
	} else {
		parts := strings.SplitN(role.Principal, ":", 6)
		external = len(parts) == 6 && parts[0] == "arn" && parts[2] == "iam" && parts[4] != own
	}
	return ctx.Emit([]componentsdk.CollectedArtifact{{Path: "artifacts/probe.json",
		Data: map[string]any{"role_arn": role.ARN, "region": region, "external_trust": external}}})
}

func trustSuite(p trustProbe) Suite {
	return Suite{
		Spec:   componentsdk.CollectorSpec{Name: "probe"},
		Run:    p.run,
		Config: map[string]any{"region": "us-east-1"},
		Scenarios: []Scenario{{Name: "clean", Responses: []Response{
			{URL: "https://iam.us-east-1.cloud.test/role", Body: `{"arn":"arn:aws:iam::111122223333:role/audit","principal":"arn:aws:iam::444455556666:root"}`},
		}}},
		Variants: []Variant{{Name: "aws-us-gov", Replace: []string{"arn:aws:", "arn:aws-us-gov:", "us-east-1", "us-gov-west-1"}}},
		Waivers:  waiving("faults", "levels", "determinism", "credentials", "sensitivity"),
	}
}

func TestTheVariantsCheckCatchesAHardCodedPartition(t *testing.T) {
	if got := violationsOf(checkSuite(t, trustSuite(trustProbe{})), "variants"); len(got) != 0 {
		t.Errorf("a collector that reads the partition from the ARN follows the variant: %+v", got)
	}
	expectViolation(t, checkSuite(t, trustSuite(trustProbe{hardcoded: true})), "variants",
		"artifacts/probe.json /external_trust from true to false")
	expectViolation(t, checkSuite(t, trustSuite(trustProbe{fixedHost: true})), "variants",
		"no canned response for GET https://iam.us-east-1.cloud.test/role")
}

func TestCheckRejectsAVariantItCannotRun(t *testing.T) {
	for _, v := range []Variant{
		{Replace: []string{"a", "b"}},
		{Name: "odd", Replace: []string{"a"}},
		{Name: "empty", Replace: []string{"", "b"}},
	} {
		s := trustSuite(trustProbe{})
		s.Variants = []Variant{v}
		if _, err := Check(s); err == nil {
			t.Errorf("Check accepted %+v", v)
		}
	}
}
