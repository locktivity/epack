package componentsdk

import (
	"errors"
	"strings"
	"testing"
)

func TestGuidanceReachesTheResultAtEachLevel(t *testing.T) {
	run := func(level Level) *CollectorResult {
		res := RunInProcess(CollectorSpec{Name: "probe"}, func(ctx CollectorContext) error {
			rec := Records(ctx)
			at := func(p string) Location { return Location{Path: "artifacts/probe.json", Pointer: p} }
			denied := CodeError(CodePermissionDenied, errors.New("AccessDenied"))
			rec.NotCollected(at("/saml"), denied, MissingPermission("iam:ListSAMLProviders"),
				Fix("Allow iam:ListSAMLProviders in the collector's IAM policy."), Scope("account 111122223333"),
				Warning("account 111122223333: ListSAMLProviders was refused"))
			rec.NotCollectedCode(at("/ca"), CodeNotLicensed, "Conditional Access needs Entra ID P1",
				Decide("Conditional Access needs Entra ID P1.",
					ChoiceOption{Label: "Add Entra ID P1", Consequence: "Microsoft charges per user. The next run collects these values."},
					ChoiceOption{Label: "Leave it off", Consequence: "These values stay Not collected."}))
			rec.Warn("usage report for acme.example is two days old", NoAction(), Scope("tenant acme.example"))
			rec.Warn("usage report for acme.example is two days old", NoAction(), Scope("tenant acme.example"))
			return ctx.Emit([]CollectedArtifact{{Path: "artifacts/probe.json", Data: map[string]any{"saml": nil, "ca": nil}}})
		}, InProcessOptions{Config: map[string]any{"level": string(level)}, OutputDir: t.TempDir()})
		if res.Result == nil {
			t.Fatalf("no result: %s", res.Stderr)
		}
		return res.Result
	}

	audit := run(LevelAudit)
	saml, ca := audit.Gaps[1], audit.Gaps[0]
	if saml.Pointer != "/saml" || saml.Fix != "Allow iam:ListSAMLProviders in the collector's IAM policy." || saml.Scope != "account 111122223333" || saml.Warning == "" {
		t.Errorf("audit saml gap = %+v", saml)
	}
	if ca.Choice == nil || len(ca.Choice.Options) != 2 || ca.Choice.Options[1].Consequence != "These values stay Not collected." {
		t.Errorf("audit choice = %+v", ca.Choice)
	}
	if len(audit.Warnings) != 1 || !audit.Warnings[0].NoAction || audit.Warnings[0].Message == "" || audit.Warnings[0].Scope == "" {
		t.Errorf("audit warnings = %+v, want one warning with its message and scope", audit.Warnings)
	}

	trust := run(LevelTrust)
	saml, ca = trust.Gaps[1], trust.Gaps[0]
	if saml.Fix == "" || saml.MissingPermission != "iam:ListSAMLProviders" || saml.Scope != "" || saml.Warning != "" {
		t.Errorf("trust saml gap = %+v, want the fix and permission without the scope or message", saml)
	}
	if ca.Choice == nil {
		t.Error("trust choice is nil, want the choice at every level")
	}
	if len(trust.Warnings) != 1 || !trust.Warnings[0].NoAction || trust.Warnings[0].Message != "" || trust.Warnings[0].Scope != "" {
		t.Errorf("trust warnings = %+v, want only the advice", trust.Warnings)
	}
}

func TestRecorderListsItsWarnings(t *testing.T) {
	rec := &Recorder{}
	rec.Warn("usage report is stale", NoAction())
	rec.Warn("usage report is stale", NoAction())
	got := rec.Warnings()
	if len(got) != 1 || got[0].Message != "usage report is stale" || !got[0].NoAction {
		t.Fatalf("warnings = %+v, want one warning with its advice", got)
	}
	got[0].Message = "changed"
	if rec.Warnings()[0].Message != "usage report is stale" {
		t.Error("Warnings returned the recorder's own list, not a copy")
	}
}

func TestAGapKeepsItsFirstAdvice(t *testing.T) {
	res := RunInProcess(CollectorSpec{Name: "probe"}, func(ctx CollectorContext) error {
		rec := Records(ctx)
		rec.NotCollectedCode(Location{Path: "artifacts/probe.json", Pointer: "/a"}, CodeVendorError, "x",
			Fix("Run the collector again."), NoAction())
		rec.NotCollectedCode(Location{Path: "artifacts/probe.json", Pointer: "/b"}, CodeNotLicensed, "x",
			Decide("Add the plan?", ChoiceOption{Label: "Add it", Consequence: "It costs money."}))
		rec.Warn("capped", NoAction(), Fix("Raise the cap."))
		return ctx.Emit([]CollectedArtifact{{Path: "artifacts/probe.json", Data: map[string]any{"a": nil, "b": nil}}})
	}, InProcessOptions{OutputDir: t.TempDir()})
	gaps := res.Result.Gaps
	if gaps[0].Fix != "Run the collector again." || gaps[0].NoAction {
		t.Errorf("gap /a guidance = %+v, want only the first advice", gaps[0].Guidance)
	}
	if gaps[1].Choice != nil {
		t.Errorf("gap /b choice = %+v, want nil for a choice with one option", gaps[1].Choice)
	}
	var findings []string
	for _, c := range res.Result.Checks {
		if c.Check == CheckGuidance {
			findings = append(findings, c.Pointer)
		}
	}
	if strings.Join(findings, ",") != "/a,/b," {
		t.Errorf("guidance findings at %q, want the two gaps and the warning", findings)
	}
}

func TestGuidanceTextIsCleanedAndRedacted(t *testing.T) {
	res := RunInProcess(CollectorSpec{Name: "probe"}, func(ctx CollectorContext) error {
		_ = ctx.Secret("API_TOKEN")
		Records(ctx).NotCollectedCode(Location{Path: "artifacts/probe.json", Pointer: "/a"}, CodeAuthFailed, "x",
			Fix("Replace the token tok-0123456789abcdef\nin the pipeline's secrets.   "))
		return ctx.Emit([]CollectedArtifact{{Path: "artifacts/probe.json", Data: map[string]any{"a": nil}}})
	}, InProcessOptions{OutputDir: t.TempDir(), Secrets: map[string]string{"API_TOKEN": "tok-0123456789abcdef"}})
	fix := res.Result.Gaps[0].Fix
	if strings.Contains(fix, "tok-0123456789abcdef") || strings.Contains(fix, "\n") || strings.HasSuffix(fix, " ") {
		t.Errorf("fix = %q, want one trimmed line with the secret redacted", fix)
	}
}

func TestTrustAdviceLeavesOutTheRunsIdentifiers(t *testing.T) {
	const fix = "Grant okta.users.read to app 0oa9xk2mq7 in northwind.okta.com for account 111122223333, as northwind-prod requires."
	run := func(level Level) Gap {
		res := RunInProcess(CollectorSpec{Name: "probe"}, func(ctx CollectorContext) error {
			rec := Records(ctx)
			rec.SignedInAs(Principal{Provider: "okta", Kind: "service_app", ID: "0oa9xk2mq7", TenantID: "northwind.okta.com"})
			rec.NotCollected(Location{Path: "artifacts/probe.json", Pointer: "/users"}, CodeError(CodePermissionDenied, errors.New("denied")),
				Fix(fix), Scope("account 111122223333"))
			return ctx.Emit([]CollectedArtifact{{Path: "artifacts/probe.json", Data: map[string]any{"users": nil}}})
		}, InProcessOptions{Config: map[string]any{"level": string(level), "org": "northwind-prod"}, OutputDir: t.TempDir()})
		if res.Result == nil || len(res.Result.Gaps) != 1 {
			t.Fatalf("result = %+v: %s", res.Result, res.Stderr)
		}
		return res.Result.Gaps[0]
	}
	trust := run(LevelTrust).Fix
	for _, id := range []string{"0oa9xk2mq7", "northwind.okta.com", "111122223333", "northwind-prod"} {
		if strings.Contains(trust, id) {
			t.Errorf("trust fix = %q, want %s left out, since the trust level leaves out what names the account", trust, id)
		}
	}
	if !strings.Contains(trust, "okta.users.read") {
		t.Errorf("trust fix = %q, want the permission kept", trust)
	}
	if audit := run(LevelAudit).Fix; audit != fix {
		t.Errorf("audit fix = %q, want it as written", audit)
	}
}
