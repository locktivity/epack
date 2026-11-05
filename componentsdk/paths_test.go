package componentsdk

import (
	"strings"
	"testing"
)

func TestArtifactPathAndRunPath(t *testing.T) {
	for _, tc := range []struct{ got, want string }{
		{ArtifactPath("okta", ""), "artifacts/okta.details.json"},
		{ArtifactPath("okta", "evidencepack/idp-posture@v1"), "artifacts/okta.idp-posture.json"},
		{ArtifactPath("tls", "evidencepack/tls@v1"), "artifacts/tls.tls.json"},
		{RunPath("okta", "okta-prod", "artifacts/okta.details.json"), "artifacts/okta-prod.details.json"},
		{RunPath("okta", "okta", "artifacts/okta.details.json"), "artifacts/okta.details.json"},
		{RunPath("okta", "okta-prod", "artifacts/okta-legacy.details.json"), "artifacts/okta-legacy.details.json"},
		{RunPath("okta", "okta-prod", "artifacts/github.details.json"), "artifacts/github.details.json"},
		{RunPath("okta", "okta-prod", "documents/okta.details.json"), "documents/okta.details.json"},
		{RunPath("documents", "documents-hr", "artifacts/documents/doc-1/policy.pdf"), "artifacts/documents-hr/doc-1/policy.pdf"},
		{RunPath("documents", "documents-hr", "artifacts/documents-old/doc-1/policy.pdf"), "artifacts/documents-old/doc-1/policy.pdf"},
	} {
		if tc.got != tc.want {
			t.Errorf("got %q, want %q", tc.got, tc.want)
		}
	}
}

func TestARunUnderAnotherNameWritesEveryPathUnderIt(t *testing.T) {
	details := ArtifactPath("okta", "")
	normalized := ArtifactPath("okta", "evidencepack/idp-posture@v1")
	spec := CollectorSpec{Name: "okta", Schemas: map[string][]byte{details: []byte(`{"type": "object", "properties": {"users": {"type": "integer"}}}`)}}
	var selected bool
	res := RunInProcess(spec, func(ctx CollectorContext) error {
		selected = Selected(ctx, Location{Path: details})
		rec := Records(ctx)
		rec.NotCollectedCode(Location{Path: details, Pointer: "/admins"}, CodePermissionDenied, "")
		rec.Mirror(Location{Path: details, Pointer: "/admins"}, Location{Path: normalized, Pointer: "/admins"})
		return ctx.Emit([]CollectedArtifact{
			{Path: details, Data: map[string]any{"users": "four"}},
			{Path: normalized, Schema: "evidencepack/idp-posture@v1", Data: map[string]any{"schema_version": "1.0.0", "provider": "okta"}},
		})
	}, InProcessOptions{Name: "okta-prod", Config: map[string]any{"collect": []any{"details", "idp-posture"}}})
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("exit %d: %s", res.ExitCode, res.Stderr)
	}
	if !selected {
		t.Error("Selected named the details file by the collector's path and got false")
	}
	for _, a := range res.Artifacts {
		if !strings.HasPrefix(a.Path, "artifacts/okta-prod.") {
			t.Errorf("artifact %s, want it under artifacts/okta-prod.", a.Path)
		}
	}
	paths := map[string]bool{}
	for _, g := range res.Result.Gaps {
		paths[g.Path] = true
	}
	if !paths["artifacts/okta-prod.details.json"] || !paths["artifacts/okta-prod.idp-posture.json"] || len(paths) != 2 {
		t.Errorf("gaps at %v, want the recorded gap and its mirror under artifacts/okta-prod.", paths)
	}
	found := false
	for _, f := range res.Result.Checks {
		if f.Check == CheckSchema && f.Path == "artifacts/okta-prod.details.json" && f.Pointer == "/users" {
			found = true
		}
	}
	if !found {
		t.Errorf("checks = %+v, want the schema keyed by the collector's path to check the renamed file", res.Result.Checks)
	}
}
