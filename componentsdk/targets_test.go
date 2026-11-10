package componentsdk

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

const targetsPath = "artifacts/demo.json"

func runTargets(t *testing.T, level, schema string, data map[string]any, declare func(*Recorder)) InProcessResult {
	t.Helper()
	spec := CollectorSpec{Name: "demo", Version: "0.1.0"}
	if schema != "" {
		spec.Schemas = map[string][]byte{targetsPath: []byte(schema)}
	}
	res := RunInProcess(spec, func(ctx CollectorContext) error {
		declare(Records(ctx))
		return ctx.Emit([]CollectedArtifact{{Data: data, Path: targetsPath}})
	}, InProcessOptions{Config: map[string]any{"level": level}, RunID: "r1", Seed: 1})
	if res.Panic != "" || res.Result == nil {
		t.Fatalf("exit = %d failure = %+v panic = %s stderr = %s", res.ExitCode, res.Failure, res.Panic, res.Stderr)
	}
	return res
}

func targetChecks(res InProcessResult) []CheckFinding {
	var out []CheckFinding
	for _, f := range res.Result.Checks {
		if f.Check == CheckTargets {
			out = append(out, f)
		}
	}
	return out
}

func endpoints(reachable ...bool) map[string]any {
	var list []any
	for i, r := range reachable {
		list = append(list, map[string]any{"host": []string{"a.example.com", "b.example.com", "c.example.com"}[i], "port": 443, "reachable": r})
	}
	return map[string]any{"endpoints": list}
}

func TestTargetsReadsAConfiguredListWithHostAndPort(t *testing.T) {
	declare := func(r *Recorder) {
		r.Targets(TargetEndpoint, Location{Path: targetsPath, Pointer: "/endpoints"}, "/host", "/port").
			ChosenBy(ChosenByConfig, "endpoints").Reached("/reachable")
	}
	res := runTargets(t, "audit", "", endpoints(true, true), declare)
	got := res.Result.Targets
	if len(got) != 1 {
		t.Fatalf("targets = %+v", got)
	}
	d := got[0]
	if d.Kind != TargetEndpoint || d.ChosenBy != ChosenByConfig || d.ConfigKey != "endpoints" || d.At == nil || d.At.Path != targetsPath ||
		!slices.Equal(d.Name, []string{"/host", "/port"}) || d.Reached != "/reachable" {
		t.Errorf("declaration = %+v", d)
	}
	if d.Count == nil || *d.Count != 2 || d.Complete == nil || !*d.Complete {
		t.Errorf("count = %v complete = %v, want 2 and true", d.Count, d.Complete)
	}

	unreached := runTargets(t, "trust", "", endpoints(true, false), declare).Result.Targets[0]
	if unreached.Complete == nil || *unreached.Complete {
		t.Errorf("an endpoint that didn't answer leaves the set incomplete, got %v", unreached.Complete)
	}
	if unreached.Count != nil {
		t.Errorf("a trust run writes no count, got %d", *unreached.Count)
	}
}

func TestTargetsAreIncompleteWhenAGapCoversOne(t *testing.T) {
	res := runTargets(t, "audit", "", endpoints(true, true), func(r *Recorder) {
		r.Targets(TargetEndpoint, Location{Path: targetsPath, Pointer: "/endpoints"}, "/host").ChosenBy(ChosenByConfig, "endpoints")
		r.NotCollected(Location{Path: targetsPath, Pointer: "/endpoints/1/certificate"}, errors.New("handshake timed out"))
	})
	if d := res.Result.Targets[0]; d.Complete == nil || *d.Complete {
		t.Errorf("complete = %v, want false with a gap inside a target", d.Complete)
	}

	leftOut := runTargets(t, "audit", "", endpoints(true), func(r *Recorder) {
		r.Targets(TargetEndpoint, Location{Path: targetsPath, Pointer: "/endpoints"}, "/host").ChosenBy(ChosenByConfig, "endpoints")
		r.NotCollectedCode(Location{Path: targetsPath, Pointer: "/endpoints/0/certificate"}, CodeNotRead, "not read")
	})
	if d := leftOut.Result.Targets[0]; d.Complete == nil || !*d.Complete {
		t.Errorf("a value the collector doesn't read leaves the set complete, got %v", d.Complete)
	}
}

func TestTargetsTheRunCouldNotReadAreIncomplete(t *testing.T) {
	res := runTargets(t, "audit", "", map[string]any{}, func(r *Recorder) {
		r.Targets(TargetOrganization, Location{Path: targetsPath, Pointer: "/org_id"}).ChosenBy(ChosenByDiscovery, "")
		r.Targets(TargetEnvironment, Location{Path: targetsPath, Pointer: "/environments/inventory"}, "/name").ChosenBy(ChosenByDiscovery, "")
		r.NotCollected(Location{Path: targetsPath, Pointer: "/org_id"}, errors.New("organization list refused"))
		r.NotCollected(Location{Path: targetsPath, Pointer: "/environments"}, errors.New("environments list refused"))
	})
	if findings := targetChecks(res); len(findings) != 0 {
		t.Errorf("a value a gap explains is not a finding, got %+v", findings)
	}
	for _, d := range res.Result.Targets {
		if d.At == nil || d.Count == nil || *d.Count != 0 || d.Complete == nil || *d.Complete {
			t.Errorf("%s: at = %+v count = %v complete = %v, want the location kept with no targets and an incomplete set", d.Kind, d.At, d.Count, d.Complete)
		}
	}

	trust := runTargets(t, "trust", gatedSchema, map[string]any{}, func(r *Recorder) {
		r.Targets(TargetRepository, Location{Path: targetsPath, Pointer: "/repositories"}, "/name").ChosenBy(ChosenByDiscovery, "")
		r.NotCollected(Location{Path: targetsPath, Pointer: "/repositories"}, errors.New("list refused"))
	})
	if d := trust.Result.Targets[0]; d.At != nil || d.Complete != nil || len(targetChecks(trust)) != 0 {
		t.Errorf("a trust run drops an audit location a gap covers like any other, got %+v", d)
	}
}

func TestTargetsLeftOutOnPurposeOrCutShort(t *testing.T) {
	res := runTargets(t, "audit", "", map[string]any{"scope": map[string]any{"included": 3}, "repositories": []any{map[string]any{"name": "web"}}}, func(r *Recorder) {
		r.Targets(TargetEnvironment, Location{Path: targetsPath, Pointer: "/environments"}, "/name").ChosenBy(ChosenByDiscovery, "")
		r.NotCollectedCode(Location{Path: targetsPath, Pointer: "/environments"}, CodeNotRead, "the collector doesn't read environments")
		r.Targets(TargetRepository, Location{Path: targetsPath, Pointer: "/repositories"}, "/name").ChosenBy(ChosenByDiscovery, "").
			Assessed(Location{Path: targetsPath, Pointer: "/scope/included"})
	})
	if findings := targetChecks(res); len(findings) != 0 {
		t.Errorf("a list left out on purpose is not a finding, got %+v", findings)
	}
	environments, repositories := res.Result.Targets[0], res.Result.Targets[1]
	if environments.At != nil || environments.Complete != nil {
		t.Errorf("a list left out on purpose is dropped, got %+v", environments)
	}
	if repositories.Count == nil || *repositories.Count != 1 || repositories.Complete == nil || *repositories.Complete {
		t.Errorf("a list holding fewer targets than were assessed is incomplete, got count %v complete %v", repositories.Count, repositories.Complete)
	}
}

func TestTargetsReadOneNestedLevel(t *testing.T) {
	data := map[string]any{"accounts": []any{
		map[string]any{"account_id": "111", "regions": []any{"us-east-1", "eu-west-1"}},
		map[string]any{"account_id": "222", "regions": nil},
	}}
	res := runTargets(t, "audit", "", data, func(r *Recorder) {
		r.Targets(TargetRegion, Location{Path: targetsPath, Pointer: "/accounts/*/regions"}).ChosenBy(ChosenByDiscovery, "")
		r.NotCollected(Location{Path: targetsPath, Pointer: "/accounts/1/regions"}, errors.New("access denied"))
	})
	d := res.Result.Targets[0]
	if d.Count == nil || *d.Count != 2 || d.Complete == nil || *d.Complete {
		t.Errorf("count = %v complete = %v, want the two regions read and an incomplete set", d.Count, d.Complete)
	}

	elsewhere := runTargets(t, "audit", "", data, func(r *Recorder) {
		r.Targets(TargetRegion, Location{Path: targetsPath, Pointer: "/accounts/*/regions"}).ChosenBy(ChosenByDiscovery, "")
		r.Targets(TargetAccount, Location{Path: targetsPath, Pointer: "/accounts"}, "/account_id").ChosenBy(ChosenByConfig, "accounts")
		r.NotCollected(Location{Path: targetsPath, Pointer: "/accounts/0/password_policy"}, errors.New("access denied"))
	}).Result.Targets
	if elsewhere[0].Complete == nil || !*elsewhere[0].Complete {
		t.Errorf("a gap elsewhere in an account isn't about its regions, got complete %v", elsewhere[0].Complete)
	}
	if elsewhere[1].Complete == nil || *elsewhere[1].Complete {
		t.Errorf("a gap inside an account leaves the accounts incomplete, got %v", elsewhere[1].Complete)
	}
	if len(targetChecks(res)) != 0 {
		t.Errorf("findings = %+v", targetChecks(res))
	}
}

func TestTargetsDeclaresASingleContainer(t *testing.T) {
	data := map[string]any{"tenant_id": "72f988bf", "organization": map[string]any{"name": "Halyard"}}
	res := runTargets(t, "audit", "", data, func(r *Recorder) {
		r.Targets(TargetTenant, Location{Path: targetsPath, Pointer: "/tenant_id"}).ChosenBy(ChosenByConfig, "tenant_id")
		r.Targets(TargetOrganization, Location{Path: targetsPath, Pointer: "/organization"}, "/name").ChosenBy(ChosenByDiscovery, "")
	})
	for _, d := range res.Result.Targets {
		if d.Count == nil || *d.Count != 1 || d.Complete == nil || !*d.Complete {
			t.Errorf("%s: count = %v complete = %v, want one complete target", d.Kind, d.Count, d.Complete)
		}
	}
	if len(targetChecks(res)) != 0 {
		t.Errorf("findings = %+v", targetChecks(res))
	}
}

func TestTargetsDeclaresAContainerTheArtifactDescribes(t *testing.T) {
	declare := func(r *Recorder) {
		r.Targets(TargetTenant, Location{Path: targetsPath, Pointer: ""}, "/tenant_id").ChosenBy(ChosenByConfig, "tenant_id").Label("/org_domain")
	}
	audit := runTargets(t, "audit", gatedSchema, map[string]any{"tenant_id": "72f988bf", "org_domain": "contoso.com"}, declare)
	d := audit.Result.Targets[0]
	if d.At == nil || d.At.Pointer != "" || d.Label != "/org_domain" || d.Count == nil || *d.Count != 1 || d.Complete == nil || !*d.Complete {
		t.Errorf("audit tenant = %+v", d)
	}
	trust := runTargets(t, "trust", gatedSchema, map[string]any{"org_domain": "contoso.com"}, declare)
	if findings := targetChecks(trust); len(findings) != 0 {
		t.Errorf("a tenant whose ID the level leaves out is named by its label, got %+v", findings)
	}
	if d := trust.Result.Targets[0]; d.At == nil || d.Label != "/org_domain" || d.Complete == nil || !*d.Complete {
		t.Errorf("trust tenant = %+v", d)
	}
}

const scannedSchema = `{
	"type": "object",
	"properties": {
		"accounts": {"type": "array", "items": {"type": "object", "properties": {
			"regions": {"type": "array", "items": {"type": "string"}},
			"primary_region": {"type": "string"},
			"guardduty": {"type": "object"},
			"security_hub": {"type": "object", "x-epack-level": "audit"}
		}}}
	}
}`

func TestTargetsNarrowedToTheValuesReadInThem(t *testing.T) {
	data := map[string]any{"accounts": []any{map[string]any{
		"regions": []any{"us-east-1", "eu-west-1"}, "primary_region": "us-east-1",
		"guardduty": map[string]any{"enabled": true}, "security_hub": map[string]any{"enabled": true},
	}}}
	declare := func(r *Recorder) {
		r.Targets(TargetRegion, Location{Path: targetsPath, Pointer: "/accounts/*/regions"}).ChosenBy(ChosenByDiscovery, "")
		r.Targets(TargetRegion, Location{Path: targetsPath, Pointer: "/accounts/*/primary_region"}).ChosenBy(ChosenByCollector, "").
			For(Location{Path: targetsPath, Pointer: "/accounts/*/security_hub"}, Location{Path: "artifacts/demo.other.json", Pointer: "/hub"})
	}
	res := runTargets(t, "audit", scannedSchema, data, declare)
	if len(res.Result.Targets) != 2 {
		t.Fatalf("targets = %+v", res.Result.Targets)
	}
	all, primary := res.Result.Targets[0], res.Result.Targets[1]
	if all.For != nil || all.Count == nil || *all.Count != 2 {
		t.Errorf("every region = %+v", all)
	}
	if len(primary.For) != 1 || primary.For[0].Path != targetsPath || primary.For[0].Pointer != "/accounts/*/security_hub" ||
		primary.ChosenBy != ChosenByCollector || primary.Count == nil || *primary.Count != 1 || primary.Complete == nil || !*primary.Complete {
		t.Errorf("a value in an artifact the run didn't write is dropped from For, got %+v", primary)
	}

	account := data["accounts"].([]any)[0].(map[string]any)
	delete(account, "security_hub")
	trust := runTargets(t, "trust", scannedSchema, data, declare).Result.Targets
	if len(trust) != 1 || trust[0].For != nil {
		t.Errorf("a declaration whose For values the level leaves out is dropped, got %+v", trust)
	}
}

const gatedSchema = `{
	"type": "object",
	"properties": {
		"tenant_id": {"type": "string", "x-epack-level": "audit"},
		"scope": {"type": "object", "properties": {"repository_count": {"type": "integer", "x-epack-level": "audit"}, "coverage_pct": {"type": "integer"}}},
		"repositories": {"type": "array", "x-epack-level": "audit", "items": {"type": "object", "properties": {"name": {"type": "string"}}}},
		"accounts": {"type": "array", "items": {"type": "object", "properties": {
			"account_id": {"type": "string", "x-epack-level": "audit"},
			"label": {"type": "string"}
		}}}
	}
}`

func TestTargetsFollowTheRunsLevel(t *testing.T) {
	declare := func(r *Recorder) {
		r.Targets(TargetTenant, Location{Path: targetsPath, Pointer: "/tenant_id"}).ChosenBy(ChosenByConfig, "tenant_id")
		r.Targets(TargetRepository, Location{Path: targetsPath, Pointer: "/repositories"}, "/name").ChosenBy(ChosenByFilter, "exclude_patterns").
			Found(Location{Path: targetsPath, Pointer: "/scope/repository_count"}).Coverage(Location{Path: targetsPath, Pointer: "/scope/coverage_pct"})
		r.Targets(TargetAccount, Location{Path: targetsPath, Pointer: "/accounts"}, "/account_id").ChosenBy(ChosenByConfig, "accounts").Label("/label")
	}
	trust := map[string]any{"scope": map[string]any{"coverage_pct": 90}, "accounts": []any{map[string]any{"label": "production"}}}
	res := runTargets(t, "trust", gatedSchema, trust, declare)
	if findings := targetChecks(res); len(findings) != 0 {
		t.Fatalf("values the level leaves out are not findings, got %+v", findings)
	}
	byKind := map[TargetKind]ResultTarget{}
	for _, d := range res.Result.Targets {
		byKind[d.Kind] = d
	}
	if d := byKind[TargetTenant]; d.At != nil || d.Complete != nil || d.ChosenBy != ChosenByConfig {
		t.Errorf("an audit tenant at trust keeps only how it was chosen, got %+v", d)
	}
	if d := byKind[TargetRepository]; d.At != nil || d.Found != nil || d.Coverage == nil || d.Coverage.Pointer != "/scope/coverage_pct" {
		t.Errorf("an audit list at trust keeps the coverage the artifact holds, got %+v", d)
	}
	if d := byKind[TargetAccount]; d.At == nil || d.Label != "/label" || d.Complete == nil || !*d.Complete {
		t.Errorf("a trust list whose names are audit keeps its labels, got %+v", d)
	}
	if strings.Contains(string(res.Artifacts[len(res.Artifacts)-1].Data), "production") {
		t.Errorf("the result points at names and copies none")
	}

	audit := map[string]any{"tenant_id": "t1", "scope": map[string]any{"repository_count": 12, "coverage_pct": 90},
		"repositories": []any{map[string]any{"name": "web"}}, "accounts": []any{map[string]any{"account_id": "111", "label": "production"}}}
	for _, d := range runTargets(t, "audit", gatedSchema, audit, declare).Result.Targets {
		if d.At == nil || d.Count == nil {
			t.Errorf("%s at audit: %+v", d.Kind, d)
		}
		if d.Kind == TargetRepository && (d.Found == nil || d.Found.Path != targetsPath) {
			t.Errorf("found = %+v", d.Found)
		}
	}
}

func TestTargetsAllowAnUnnamedTargetAGapCovers(t *testing.T) {
	data := map[string]any{"accounts": []any{map[string]any{"account_id": "111"}, map[string]any{"account_label": "staging"}}}
	res := runTargets(t, "audit", "", data, func(r *Recorder) {
		r.Targets(TargetAccount, Location{Path: targetsPath, Pointer: "/accounts"}, "/account_id").ChosenBy(ChosenByConfig, "accounts").Label("/account_label")
		r.NotCollected(Location{Path: targetsPath, Pointer: "/accounts/1/storage"}, errors.New("role refused"))
	})
	if findings := targetChecks(res); len(findings) != 0 {
		t.Errorf("an account a gap covers may lack its ID, got %+v", findings)
	}
}

func TestTargetsReportWhatTheArtifactDoesntBearOut(t *testing.T) {
	data := map[string]any{"accounts": []any{map[string]any{"label": "production"}}}
	res := runTargets(t, "audit", gatedSchema, data, func(r *Recorder) {
		r.Targets(TargetEndpoint, Location{Path: targetsPath, Pointer: "/endpoints"}, "/host").ChosenBy(ChosenByConfig, "endpoints")
		r.Targets(TargetAccount, Location{Path: targetsPath, Pointer: "/accounts"}, "/account_id").ChosenBy(ChosenByConfig, "accounts")
	})
	var got []string
	for _, f := range targetChecks(res) {
		got = append(got, f.Pointer+" "+f.Message)
	}
	want := []string{
		"/endpoints declares endpoint targets here, but the artifact holds no value at it",
		"/accounts/0 has no value at /account_id to name this account target",
	}
	if !slices.Equal(got, want) {
		t.Errorf("findings = %q, want %q", got, want)
	}
}

func TestTargetsRejectAMalformedDeclaration(t *testing.T) {
	for name, declare := range map[string]func(*Recorder){
		"unknown kind": func(r *Recorder) {
			r.Targets("user", Location{Path: targetsPath, Pointer: "/users"}).ChosenBy(ChosenByDiscovery, "")
		},
		"no choice": func(r *Recorder) { r.Targets(TargetDomain, Location{Path: targetsPath, Pointer: "/domains"}) },
		"bad pointer": func(r *Recorder) {
			r.Targets(TargetDomain, Location{Path: targetsPath, Pointer: "domains"}).ChosenBy(ChosenByConfig, "domains")
		},
		"two wildcards": func(r *Recorder) {
			r.Targets(TargetRegion, Location{Path: targetsPath, Pointer: "/a/*/b/*/c"}).ChosenBy(ChosenByConfig, "")
		},
		"relative label": func(r *Recorder) {
			r.Targets(TargetDomain, Location{Path: targetsPath, Pointer: "/domains"}).ChosenBy(ChosenByConfig, "").Label("name")
		},
		"for the whole artifact": func(r *Recorder) {
			r.Targets(TargetDomain, Location{Path: targetsPath, Pointer: "/domains"}).ChosenBy(ChosenByConfig, "").For(Location{Path: targetsPath})
		},
		"relative for": func(r *Recorder) {
			r.Targets(TargetDomain, Location{Path: targetsPath, Pointer: "/domains"}).ChosenBy(ChosenByConfig, "").For(Location{Path: targetsPath, Pointer: "spf"})
		},
	} {
		spec := CollectorSpec{Name: "demo", Version: "0.1.0"}
		res := RunInProcess(spec, func(ctx CollectorContext) error {
			declare(Records(ctx))
			return ctx.Emit([]CollectedArtifact{{Data: map[string]any{"domains": []any{}}, Path: targetsPath}})
		}, InProcessOptions{RunID: "r1", Seed: 1})
		if res.ExitCode == 0 {
			t.Errorf("%s: the run succeeded, want Emit to fail", name)
		}
	}
}

func TestTargetsFollowARenamedRun(t *testing.T) {
	spec := CollectorSpec{Name: "demo", Version: "0.1.0"}
	res := RunInProcess(spec, func(ctx CollectorContext) error {
		Records(ctx).Targets(TargetDomain, Location{Path: "artifacts/demo.email-dns.json", Pointer: "/domains"}, "/domain").ChosenBy(ChosenByConfig, "domains")
		return ctx.Emit([]CollectedArtifact{{Data: map[string]any{"domains": []any{map[string]any{"domain": "example.com"}}}, Path: "artifacts/demo.email-dns.json"}})
	}, InProcessOptions{Name: "demo-prod", Config: map[string]any{"level": "audit"}, RunID: "r1", Seed: 1})
	if res.Result == nil || len(res.Result.Targets) != 1 {
		t.Fatalf("result = %+v stderr = %s", res.Result, res.Stderr)
	}
	if d := res.Result.Targets[0]; d.At == nil || d.At.Path != "artifacts/demo-prod.email-dns.json" || d.Count == nil || *d.Count != 1 {
		t.Errorf("declaration = %+v, want the renamed path", d)
	}
}
