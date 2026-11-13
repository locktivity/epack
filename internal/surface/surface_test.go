package surface

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testSpec = `
openapi: 3.0.0
servers:
  - url: https://{yourOktaDomain}
paths:
  /api/v1/users:
    get: {operationId: listUsers, tags: [User], summary: List users}
    post: {operationId: createUser, tags: [User]}
  /api/v1/users/{userId}:
    get: {operationId: getUser, tags: [User]}
  /api/v1/users/{userId}/factors:
    get: {operationId: listFactors, tags: [UserFactor]}
  /api/v1/devices:
    get: {operationId: listDevices, tags: [Device]}
  /api/v1/devices/{deviceId}/users:
    get: {operationId: listDeviceUsers, tags: [Device]}
  /api/v1/brands:
    get: {operationId: listBrands, tags: [Customization]}
  /api/v1/old:
    get: {operationId: listOld, tags: [User], deprecated: true}
  /repos/{owner}/{repo}/contents/{path}:
    get: {operationId: repos/get-content, tags: [repos], x-github: {category: repos, subcategory: contents}}
  /repos/{owner}/{repo}/hooks:
    get: {operationId: repos/list-webhooks, tags: [repos], x-github: {category: repos, subcategory: webhooks}}
`

const testRecording = `{"name":"okta","responses":[
 {"operation":"okta.token.create","method":"POST","url":"https://acme.okta.com/oauth2/v1/token?"},
 {"operation":"okta.users.list","method":"GET","url":"https://acme.okta.com/api/v1/users?limit=200"},
 {"operation":"okta.users.factors.list","method":"GET","url":"https://acme.okta.com/api/v1/users/00u1abc/factors"},
 {"operation":"okta.users.factors.list","method":"GET","url":"https://acme.okta.com/api/v1/users/00u2abc/factors"},
 {"operation":"github.repo_contents.get","method":"GET","url":"https://api.github.com/repos/o/r/contents/.github/CODEOWNERS"}
]}`

func loadTestSpec(t *testing.T) *Spec {
	t.Helper()
	spec, err := ParseSpec([]byte(testSpec), false)
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func TestMatchPrefersLiteralsAndAbsorbsTrailingPath(t *testing.T) {
	spec := loadTestSpec(t)
	cases := map[string]string{
		"GET https://acme.okta.com/api/v1/users?limit=200":                 "listUsers",
		"GET https://acme.okta.com/api/v1/users/00u1/factors":              "listFactors",
		"GET https://acme.okta.com/api/v1/users/00u1":                      "getUser",
		"POST https://acme.okta.com/api/v1/users":                          "createUser",
		"GET https://api.github.com/repos/o/r/contents/.github/CODEOWNERS": "repos/get-content",
		"GET https://api.github.com/repos/o/r/hooks":                       "repos/list-webhooks",
	}
	for req, want := range cases {
		method, url, _ := strings.Cut(req, " ")
		op, ok := spec.Match(method, url)
		if !ok || op.Key() != want {
			t.Errorf("Match(%s) = %v, %v, want %s", req, op, ok, want)
		}
	}
	for _, req := range []string{"POST https://acme.okta.com/oauth2/v1/token", "GET https://acme.okta.com/api/v1/users/00u1/factors/extra/deep", "GET https://api.github.com/repos/o/r/hooks/5"} {
		method, url, _ := strings.Cut(req, " ")
		if op, ok := spec.Match(method, url); ok {
			t.Errorf("Match(%s) = %s, want no match", req, op.Key())
		}
	}
}

func TestMatchStripsServerBasePathAndChecksTheHost(t *testing.T) {
	spec, err := ParseSpec([]byte("openapi: 3.0.0\nservers: [{url: https://api.example.com/v2}]\npaths:\n  /things: {get: {operationId: listThings}}\n"), false)
	if err != nil {
		t.Fatal(err)
	}
	if op, ok := spec.Match("GET", "https://API.example.com/v2/things"); !ok || op.ID != "listThings" {
		t.Errorf("Match with base path = %v, %v", op, ok)
	}
	if op, ok := spec.Match("GET", "https://management.example.net/v2/things"); ok {
		t.Errorf("a request on another host matched %s", op.ID)
	}
	templated := loadTestSpec(t)
	if len(templated.Hosts) != 0 {
		t.Errorf("a templated host should not be a fixed host: %v", templated.Hosts)
	}
	if _, ok := templated.Match("GET", "https://anything.okta.com/api/v1/users"); !ok {
		t.Error("a description with only a templated host matches any host")
	}
}

func TestAnalyzeVerdictsAndProblems(t *testing.T) {
	spec := loadTestSpec(t)
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "rec"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rec", "okta.json"), []byte(testRecording), 0o644); err != nil {
		t.Fatal(err)
	}
	calls, err := LoadCalls(dir, "rec")
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 5 {
		t.Fatalf("LoadCalls = %d calls, want 5", len(calls))
	}
	cfg := &Config{
		Vendor:       "Okta",
		Scope:        Scope{ExcludeTags: []string{"repos"}},
		NotCollected: []Item{{Title: "Devices", Says: "The devices users enroll.", Tags: []string{"Device"}}},
		Irrelevant:   []Item{{Reason: "Branding", Operations: []string{"listBrands"}}},
	}
	r := Analyze(spec, cfg, calls)
	if r.InScope != 6 {
		t.Errorf("InScope = %d, want 6 (deprecated listOld and repos excluded, createUser is POST)", r.InScope)
	}
	if len(r.Exercised) != 3 {
		t.Errorf("Exercised = %d, want 3", len(r.Exercised))
	}
	var factors *Exercised
	for i := range r.Exercised {
		if r.Exercised[i].Op.ID == "listFactors" {
			factors = &r.Exercised[i]
		}
	}
	if factors == nil || factors.CollectorNames() != "okta.users.factors.list" || factors.Collector["okta.users.factors.list"] != 2 {
		t.Errorf("exercised listFactors = %v", factors)
	}
	if len(r.NotCollected) != 2 || len(r.Irrelevant) != 1 {
		t.Errorf("NotCollected = %d, Irrelevant = %d, want 2 and 1", len(r.NotCollected), len(r.Irrelevant))
	}
	if len(r.Unverdicted) != 1 || r.Unverdicted[0].ID != "getUser" {
		t.Errorf("Unverdicted = %v, want getUser", r.Unverdicted)
	}
	if len(r.Unmatched) != 1 || r.Unmatched[0].Operation != "okta.token.create" {
		t.Errorf("Unmatched = %v, want the token call", r.Unmatched)
	}
	wantProblems := []string{
		"the recordings call POST /oauth2/v1/token as okta.token.create",
		"getUser (GET /api/v1/users/{userId}) has no verdict",
	}
	for _, want := range wantProblems {
		if !containsProblem(r.Problems, want) {
			t.Errorf("Problems lack %q:\n%s", want, strings.Join(r.Problems, "\n"))
		}
	}
	if len(r.Problems) != len(wantProblems) {
		t.Errorf("Problems = %d, want %d:\n%s", len(r.Problems), len(wantProblems), strings.Join(r.Problems, "\n"))
	}

	cfg.Unmatched = []Unmatched{{Operation: "okta.token.create", Reason: "OAuth token endpoint"}, {Operation: "okta.nothing", Reason: "stale"}}
	cfg.Irrelevant = append(cfg.Irrelevant,
		Item{Reason: "Stale", Operations: []string{"listNothing"}},
		Item{Reason: "Exercised", Operations: []string{"listUsers"}},
		Item{Reason: "Conflict", Tags: []string{"Device"}},
		Item{Reason: "Users", Operations: []string{"getUser"}})
	cfg.Reads = []Read{{Operations: []string{"listDeviceUsers", "listUsers", "listNothing"}, Collector: "okta.devices.users.list", When: "a device is enrolled"}}
	r = Analyze(spec, cfg, calls)
	for _, want := range []string{
		"unmatched lists okta.nothing",
		"Stale names listNothing, which the API description does not describe",
		"Exercised names listUsers, which the recordings call",
		"listDevices is both not collected (Devices) and irrelevant (Conflict)",
		"reads names listUsers, which the recordings now call",
		"reads names listNothing, which the API description does not describe",
	} {
		if !containsProblem(r.Problems, want) {
			t.Errorf("Problems lack %q:\n%s", want, strings.Join(r.Problems, "\n"))
		}
	}
	if len(r.Unverdicted) != 0 || len(r.Acknowledged) != 1 || len(r.Reads) != 1 || r.Reads[0].Op.ID != "listDeviceUsers" {
		t.Errorf("Unverdicted = %d, Acknowledged = %d, Reads = %v", len(r.Unverdicted), len(r.Acknowledged), r.Reads)
	}
	if !containsProblem(r.Problems, "listDeviceUsers is both") == false {
		t.Error("a read operation needs no verdict, so it is never a conflict")
	}

	specific := &Config{Vendor: "Okta",
		NotCollected: []Item{{Title: "Device users", Says: "x", Operations: []string{"listDeviceUsers"}}},
		Irrelevant:   []Item{{Reason: "Devices by tag", Tags: []string{"Device"}}}}
	r = Analyze(spec, specific, calls)
	if len(r.Problems) != 0 && !containsProblem(r.Problems, "has no verdict") && !containsProblem(r.Problems, "okta.token.create") {
		t.Errorf("naming an operation should win over a tag:\n%s", strings.Join(r.Problems, "\n"))
	}
	if len(r.NotCollected) != 1 || r.NotCollected[0].Op.ID != "listDeviceUsers" || len(r.Irrelevant) != 1 {
		t.Errorf("NotCollected = %v, Irrelevant = %d; the named operation should win over the tag", r.NotCollected, len(r.Irrelevant))
	}
}

func TestRenderReferenceLeadsWithReads(t *testing.T) {
	spec := loadTestSpec(t)
	cfg := &Config{
		Vendor:       "Okta",
		Spec:         SpecRef{Source: "https://example.com/spec", Revision: "abc"},
		Reference:    ReferenceRef{File: "docs/coverage.md"},
		Scope:        Scope{ExcludeTags: []string{"repos"}},
		NotCollected: []Item{{Title: "Devices", Says: "The devices users enroll.", Tags: []string{"Device"}}},
		Irrelevant:   []Item{{Reason: "Branding", Operations: []string{"listBrands"}}, {Reason: "Users", Operations: []string{"getUser"}}},
		Unmatched:    []Unmatched{{Operation: "okta.token.create", Reason: "OAuth token endpoint"}},
		Reads:        []Read{{Collector: "okta.saml.list", When: "SAML is on"}},
	}
	calls := []Call{
		{Scenario: "okta", Operation: "okta.token.create", Method: "POST", URL: "https://acme.okta.com/oauth2/v1/token"},
		{Scenario: "okta", Operation: "okta.users.list", Method: "GET", URL: "https://acme.okta.com/api/v1/users"},
		{Scenario: "okta", Operation: "okta.users.factors.list", Method: "GET", URL: "https://acme.okta.com/api/v1/users/1/factors"},
	}
	r := Analyze(spec, cfg, calls)
	if len(r.Problems) != 0 {
		t.Fatalf("Problems = %v", r.Problems)
	}
	got := RenderReference(cfg, r, Docs{Module: "github.com/locktivity/epack-collector-okta"})
	for _, want := range []string{
		"# Okta API coverage\n",
		"checked against the Okta API description at revision abc: https://example.com/spec.",
		"| Called by the collector | 2 |",
		"| Not collected | 2, in 1 items |",
		"## What the collector reads\n\n- **users:** `listUsers` (GET /api/v1/users); `listFactors` (GET /api/v1/users/{userId}/factors)\n",
		"### Devices\n\nThe devices users enroll.\n\n- `listDevices` (GET /api/v1/devices)\n- `listDeviceUsers` (GET /api/v1/devices/{deviceId}/users)\n",
		"## Left out as irrelevant\n\n- **Branding.** `listBrands`\n- **Users.** `getUser`\n",
		"## Outside the description\n\n- okta.token.create (POST /oauth2/v1/token): OAuth token endpoint\n",
		"Generated by `epack sdk surface`",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("reference lacks %q:\n%s", want, got)
		}
	}
	if !strings.Contains(got, "## Calls the sandbox never exercises\n\nThe collector makes these calls when the tenant has something the sandbox lacks, so no recording holds them.\n\n- okta.saml.list, when SAML is on.\n") {
		t.Errorf("a read with no operations should still be listed:\n%s", got)
	}
	if a := Area(&Operation{Path: "/attack-protection/api/v1/user-lockout-settings"}); a != "attack-protection" {
		t.Errorf("Area = %s", a)
	}
	if a := Area(&Operation{Path: "/.well-known/ssf-configuration"}); a != "well-known" {
		t.Errorf("Area = %s", a)
	}
}

func containsProblem(problems []string, want string) bool {
	for _, p := range problems {
		if strings.Contains(p, want) {
			return true
		}
	}
	return false
}

func TestItemCoversCategoriesAndPaths(t *testing.T) {
	spec := loadTestSpec(t)
	content, _ := spec.Lookup("repos/get-content")
	hooks, _ := spec.Lookup("repos/list-webhooks")
	if !(Item{Categories: []string{"repos/contents"}}).Covers(content) || (Item{Categories: []string{"repos/contents"}}).Covers(hooks) {
		t.Error("category/subcategory should cover only contents")
	}
	if !(Item{Categories: []string{"repos"}}).Covers(hooks) {
		t.Error("a category alone covers every subcategory")
	}
	if !(Item{Paths: []string{"/repos/{owner}/{repo}/contents*"}}).Covers(content) || (Item{Paths: []string{"/repos/{owner}/{repo}/contents*"}}).Covers(hooks) {
		t.Error("a path prefix covers only paths beneath it")
	}
	if !(Item{Operations: []string{"GET /repos/{owner}/{repo}/hooks"}}).Covers(hooks) {
		t.Error("METHOD /path names an operation")
	}
}

func TestRenderAndReplaceSection(t *testing.T) {
	cfg := &Config{
		Vendor:       "Okta",
		Spec:         SpecRef{Source: "https://github.com/okta/okta-management-openapi-spec", Path: "dist/current/management.yaml", Revision: "ec20a8e"},
		Reference:    ReferenceRef{File: "docs/coverage.md"},
		NotCollected: []Item{{Title: "Devices.", Says: " The devices users enroll. "}, {Title: "Sessions", Says: "Users' sessions."}},
	}
	docs := Docs{Module: "github.com/locktivity/epack-collector-okta"}
	section := RenderSection(cfg, docs)
	pointer := "The coverage reference lists what the collector reads of the Okta API, and everything else the API offers with why it is left out, checked against Okta's published API description: https://github.com/locktivity/epack-collector-okta/blob/main/docs/coverage.md\n"
	want := "## Not Collected\n\nOkta offers the following through its API, and the collector does not read them.\n\n- **Devices.** The devices users enroll.\n- **Sessions.** Users' sessions.\n\n" + pointer
	if section != want {
		t.Errorf("RenderSection without headlines =\n%s\nwant\n%s", section, want)
	}
	cfg.Overview = []Headline{{Title: "Devices and sessions", Says: "Devices and sessions.", Items: []string{"Devices.", "Sessions"}}, {Title: "Devices", Items: []string{"Devices."}}}
	section = RenderSection(cfg, docs)
	want = "## Not Collected\n\nOkta offers the following through its API, and the collector does not read them.\n\n- **Devices and sessions.** Devices and sessions.\n- **Devices.** The devices users enroll.\n\n" + pointer
	if section != want {
		t.Errorf("RenderSection with headlines =\n%s\nwant\n%s", section, want)
	}
	cfg.Overview = nil
	doc := "# Okta\n\n## Output\n\nstuff\n\n## Not Collected\n\nOld text.\n\n- old bullet\n\n## Use Cases\n\nmore\n"
	got := string(ReplaceSection([]byte(doc), section))
	wantDoc := "# Okta\n\n## Output\n\nstuff\n\n" + section + "\n## Use Cases\n\nmore\n"
	if got != wantDoc {
		t.Errorf("ReplaceSection =\n%s\nwant\n%s", got, wantDoc)
	}
	if CurrentSection([]byte(got)) != section {
		t.Errorf("CurrentSection after replace =\n%s", CurrentSection([]byte(got)))
	}
	noSection := "# Okta\n\n## Output\n\nstuff\n\n## Use Cases\n\nmore\n"
	got = string(ReplaceSection([]byte(noSection), section))
	if got != "# Okta\n\n## Output\n\nstuff\n\n"+section+"\n## Use Cases\n\nmore\n" {
		t.Errorf("ReplaceSection without a section =\n%s", got)
	}
	if CurrentSection([]byte(noSection)) != "" {
		t.Error("CurrentSection should be empty without a section")
	}
	tail := "# Okta\n\n## Output\n\nstuff\n"
	if got = string(ReplaceSection([]byte(tail), section)); got != tail+"\n"+section {
		t.Errorf("ReplaceSection at the end =\n%s", got)
	}
}

const armSpec = `{
  "swagger": "2.0",
  "host": "management.azure.com",
  "paths": {
    "/subscriptions/{subscriptionId}/providers/Microsoft.Storage/storageAccounts": {"get": {"operationId": "StorageAccounts_List"}},
    "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Storage/storageAccounts/{accountName}/blobServices": {"get": {"operationId": "BlobServices_List"}},
    "/subscriptions/{subscriptionId}": {"get": {"operationId": "Subscriptions_Get"}}
  }
}`

const graphSpec = `{
  "openapi": "3.0.1",
  "servers": [{"url": "https://graph.microsoft.com/v1.0"}],
  "paths": {
    "/subscriptions/{subscription-id}": {"get": {"operationId": "subscriptions.subscription.GetSubscription"}},
    "/users": {"get": {"operationId": "users.user.ListUser"}},
    "/groups/{group-id}/members": {"get": {"operationId": "groups.ListMembers"}},
    "/groups/{group-id}/calendar": {"get": {"operationId": "groups.GetCalendar"}}
  }
}`

func TestCombineMatchesByHostAndBasePath(t *testing.T) {
	arm, err := ParseSpec([]byte(armSpec), true)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := ParseSpec([]byte(graphSpec), true)
	if err != nil {
		t.Fatal(err)
	}
	arm.Name, graph.Name = "arm", "graph"
	spec := Combine(arm, graph)
	if len(spec.Parts) != 2 || len(spec.Operations) != 7 {
		t.Fatalf("Combine: %d parts, %d operations", len(spec.Parts), len(spec.Operations))
	}
	cases := map[string]string{
		"GET https://management.azure.com/subscriptions/abc?api-version=2020-01-01":                      "Subscriptions_Get",
		"GET https://graph.microsoft.com/v1.0/subscriptions/abc":                                         "subscriptions.subscription.GetSubscription",
		"GET https://graph.microsoft.com/v1.0/users?$select=id":                                          "users.user.ListUser",
		"GET https://management.azure.com/subscriptions/abc/providers/Microsoft.Storage/storageAccounts": "StorageAccounts_List",
	}
	for req, want := range cases {
		method, url, _ := strings.Cut(req, " ")
		op, ok := spec.Match(method, url)
		if !ok || op.Key() != want {
			t.Errorf("Match(%s) = %v, %v, want %s", req, op, ok, want)
		} else if (want == "Subscriptions_Get" && op.Description() != "arm") || (want == "users.user.ListUser" && op.Description() != "graph") {
			t.Errorf("Match(%s) came from %q", req, op.Description())
		}
	}
	if op, ok := spec.Match("GET", "https://graph.microsoft.com/users"); ok {
		t.Errorf("a Graph request without the base path matched %s", op.Key())
	}
	blob, _ := spec.Lookup("BlobServices_List")
	if Area(blob) != "Microsoft.Storage" {
		t.Errorf("Area of an Azure path = %s, want the provider namespace", Area(blob))
	}
}

func TestLongerPathPrefixesAndContainsWin(t *testing.T) {
	graph, err := ParseSpec([]byte(graphSpec), true)
	if err != nil {
		t.Fatal(err)
	}
	members, _ := graph.Lookup("groups.ListMembers")
	calendar, _ := graph.Lookup("groups.GetCalendar")
	broad := Item{Reason: "Group content", Paths: []string{"/groups/{group-id}/*"}}
	narrow := Item{Title: "Group membership", Says: "x", Paths: []string{"/groups/{group-id}/members*"}}
	if narrow.Specificity(members) <= broad.Specificity(members) {
		t.Error("the longer prefix should win for members")
	}
	if narrow.Specificity(calendar) != 0 || broad.Specificity(calendar) == 0 {
		t.Error("only the broad prefix covers the calendar")
	}
	arm, _ := ParseSpec([]byte(armSpec), true)
	blob, _ := arm.Lookup("BlobServices_List")
	provider := Item{Reason: "Storage", PathContains: []string{"/providers/Microsoft.Storage/"}}
	if provider.Specificity(blob) == 0 {
		t.Error("path_contains should cover an Azure provider path")
	}
	sub, _ := arm.Lookup("Subscriptions_Get")
	if provider.Specificity(sub) != 0 {
		t.Error("path_contains should not cover a path without the string")
	}
	cfg := &Config{Vendor: "Microsoft", NotCollected: []Item{narrow}, Irrelevant: []Item{broad, provider}}
	r := Analyze(Combine(arm, graph), cfg, nil)
	tied := &Config{Vendor: "Microsoft", NotCollected: []Item{narrow, {Title: "Also members", Says: "y", Paths: []string{"/groups/{group-id}/members*"}}}, Irrelevant: []Item{broad, provider}}
	if tr := Analyze(Combine(arm, graph), tied, nil); !containsProblem(tr.Problems, "groups.ListMembers is covered equally by two not_collected items") {
		t.Errorf("two items covering an operation equally should be a problem:\n%s", strings.Join(tr.Problems, "\n"))
	}
	if len(r.NotCollected) != 1 || r.NotCollected[0].Op.Key() != "groups.ListMembers" {
		t.Errorf("NotCollected = %v", r.NotCollected)
	}
	for _, p := range r.Problems {
		if strings.Contains(p, "both not collected") {
			t.Errorf("unexpected conflict: %s", p)
		}
	}
}

func TestLoadSpecReadsADirectoryAsOneDescription(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte(armSpec), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.json"), []byte(`{"swagger":"2.0","host":"management.azure.com","paths":{"/subscriptions/{subscriptionId}/providers/Microsoft.KeyVault/vaults":{"get":{"operationId":"Vaults_ListBySubscription"}}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "readme.md"), []byte("not a description"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := LoadSpec(dir)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Name != filepath.Base(dir) || len(spec.Operations) != 4 || len(spec.Parts) != 0 {
		t.Errorf("directory description: name %q, %d operations, %d parts", spec.Name, len(spec.Operations), len(spec.Parts))
	}
	if op, ok := spec.Match("GET", "https://management.azure.com/subscriptions/abc/providers/Microsoft.KeyVault/vaults?api-version=2024-11-01"); !ok || op.ID != "Vaults_ListBySubscription" {
		t.Errorf("Match in a directory description = %v, %v", op, ok)
	}
	if op, ok := spec.Match("GET", "https://graph.microsoft.com/subscriptions/abc"); ok {
		t.Errorf("a request on another host matched %s", op.ID)
	}
}

func TestSpanningParametersAnywhereAndInSelector(t *testing.T) {
	arm, err := ParseSpec([]byte(`{"swagger":"2.0","host":"management.azure.com","paths":{
	  "/{resourceUri}/providers/Microsoft.Insights/diagnosticSettings": {"get": {"operationId": "DiagnosticSettings_List"}},
	  "/{scope}/providers/Microsoft.Security/assessments": {"get": {"operationId": "Assessments_List"}},
	  "/subscriptions/{subscriptionId}/providers/Microsoft.Insights/diagnosticSettings": {"get": {"operationId": "SubscriptionDiagnosticSettings_List"}}}}`), true)
	if err != nil {
		t.Fatal(err)
	}
	arm.Rename("Azure")
	graph, _ := ParseSpec([]byte(graphSpec), true)
	graph.Rename("Graph")
	spec := Combine(arm, graph)
	cases := map[string]string{
		"GET https://management.azure.com/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acc/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview": "DiagnosticSettings_List",
		"GET https://management.azure.com/subscriptions/s/providers/Microsoft.Insights/diagnosticSettings":                                                                                                  "SubscriptionDiagnosticSettings_List",
		"GET https://management.azure.com/subscriptions/s/providers/Microsoft.Security/assessments":                                                                                                         "Assessments_List",
	}
	for req, want := range cases {
		method, url, _ := strings.Cut(req, " ")
		op, ok := spec.Match(method, url)
		if !ok || op.Key() != want {
			t.Errorf("Match(%s) = %v, %v, want %s", req, op, ok, want)
		}
	}
	webhooks, _ := spec.Lookup("subscriptions.subscription.GetSubscription")
	sub, _ := spec.Lookup("SubscriptionDiagnosticSettings_List")
	if webhooks.Description() != "Graph" || sub.Description() != "Azure" {
		t.Errorf("descriptions: %q and %q", webhooks.Description(), sub.Description())
	}
	graphOnly := Item{Reason: "Webhooks", Paths: []string{"/subscriptions*"}, In: []string{"Graph"}}
	if graphOnly.Specificity(webhooks) == 0 || graphOnly.Specificity(sub) != 0 {
		t.Error("an item limited to a description should not cover another description's paths")
	}
}
