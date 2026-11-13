package collectortest

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk"
)

// fieldProbeChecks are the checks the field-faults tests leave out, so each
// test sees only the check it is about.
var fieldProbeChecks = []string{"faults", "levels", "determinism", "credentials", "sensitivity", "order", "pages", "variants"}

// ptrList returns the list l points to, or none.
func ptrList[T any](l *[]T) []T {
	if l == nil {
		return nil
	}
	return *l
}

// getJSON reads op's answer at url into out.
func getJSON(ctx componentsdk.CollectorContext, op, url string, out any) error {
	client := componentsdk.NewHTTPClient(ctx, componentsdk.HTTPOptions{})
	req, err := http.NewRequestWithContext(componentsdk.WithOperation(ctx.Context(), componentsdk.Operation{Name: op}), http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	return componentsdk.ResponseError(resp, json.NewDecoder(resp.Body).Decode(out))
}

// adminProbe counts the users who hold Global Administrator, as the Microsoft
// collector's v0.2.4 did. A role whose isPrivileged is null counts as
// unclassified, and its holders are skipped. Graph v1.0 sends null on every
// role, so the count read 0. fixed leaves the count out with a gap when an
// assignment's role is unclassified or missing.
type adminProbe struct{ fixed bool }

func (p adminProbe) run(ctx componentsdk.CollectorContext) error {
	var roles struct {
		Value []struct {
			ID           string `json:"id"`
			IsPrivileged *bool  `json:"isPrivileged"`
		} `json:"value"`
	}
	if err := getJSON(ctx, "demo.roles.list", demoHost+"/roles", &roles); err != nil {
		return err
	}
	var assignments struct {
		Value *[]struct {
			PrincipalID string `json:"principalId"`
			RoleID      string `json:"roleId"`
		} `json:"value"`
	}
	if err := getJSON(ctx, "demo.assignments.list", demoHost+"/assignments", &assignments); err != nil {
		return err
	}
	privileged := map[string]*bool{}
	for _, r := range roles.Value {
		privileged[r.ID] = r.IsPrivileged
	}
	admins, unclassified := map[string]bool{}, assignments.Value == nil
	for _, a := range ptrList(assignments.Value) {
		is := privileged[a.RoleID]
		if is == nil {
			unclassified = true
			continue
		}
		if *is && a.RoleID == "global-admin" {
			admins[a.PrincipalID] = true
		}
	}
	out := map[string]any{"super_admin_count": len(admins)}
	if (p.fixed && unclassified) || assignments.Value == nil {
		delete(out, "super_admin_count")
		componentsdk.Records(ctx).NotCollectedCode(componentsdk.Location{Path: "artifacts/probe.json", Pointer: "/super_admin_count"}, componentsdk.CodeInvalidResponse, "an assignment's role is unclassified")
	}
	return ctx.Emit([]componentsdk.CollectedArtifact{{Path: "artifacts/probe.json", Data: out}})
}

func adminSuite(p adminProbe) Suite {
	return Suite{
		Spec: componentsdk.CollectorSpec{Name: "probe"},
		Run:  p.run,
		Scenarios: []Scenario{{Name: "clean", Responses: []Response{
			{URL: demoHost + "/roles", Body: `{"value":[{"id":"global-admin","isPrivileged":true},{"id":"reader","isPrivileged":false}]}`},
			{URL: demoHost + "/assignments", Body: `{"value":[{"principalId":"u1","roleId":"global-admin"},{"principalId":"u2","roleId":"reader"}]}`},
		}}},
		Populations: []Population{{Operation: "demo.assignments.list", List: "/value", Reason: "a tenant with no role assignments has no Global Administrators"}},
		Waivers:     waiving(fieldProbeChecks...),
	}
}

func TestTheFieldFaultsCheckCatchesANullClassificationReadAsNoAdmins(t *testing.T) {
	report := checkSuite(t, adminSuite(adminProbe{}))
	for _, fault := range []string{"null", "dropped"} {
		expectViolation(t, report, "field_faults", "demo.roles.list /value/*/isPrivileged "+fault)
	}
	expectViolation(t, report, "field_faults", "artifacts/probe.json /super_admin_count: changed from 1 to 0 without a gap")

	if got := violationsOf(checkSuite(t, adminSuite(adminProbe{fixed: true})), "field_faults"); len(got) != 0 {
		t.Errorf("a collector that leaves the count out with a gap: %+v", got)
	}

	off := adminSuite(adminProbe{})
	off.Waivers = append(off.Waivers, waive("field_faults"))
	if got := violationsOf(checkSuite(t, off), "field_faults"); len(got) != 0 {
		t.Errorf("the check is on in every suite and off only under a waiver: %+v", got)
	}
}

func TestGapOperationsMakesAFieldFaultGapNameItsOperation(t *testing.T) {
	s := adminSuite(adminProbe{fixed: true})
	s.GapOperations = true
	expectViolation(t, checkSuite(t, s), "field_faults", "super_admin_count: 1 left out under a gap that names no operation")
}

// vaultProbe takes the share of backup vaults with soft delete on, as the
// Microsoft collector's v0.2.4 did. Azure's vault list leaves each vault's
// security settings out, so a vault without them counted as off and the
// share read 0. fixed leaves the share out with a gap for a vault with no
// state. Either leaves every value out when the answer has no vault list.
type vaultProbe struct{ fixed bool }

func (p vaultProbe) run(ctx componentsdk.CollectorContext) error {
	var vaults struct {
		Value *[]struct {
			Properties struct {
				SecuritySettings struct {
					SoftDeleteSettings struct {
						State string `json:"softDeleteState"`
					} `json:"softDeleteSettings"`
				} `json:"securitySettings"`
			} `json:"properties"`
		} `json:"value"`
	}
	err := getJSON(ctx, "demo.vaults.list", demoHost+"/vaults", &vaults)
	if err != nil {
		return err
	}
	rec := componentsdk.Records(ctx)
	at := func(pointer string) componentsdk.Location {
		return componentsdk.Location{Path: "artifacts/probe.json", Pointer: pointer}
	}
	if vaults.Value == nil {
		for _, pointer := range []string{"/vault_count", "/vault_soft_delete_pct"} {
			rec.NotCollectedCode(at(pointer), componentsdk.CodeInvalidResponse, "the answer has no vault list")
		}
		return ctx.Emit([]componentsdk.CollectedArtifact{{Path: "artifacts/probe.json", Data: map[string]any{}}})
	}
	list := *vaults.Value
	on, unknown := 0, false
	for _, v := range list {
		switch v.Properties.SecuritySettings.SoftDeleteSettings.State {
		case "Enabled":
			on++
		case "":
			unknown = true
		}
	}
	out := map[string]any{"vault_count": len(list)}
	switch {
	case p.fixed && unknown:
		rec.NotCollectedCode(at("/vault_soft_delete_pct"), componentsdk.CodeInvalidResponse, "a vault has no soft delete state")
	case len(list) > 0:
		out["vault_soft_delete_pct"] = on * 100 / len(list)
	}
	return ctx.Emit([]componentsdk.CollectedArtifact{{Path: "artifacts/probe.json", Data: out}})
}

func vaultSuite(p vaultProbe) Suite {
	return Suite{
		Spec: componentsdk.CollectorSpec{Name: "probe"},
		Run:  p.run,
		Scenarios: []Scenario{{Name: "clean", Responses: []Response{{URL: demoHost + "/vaults", Body: `{"value":[` +
			`{"name":"a","properties":{"securitySettings":{"softDeleteSettings":{"softDeleteState":"Enabled"}}}},` +
			`{"name":"b","properties":{"securitySettings":{"softDeleteSettings":{"softDeleteState":"Disabled"}}}}]}`}}}},
		Populations: []Population{{Operation: "demo.vaults.list", List: "/value", Reason: "a subscription with no vaults has none to share"}},
		Waivers:     waiving(fieldProbeChecks...),
	}
}

func TestTheFieldFaultsCheckCatchesMissingSecuritySettingsReadAsOff(t *testing.T) {
	report := checkSuite(t, vaultSuite(vaultProbe{}))
	expectViolation(t, report, "field_faults", "artifacts/probe.json /vault_soft_delete_pct: changed from 50 to 0 without a gap")
	cases := map[string]bool{}
	for _, v := range violationsOf(report, "field_faults") {
		cases[v.Case] = true
	}
	leaf := "demo.vaults.list /value/*/properties/securitySettings/softDeleteSettings/softDeleteState "
	if !cases[leaf+"null"] || !cases[leaf+"dropped"] {
		t.Errorf("the state the collector reads should be reported: %v", cases)
	}
	for _, holder := range []string{"/value/*/properties", "/value/*/properties/securitySettings", "/value/*/properties/securitySettings/softDeleteSettings"} {
		if cases["demo.vaults.list "+holder+" dropped"] {
			t.Errorf("dropping %s moves only what dropping the state inside it moves, so the state's report covers it: %v", holder, cases)
		}
	}

	if got := violationsOf(checkSuite(t, vaultSuite(vaultProbe{fixed: true})), "field_faults"); len(got) != 0 {
		t.Errorf("a collector that leaves the share out with a gap: %+v", got)
	}

	declared := vaultSuite(vaultProbe{})
	declared.Omissions = []Omission{{Operation: "demo.vaults.list", Field: "/value/*/properties/securitySettings/softDeleteSettings/softDeleteState", Reason: "a vault without a state has soft delete off"}}
	if got := violationsOf(checkSuite(t, declared), "field_faults"); len(got) != 0 {
		t.Errorf("a declared state still explains the objects that hold it: %+v", got)
	}
}

// userProbe counts users and the share with MFA. An absent mfa counts as
// off. An answer with no user list leaves both values out.
type userProbe struct{}

func (userProbe) run(ctx componentsdk.CollectorContext) error {
	var users struct {
		Users *[]struct {
			Name string `json:"name"`
			MFA  bool   `json:"mfa"`
		} `json:"users"`
		Next string `json:"next"`
	}
	if err := getJSON(ctx, "demo.users.list", demoHost+"/users", &users); err != nil {
		return err
	}
	if users.Users == nil {
		for _, pointer := range []string{"/user_count", "/mfa_pct"} {
			componentsdk.Records(ctx).NotCollectedCode(componentsdk.Location{Path: "artifacts/probe.json", Pointer: pointer}, componentsdk.CodeInvalidResponse, "the answer has no user list")
		}
		return ctx.Emit([]componentsdk.CollectedArtifact{{Path: "artifacts/probe.json", Data: map[string]any{}}})
	}
	list := *users.Users
	out := map[string]any{"user_count": len(list)}
	if len(list) > 0 {
		mfa := 0
		for _, u := range list {
			if u.MFA {
				mfa++
			}
		}
		out["mfa_pct"] = mfa * 100 / len(list)
	}
	return ctx.Emit([]componentsdk.CollectedArtifact{{Path: "artifacts/probe.json", Data: out}})
}

func userSuite() Suite {
	return Suite{
		Spec: componentsdk.CollectorSpec{Name: "probe"},
		Run:  userProbe{}.run,
		Scenarios: []Scenario{{Name: "clean", Responses: []Response{{URL: demoHost + "/users",
			Body: `{"users":[{"name":"ann","mfa":true},{"name":"bo","mfa":false}],"next":""}`}}}},
		Waivers: waiving(fieldProbeChecks...),
	}
}

func TestPopulationsAndOmissionsDeclareRealAnswers(t *testing.T) {
	report := checkSuite(t, userSuite())
	expectViolation(t, report, "field_faults", "demo.users.list /users emptied")
	expectViolation(t, report, "field_faults", "user_count: changed from 2 to 0 without a gap")
	expectViolation(t, report, "field_faults", "unless an empty list means there are none, which Suite.Populations declares")
	expectViolation(t, report, "field_faults", "demo.users.list /users/*/mfa dropped")
	expectViolation(t, report, "field_faults", "unless the vendor leaves the field out to mean a value, which Suite.Omissions declares")
	for _, v := range violationsOf(report, "field_faults") {
		if strings.Contains(v.Case, "/users/*/name") || strings.Contains(v.Case, "/next") {
			t.Errorf("neither a string the collector does not judge nor a paging field should be reported: %+v", v)
		}
	}

	declared := userSuite()
	declared.Populations = []Population{{Operation: "demo.users.list", List: "/users", Reason: "an empty users list means there are no users"}}
	declared.Omissions = []Omission{{Operation: "demo.users.list", Field: "/users/*/mfa", Reason: "the vendor leaves mfa out for a user without MFA"}}
	if got := violationsOf(checkSuite(t, declared), "field_faults"); len(got) != 0 {
		t.Errorf("the declarations cover the emptied list, and the field set to null or dropped: %+v", got)
	}
	declared.Omissions[0].Field = "/users/*/*"
	if got := violationsOf(checkSuite(t, declared), "field_faults"); len(got) != 0 {
		t.Errorf("a * in an entry matches any key: %+v", got)
	}

	stale := userSuite()
	stale.Waivers = append(slices.Clone(stale.Waivers), waive("field_faults"))
	stale.Populations = []Population{{Operation: "demo.users.list", List: "/groups", Reason: "no groups"}}
	if got := violationsOf(checkSuite(t, stale), "field_faults"); len(got) != 0 {
		t.Errorf("a skipped check reports nothing: %+v", got)
	}
	stale.Waivers = waiving(fieldProbeChecks...)
	stale.Populations = append(stale.Populations, Population{Operation: "demo.users.list", List: "/users", Reason: "no users"})
	stale.Omissions = []Omission{{Operation: "demo.users.list", Field: "/users/*/name", Reason: "names are optional"}}
	report = checkSuite(t, stale)
	expectViolation(t, report, "field_faults", "Suite.Populations lists demo.users.list's /groups, which the check never emptied")
	expectViolation(t, report, "field_faults", "Suite.Omissions lists demo.users.list's /users/*/name, but no value moved without a gap when it was set to null or dropped; remove the entry")
}

func TestFieldDeclarationsMatchByPattern(t *testing.T) {
	tags := fieldDeclaration{list: "Omissions", op: "op", pattern: "/value/*/tags/*"}
	for label, want := range map[string]bool{"/value/*/tags/Owner": true, "/value/*/tags": false, "/value/*/tags/a/b": false, "/value/*/name": false} {
		if got := tags.covers("op", label, fieldDropped); got != want {
			t.Errorf("covers(%s) = %v", label, got)
		}
	}
	if tags.covers("op", "/value/*/tags/Owner", fieldEmptied) || tags.covers("other", "/value/*/tags/Owner", fieldNull) {
		t.Error("an Omissions entry covers null and dropped on its own operation")
	}
	root := fieldDeclaration{list: "Populations", op: "op", pattern: "/"}
	if !root.covers("op", "/", fieldEmptied) || root.covers("op", "/", fieldDropped) {
		t.Error("a Populations entry covers emptying only")
	}
}

func TestFieldDeclarationsNeedAReason(t *testing.T) {
	for name, s := range map[string]Suite{
		"no reason":   {Populations: []Population{{Operation: "op", List: "/value"}}},
		"no pattern":  {Omissions: []Omission{{Operation: "op", Reason: "r"}}},
		"not pointer": {Omissions: []Omission{{Operation: "op", Field: "value", Reason: "r"}}},
		"twice":       {Populations: []Population{{Operation: "op", List: "/value", Reason: "r"}, {Operation: "op", List: "/value", Reason: "s"}}},
	} {
		if err := checkFieldDeclarations(s); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	both := Suite{Populations: []Population{{Operation: "op", List: "/value", Reason: "r"}}, Omissions: []Omission{{Operation: "op", Field: "/value", Reason: "r"}}}
	if err := checkFieldDeclarations(both); err != nil {
		t.Errorf("a list may be both a population and a field the vendor leaves out: %v", err)
	}
}

// strictProbe fails the run when an answer lacks the field it reads.
type strictProbe struct{}

func (strictProbe) run(ctx componentsdk.CollectorContext) error {
	var score struct {
		Score *int `json:"score"`
	}
	if err := getJSON(ctx, "demo.score.get", demoHost+"/score", &score); err != nil {
		return err
	}
	if score.Score == nil {
		return errors.New("the score answer has no score")
	}
	return ctx.Emit([]componentsdk.CollectedArtifact{{Path: "artifacts/probe.json", Data: map[string]any{"score": *score.Score}}})
}

func TestAFieldFaultMayFailTheRunOnlyOnARequiredOperation(t *testing.T) {
	s := Suite{
		Spec:      componentsdk.CollectorSpec{Name: "probe"},
		Run:       strictProbe{}.run,
		Scenarios: []Scenario{{Name: "clean", Responses: []Response{{URL: demoHost + "/score", Body: `{"score":80}`}}}},
		Waivers:   waiving(fieldProbeChecks...),
	}
	expectViolation(t, checkSuite(t, s), "field_faults", "the run failed with exit")
	s.Required = []string{"demo.score.get"}
	if got := violationsOf(checkSuite(t, s), "field_faults"); len(got) != 0 {
		t.Errorf("a Required operation may fail the run: %+v", got)
	}
}

// xmlUserProbe counts the users with MFA in an AWS-style XML answer. A user
// without an MFA element counts as without MFA.
type xmlUserProbe struct{}

func (xmlUserProbe) run(ctx componentsdk.CollectorContext) error {
	client := componentsdk.NewHTTPClient(ctx, componentsdk.HTTPOptions{})
	req, err := http.NewRequestWithContext(componentsdk.WithOperation(ctx.Context(), componentsdk.Operation{Name: "demo.iam.ListUsers"}), http.MethodGet, demoHost+"/iam/users", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	var page struct {
		Users []struct {
			Name string `xml:"UserName"`
			MFA  bool   `xml:"MFA"`
		} `xml:"ListUsersResult>Users>member"`
	}
	if err := xml.NewDecoder(resp.Body).Decode(&page); err != nil {
		return componentsdk.ResponseError(resp, err)
	}
	mfa := 0
	for _, u := range page.Users {
		if u.MFA {
			mfa++
		}
	}
	return ctx.Emit([]componentsdk.CollectedArtifact{{Path: "artifacts/probe.json", Data: map[string]any{"mfa_user_count": mfa}}})
}

func TestTheFieldFaultsCheckChangesXMLElements(t *testing.T) {
	s := Suite{
		Spec: componentsdk.CollectorSpec{Name: "probe"},
		Run:  xmlUserProbe{}.run,
		Scenarios: []Scenario{{Name: "clean", Responses: []Response{{URL: demoHost + "/iam/users", Header: http.Header{"Content-Type": []string{"text/xml"}},
			Body: `<ListUsersResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><ListUsersResult><Users>` +
				`<member><UserName>ann</UserName><MFA>true</MFA></member><member><UserName>bo</UserName><MFA>false</MFA></member>` +
				`</Users><IsTruncated>false</IsTruncated></ListUsersResult></ListUsersResponse>`}}}},
		Waivers: waiving(fieldProbeChecks...),
	}
	report := checkSuite(t, s)
	expectViolation(t, report, "field_faults", "demo.iam.ListUsers /ListUsersResponse/ListUsersResult/Users/member/MFA dropped")
	expectViolation(t, report, "field_faults", "demo.iam.ListUsers /ListUsersResponse/ListUsersResult/Users emptied")
	for _, v := range violationsOf(report, "field_faults") {
		if strings.Contains(v.Case, "IsTruncated") || strings.HasSuffix(v.Case, " null") || strings.Contains(v.Case, "/member dropped") {
			t.Errorf("XML has no null, a paging element stays, and an item is not a field: %+v", v)
		}
	}
}

func TestChangeFieldInJSON(t *testing.T) {
	for _, c := range []struct {
		body, pattern, fault, want string
	}{
		{`{"value":[{"a":1,"b":2},{"a":3}]}`, "/value/*/a", fieldNull, `{"value":[{"a":null,"b":2},{"a":null}]}`},
		{`{"value":[{"a":1,"b":2},{"a":3}]}`, "/value/*/a", fieldDropped, `{"value":[{"b":2},{}]}`},
		{`{"value":[{"a":1}],"n":2}`, "/n", fieldDropped, `{"value":[{"a":1}]}`},
		{`{"value":[{"l":[1]},{"l":[]}]}`, "/value/*/l", fieldEmptied, `{"value":[{"l":[]},{"l":[]}]}`},
		{`[{"id":"a"},{"id":"b"}]`, "", fieldEmptied, `[]`},
		{`{"a~b":{"c/d":1}}`, "/a~0b/c~1d", fieldDropped, `{"a~b":{}}`},
	} {
		got, ok := changeField(c.body, fieldShape{pattern: c.pattern}, c.fault)
		if !ok || got != c.want {
			t.Errorf("%s %s of %s = %s, %v; want %s", c.pattern, c.fault, c.body, got, ok, c.want)
		}
	}
	for _, c := range []struct{ body, pattern, fault string }{
		{`{"a":null}`, "/a", fieldNull},
		{`{"a":1}`, "/b", fieldDropped},
		{`{"l":[]}`, "/l", fieldEmptied},
	} {
		if got, ok := changeField(c.body, fieldShape{pattern: c.pattern}, c.fault); ok {
			t.Errorf("%s %s of %s changed nothing, but reported %s", c.pattern, c.fault, c.body, got)
		}
	}
}

func TestJSONShapesFollowTheirParents(t *testing.T) {
	doc, _ := decodeJSON(`{"value":[{"props":{"tags":[{"k":"x"}],"on":true},"none":null}],"@odata.nextLink":"https://h/next"}`)
	shapes := map[string]fieldShape{}
	jsonShapes(doc, func(s fieldShape) { shapes[s.pattern] = s })
	for pattern, want := range map[string]string{
		"/value": "", "/value/*/props": "/value", "/value/*/props/tags": "/value/*/props",
		"/value/*/props/tags/*/k": "/value/*/props/tags", "/value/*/none": "/value",
	} {
		if s, ok := shapes[pattern]; !ok || s.parent != want {
			t.Errorf("%s: parent %q, %v; want %q", pattern, s.parent, ok, want)
		}
	}
	if _, ok := shapes["/value/*"]; ok {
		t.Error("a list item is not a field")
	}
	if !shapes["/value"].list || shapes["/value/*/none"].value || !shapes[""].value {
		t.Errorf("shapes = %+v", shapes)
	}
	if !pagingField(shapes["/@odata.nextLink"]) || pagingField(shapes["/value/*/props"]) {
		t.Error("pagingField should pick out only the next-page link")
	}
	for pattern, want := range map[string]bool{
		"/links/next": true, "/data/users/pageInfo/endCursor": true, "/meta/cursor/next": false, "/value/*/nextLink": false, "/NextToken": true,
	} {
		if got := pagingField(fieldShape{pattern: pattern}); got != want {
			t.Errorf("pagingField(%s) = %v", pattern, got)
		}
	}
	if !pagingField(fieldShape{pattern: "/R/Result/Marker", xml: true}) {
		t.Error("an XML paging element anywhere is a paging field")
	}
}

func TestXMLElementsAndTheirChanges(t *testing.T) {
	body := `<?xml version="1.0"?><R xmlns="urn:x"><Result><Users><member><Name>a</Name><Tags/></member><member><Name>b</Name></member></Users><Count>2</Count></Result></R>`
	shapes := map[string]fieldShape{}
	xmlShapes(body, func(s fieldShape) { shapes[s.pattern] = s })
	for pattern, want := range map[string]string{
		"/R/Result": "", "/R/Result/Users": "/R/Result", "/R/Result/Users/member/Name": "/R/Result/Users", "/R/Result/Count": "/R/Result",
	} {
		if s, ok := shapes[pattern]; !ok || s.parent != want {
			t.Errorf("%s: parent %q, %v; want %q", pattern, s.parent, ok, want)
		}
	}
	if _, ok := shapes["/R/Result/Users/member"]; ok {
		t.Error("a list item is not a field")
	}
	if !shapes["/R/Result/Users"].list || shapes["/R/Result"].list {
		t.Errorf("only Users is a list: %+v", shapes)
	}

	got, ok := changeXMLElement(body, "/R/Result/Users/member/Name", fieldDropped)
	if want := `<?xml version="1.0"?><R xmlns="urn:x"><Result><Users><member><Tags/></member><member></member></Users><Count>2</Count></Result></R>`; !ok || got != want {
		t.Errorf("dropped = %s", got)
	}
	got, ok = changeXMLElement(body, "/R/Result/Users", fieldEmptied)
	if want := `<?xml version="1.0"?><R xmlns="urn:x"><Result><Users></Users><Count>2</Count></Result></R>`; !ok || got != want {
		t.Errorf("emptied = %s", got)
	}
	got, ok = changeXMLElement(body, "/R/Result/Users/member/Tags", fieldDropped)
	if want := `<?xml version="1.0"?><R xmlns="urn:x"><Result><Users><member><Name>a</Name></member><member><Name>b</Name></member></Users><Count>2</Count></Result></R>`; !ok || got != want {
		t.Errorf("a self-closed element dropped = %s", got)
	}
	if _, ok := changeXMLElement(body, "/R/Result/Count", fieldEmptied); ok {
		t.Error("an element that is not a list cannot be emptied")
	}
	summary := map[string]bool{}
	xmlShapes(`<R><Result><SummaryMap><entry><key>Users</key><value>3</value></entry><entry><key>Roles</key><value>2</value></entry></SummaryMap></Result></R>`,
		func(s fieldShape) { summary[s.pattern] = s.list })
	if !summary["/R/Result/SummaryMap"] || len(summary) != 3 {
		t.Errorf("a Query map is a list, and its entries' keys and values are not fields on their own: %v", summary)
	}
	if _, ok := xmlSpans(`<R><open></R>`); ok {
		t.Error("xmlSpans should refuse text that is not XML")
	}
}

func TestFieldFaultProblems(t *testing.T) {
	artifact := func(data string) []componentsdk.EmittedArtifact {
		return []componentsdk.EmittedArtifact{{Path: "a.json", Data: json.RawMessage(data)}}
	}
	clean := artifact(`{"count":2,"on":true,"name":"x","list":[{"n":1},{"n":2}],"pct":null}`)
	problems := func(faulted []componentsdk.EmittedArtifact, gaps []componentsdk.Gap, nameOp bool) []string {
		return fieldFaultProblems(clean, faulted, gaps, "op", nameOp, ignoreSet{})
	}
	if got := problems(artifact(`{"count":2,"on":true,"name":"y","list":[{"n":2},{"n":1}],"pct":null}`), nil, false); len(got) != 0 {
		t.Errorf("a string that changed and a list in another order are not problems: %q", got)
	}
	got := problems(artifact(`{"count":0,"name":"x","list":[{"n":1}],"pct":5}`), nil, false)
	want := []string{
		"a.json /count: changed from 2 to 0 without a gap",
		"a.json /list/1/n: 2 left out without a gap",
		"a.json /on: true left out without a gap",
		"a.json /pct: 5 appeared without a gap",
	}
	if !slices.Equal(got, want) {
		t.Errorf("problems = %q\nwant %q", got, want)
	}
	gaps := []componentsdk.Gap{
		{Location: componentsdk.Location{Path: "a.json", Pointer: "/on"}},
		{Location: componentsdk.Location{Path: "a.json", Pointer: "/list"}, Operation: "op"},
	}
	if got := problems(artifact(`{"count":2,"name":"x","list":[{"n":1}],"pct":null}`), gaps, false); len(got) != 0 {
		t.Errorf("values left out under gaps: %q", got)
	}
	got = problems(artifact(`{"count":2,"name":"x","list":[{"n":1}],"pct":null}`), gaps, true)
	if !slices.Equal(got, []string{"a.json /on: true left out under a gap that names no operation"}) {
		t.Errorf("with nameOp, only the gap that names op covers: %q", got)
	}
	if got := problems(nil, nil, false); len(got) != 4 {
		t.Errorf("an artifact left out leaves out each judged value: %q", got)
	}

	rows := artifact(`{"users":[{"name":"ann","mfa":true},{"name":"bo","mfa":false}]}`)
	if got := fieldFaultProblems(rows, artifact(`{"users":[{"name":"","mfa":false},{"name":"","mfa":true}]}`), nil, "op", false, ignoreSet{}); len(got) != 0 {
		t.Errorf("rows whose names went blank may come in another order: %q", got)
	}
	got = fieldFaultProblems(rows, artifact(`{"users":[{"name":"ann","mfa":false},{"name":"bo","mfa":true}]}`), nil, "op", false, ignoreSet{})
	if len(got) != 2 {
		t.Errorf("a value that moved from one named row to another is a problem: %q", got)
	}
}
