package collectortest

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestThePagesCheckCatchesAListReadInPart(t *testing.T) {
	report := checkDemo(t, demo{firstPage: true})
	expectViolation(t, report, "pages", "the answer to demo.users.list for GET https://api.demo.test/users?page offers the next page https://api.demo.test/users?page, and the run never asked for it")
	expectViolation(t, report, "pages", "demo.users.list/next-page")

	for _, d := range []demo{{}, {linkPages: true}, {sdkLinks: true}} {
		if got := violationsOf(checkDemo(t, d), "pages"); len(got) != 0 {
			t.Errorf("a collector that reads every page, %+v: %+v", d, got)
		}
	}

	capped := demoSuite(demo{firstPage: true})
	capped.Waivers = append(capped.Waivers, waive(WaiveCapped, "demo.users.list"))
	if got := violationsOf(checkSuite(t, capped), "pages"); len(got) != 0 {
		t.Errorf("an operation waived as capped may leave pages unread: %+v", got)
	}
	skipped := demoSuite(demo{firstPage: true})
	skipped.Waivers = waiving("pages")
	if got := violationsOf(checkSuite(t, skipped), "pages"); len(got) != 0 {
		t.Errorf("a waiver turns the pages check off: %+v", got)
	}
}

func TestThePagesCheckAddsAPageInEachStyleAnOperationUses(t *testing.T) {
	// The demo follows the body's next field and would miss a page added
	// only by Link header. With both styles in use, the kit must add the page
	// to the body as well.
	s := demoSuite(demo{})
	s.Paged = []string{"demo.users.list"}
	if got := violationsOf(checkSuite(t, s), "pages"); len(got) != 0 {
		t.Errorf("the demo should read the added page from the body: %+v", got)
	}
	// Okta's answers put rel="self" on a Link line of its own. The kit adds
	// the next page on a second Link line.
	selfLinked := func(d demo) Suite {
		s := demoSuite(d)
		s.Scenarios = []Scenario{{Name: "clean", Responses: []Response{
			{URL: demoHost + "/me", Body: `{"org":"acme","mfa_enforced":true}`},
			{URL: demoHost + "/users?page=1", Header: http.Header{"Link": {`<` + demoHost + `/users?page=1>; rel="self"`}}, Body: `{"users":[{"mfa":true}],"total":1}`},
			{URL: demoHost + "/score", Body: `{"value":72}`},
		}}}
		return s
	}
	// The demo follows the body, so it never reads a page linked by header.
	expectViolation(t, checkSuite(t, selfLinked(demo{})), "pages", "demo.users.list/next-page")
	// A collector that reads only the first Link line also misses it. Okta's
	// collector did this, and every list stopped at its first page.
	expectViolation(t, checkSuite(t, selfLinked(demo{linkPages: true})), "pages", "demo.users.list/next-page")
	if got := violationsOf(checkSuite(t, selfLinked(demo{sdkLinks: true})), "pages"); len(got) != 0 {
		t.Errorf("a collector that follows componentsdk.NextLink reads the added page: %+v", got)
	}
}

func TestPageOffersInAnswers(t *testing.T) {
	base, _ := url.Parse("https://api.example.test/v1/items?limit=50")
	cases := []struct {
		name, body string
		want       []string
	}{
		{"OData", `{"@odata.context":"x","value":[],"@odata.nextLink":"https://graph.example.test/v1.0/users?$skiptoken=X1"}`, []string{"https://graph.example.test/v1.0/users?$skiptoken=X1"}},
		{"a relative next", `{"items":[],"next":"/v1/items?page=2"}`, []string{"https://api.example.test/v1/items?page=2"}},
		{"a next that is a token", `{"items":[],"next":"abc123"}`, []string{"token abc123"}},
		{"AWS JSON", `{"Findings":[],"NextToken":"tok/en+=="}`, []string{"token tok/en+=="}},
		{"JSON:API", `{"data":[],"links":{"self":"/v1/items","next":"https://api.example.test/v1/items?page[cursor]=c2"}}`, []string{"https://api.example.test/v1/items?page[cursor]=c2"}},
		{"HAL", `{"_links":{"next":{"href":"https://api.example.test/v1/items?p=2"}}}`, []string{"https://api.example.test/v1/items?p=2"}},
		{"Slack", `{"members":[],"response_metadata":{"next_cursor":"dXNlcjpVMEc5"}}`, []string{"token dXNlcjpVMEc5"}},
		{"GraphQL", `{"data":{"organization":{"repositories":{"nodes":[],"pageInfo":{"hasNextPage":true,"endCursor":"Y3Vyc29y"}}}}}`, []string{"token Y3Vyc29y"}},
		{"GraphQL, last page", `{"data":{"repos":{"pageInfo":{"hasNextPage":false,"endCursor":"Y3Vyc29y"}}}}`, nil},
		{"an empty next", `{"items":[],"next":"","NextToken":null}`, nil},
		{"AWS XML", `<ListRolesResponse><ListRolesResult><Roles/><IsTruncated>true</IsTruncated><NextToken>xml-tok</NextToken></ListRolesResult></ListRolesResponse>`, []string{"token xml-tok"}},
	}
	for _, tc := range cases {
		var log pageLog
		resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Request: &http.Request{Method: http.MethodGet, URL: base}}
		log.answer("op", resp, tc.body)
		var got []string
		for _, o := range log.offers {
			if o.link != nil {
				got = append(got, o.link.String())
			} else {
				got = append(got, "token "+o.token)
			}
		}
		if strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("%s: offers %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestATokenIsFollowedWhereverTheRequestCarriesIt(t *testing.T) {
	u := func(s string) *url.URL { v, _ := url.Parse(s); return v }
	token := "tok/en+=="
	cases := []struct {
		name string
		a    asked
		want bool
	}{
		{"in the query, encoded", asked{url: u("https://api.example.test/items?NextToken=tok%2Fen%2B%3D%3D")}, true},
		{"in a JSON body", asked{url: u("https://api.example.test/"), body: []byte(`{"NextToken":"tok/en+=="}`)}, true},
		{"in a form body", asked{url: u("https://api.example.test/"), body: []byte(`Action=ListRoles&NextToken=tok%2Fen%2B%3D%3D`)}, true},
		{"nowhere", asked{url: u("https://api.example.test/items"), body: []byte(`{"NextToken":"other"}`)}, false},
	}
	for _, tc := range cases {
		if got := carries(tc.a, token); got != tc.want {
			t.Errorf("%s: carries = %v, want %v", tc.name, got, tc.want)
		}
	}
	link := u("https://API.example.test/items?page=2")
	if !sameTarget(link, u("https://api.example.test/items?per_page=100&page=2")) {
		t.Error("a request may add its own query parameters to the link it follows")
	}
	if sameTarget(link, u("https://api.example.test/items?page=3")) {
		t.Error("another page is not the one offered")
	}
}
