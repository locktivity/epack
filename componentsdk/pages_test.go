package componentsdk

import (
	"net/http"
	"net/url"
	"testing"
)

func TestNextLink(t *testing.T) {
	requested, _ := url.Parse("https://acme.okta.test/api/v1/users?limit=200")
	cases := []struct {
		name  string
		lines []string
		want  string
	}{
		{"self and next on separate lines, as Okta sends them",
			[]string{`<https://acme.okta.test/api/v1/users?limit=200>; rel="self"`, `<https://acme.okta.test/api/v1/users?after=00u9&limit=200>; rel="next"`},
			"https://acme.okta.test/api/v1/users?after=00u9&limit=200"},
		{"several links on one line, as GitHub sends them",
			[]string{`<https://api.github.test/orgs/acme/repos?page=1>; rel="prev", <https://api.github.test/orgs/acme/repos?page=3>; rel="next", <https://api.github.test/orgs/acme/repos?page=9>; rel="last"`},
			"https://api.github.test/orgs/acme/repos?page=3"},
		{"next among several relation types in mixed case",
			[]string{`<https://acme.okta.test/p2>; REL="Next Prefetch"`},
			"https://acme.okta.test/p2"},
		{"a quoted parameter that holds a comma and a semicolon",
			[]string{`<https://acme.okta.test/p1>; title="first, then; more"; rel="prev", <https://acme.okta.test/p3>; rel=next`},
			"https://acme.okta.test/p3"},
		{"a relative target",
			[]string{`</api/v1/users?after=00u9>; rel="next"`},
			"https://acme.okta.test/api/v1/users?after=00u9"},
		{"only the first rel counts",
			[]string{`<https://acme.okta.test/p1>; rel="self"; rel="next"`},
			""},
		{"Sentry's next link on a page with more results",
			[]string{`<https://sentry.test/api/0/organizations/acme/members/?cursor=0:0:1>; rel="previous"; results="false"; cursor="0:0:1", <https://sentry.test/api/0/organizations/acme/members/?cursor=0:100:0>; rel="next"; results="true"; cursor="0:100:0"`},
			"https://sentry.test/api/0/organizations/acme/members/?cursor=0:100:0"},
		{"Sentry's next link on its last page",
			[]string{`<https://sentry.test/api/0/organizations/acme/members/?cursor=0:100:1>; rel="previous"; results="true"; cursor="0:100:1", <https://sentry.test/api/0/organizations/acme/members/?cursor=0:200:0>; rel="next"; results="false"; cursor="0:200:0"`},
			""},
		{"no next page", []string{`<https://acme.okta.test/p1>; rel="self"`}, ""},
		{"no Link header", nil, ""},
	}
	for _, tc := range cases {
		resp := &http.Response{Header: http.Header{}, Request: &http.Request{URL: requested}}
		for _, line := range tc.lines {
			resp.Header.Add("Link", line)
		}
		got, ok := NextLink(resp)
		switch {
		case tc.want == "" && ok:
			t.Errorf("%s: got %s, want no next page", tc.name, got)
		case tc.want != "" && (!ok || got.String() != tc.want):
			t.Errorf("%s: got %v %v, want %s", tc.name, got, ok, tc.want)
		}
	}
	if _, ok := NextLink(nil); ok {
		t.Error("NextLink(nil) returned a next page")
	}
}
