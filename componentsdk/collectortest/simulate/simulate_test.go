package simulate

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
	"github.com/locktivity/epack/componentsdk/collectortest/roster"
)

// follow reads a list the way a client of each paging style does, through
// the replay the pager's responses make, and returns the items it read.
func follow(t *testing.T, responses []collectortest.Response, first string, next func(resp *http.Response, body []byte, page []any) string, items func(body []byte) []any) []any {
	t.Helper()
	replay, err := collectortest.NewReplay(collectortest.Scenario{Responses: responses})
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: replay}
	var out []any
	for at := first; at != ""; {
		resp, err := client.Get(at)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: %d %s", at, resp.StatusCode, body)
		}
		page := items(body)
		out = append(out, page...)
		at = next(resp, body, page)
		if len(out) > 1000 {
			t.Fatal("the pages never end")
		}
	}
	if unmatched := replay.Unmatched(); len(unmatched) > 0 {
		t.Errorf("no response for %v", unmatched)
	}
	return out
}

func numbers(n int) []any {
	out := make([]any, n)
	for i := range n {
		out[i] = map[string]any{"id": fmt.Sprintf("item%02d", i)}
	}
	return out
}

func field(body []byte, path string) any {
	var doc any
	_ = json.Unmarshal(body, &doc)
	for _, part := range strings.Split(path, ".") {
		m, _ := doc.(map[string]any)
		doc = m[part]
	}
	return doc
}

func list(body []byte, path string) []any {
	if path == "" {
		var out []any
		_ = json.Unmarshal(body, &out)
		return out
	}
	out, _ := field(body, path).([]any)
	return out
}

func TestPagersAnswerEveryPageAClientAsksFor(t *testing.T) {
	const base = "https://api.example.test/v1/users"
	styles := []struct {
		name  string
		pager Pager
		first string
		next  func(first string) func(*http.Response, []byte, []any) string
		items string
	}{
		{"next link", NextLink{Items: "value", Next: "@odata.nextLink", Token: "$skiptoken", Size: 3, Envelope: map[string]any{"@odata.context": "users"}}, base,
			func(string) func(*http.Response, []byte, []any) string {
				return func(_ *http.Response, body []byte, _ []any) string {
					var page map[string]any
					_ = json.Unmarshal(body, &page)
					s, _ := page["@odata.nextLink"].(string)
					return s
				}
			}, "value"},
		{"nested next link", NextLink{Items: "value", Next: "_links/next/href", Token: "after", Size: 3,
			Envelope: map[string]any{"_links": map[string]any{"self": map[string]any{"href": base}}}}, base + "?limit=3",
			func(string) func(*http.Response, []byte, []any) string {
				return func(_ *http.Response, body []byte, _ []any) string {
					s, _ := field(body, "_links.next.href").(string)
					return s
				}
			}, "value"},
		{"link header", LinkHeader{Cursor: "after", Size: 3, CursorOf: func(item any) string { return item.(map[string]any)["id"].(string) }}, base + "?limit=3",
			func(string) func(*http.Response, []byte, []any) string {
				return func(resp *http.Response, _ []byte, _ []any) string {
					if u, ok := componentsdk.NextLink(resp); ok {
						return u.String()
					}
					return ""
				}
			}, ""},
		{"cursor", Cursor{Items: "members", Next: "response_metadata/next_cursor", Param: "cursor", Size: 3}, base + "?limit=3",
			func(first string) func(*http.Response, []byte, []any) string {
				return func(_ *http.Response, body []byte, _ []any) string {
					if c, _ := field(body, "response_metadata.next_cursor").(string); c != "" {
						return first + "&cursor=" + c
					}
					return ""
				}
			}, "members"},
		{"offset", Offset{Param: "offset", Size: 3}, base,
			func(first string) func(*http.Response, []byte, []any) string {
				read := 0
				return func(_ *http.Response, _ []byte, page []any) string {
					read += len(page)
					if len(page) < 3 {
						return ""
					}
					return fmt.Sprintf("%s?offset=%d", first, read)
				}
			}, ""},
		{"page number", Offset{Items: "data", Param: "page", Size: 3, First: 1, ByPage: true}, base,
			func(first string) func(*http.Response, []byte, []any) string {
				n := 1
				return func(_ *http.Response, _ []byte, page []any) string {
					n++
					if len(page) < 3 {
						return ""
					}
					return fmt.Sprintf("%s?page=%d", first, n)
				}
			}, "data"},
	}
	for _, style := range styles {
		for _, n := range []int{0, 1, 3, 7} {
			t.Run(fmt.Sprintf("%s/%d items", style.name, n), func(t *testing.T) {
				items := numbers(n)
				got := follow(t, style.pager.Pages(style.first, items, 0), style.first, style.next(style.first), func(b []byte) []any { return list(b, style.items) })
				if len(got) != n {
					t.Errorf("read %d items, want %d", len(got), n)
				}
			})
		}
	}
}

func TestPageSizeOverride(t *testing.T) {
	pages := NextLink{Items: "value", Next: "next", Token: "skip", Size: 100}.Pages("https://api.example.test/x", numbers(5), 2)
	if len(pages) != 3 {
		t.Errorf("%d pages at size 2 for 5 items, want 3", len(pages))
	}
	if one := (LinkHeader{}).Pages("https://api.example.test/y", numbers(5), 2); len(one) != 1 {
		t.Errorf("a LinkHeader with no cursor answered %d pages, want 1", len(one))
	}
	if pages[0].URL != "https://api.example.test/x?" {
		t.Errorf("first page URL %q; a URL with no query must end in ? so the next pages don't match it", pages[0].URL)
	}
}

func TestTenantRefusesPermissionBeforePlan(t *testing.T) {
	tenant := &Tenant{
		Granted: []string{"users.read"},
		Plans:   []string{"free", "premium"},
		Refuse: func(r Refusal) collectortest.Response {
			if r.Plan != "" {
				return collectortest.Response{Status: http.StatusPaymentRequired, Body: JSON(map[string]any{"needs": r.Plan})}
			}
			return collectortest.Response{Status: http.StatusForbidden, Body: JSON(map[string]any{"missing": r.Permissions[0]})}
		},
	}
	tenant.Get("users.get", "https://api.example.test/users", Needs([]string{"users.read", "directory.read"}), map[string]any{"ok": true})
	tenant.Get("logs.list", "https://api.example.test/logs", Need{AnyOf: [][]string{{"logs.read"}}, Plan: "premium"}, "[]")
	tenant.List("risky.list", "https://api.example.test/risky", Need{Plan: "premium"}, LinkHeader{Cursor: "after"}, nil)
	got := tenant.Responses()
	want := []struct {
		status int
		body   string
	}{{0, `{"ok":true}`}, {http.StatusForbidden, `{"missing":"logs.read"}`}, {http.StatusPaymentRequired, `{"needs":"premium"}`}}
	for i, w := range want {
		if got[i].Status != w.status || got[i].Body != w.body || got[i].Method != http.MethodGet || got[i].Operation == "" {
			t.Errorf("response %d: %d %s %s, want %d %s", i, got[i].Status, got[i].Method, got[i].Body, w.status, w.body)
		}
	}
	tenant.Plan = "premium"
	if _, refused := tenant.Refused(Need{Plan: "premium"}); refused {
		t.Error("a premium tenant is refused a premium call")
	}
}

func TestIDsAreStableAndShaped(t *testing.T) {
	first, again, group := UUID("user", "alice"), UUID("user", "alice"), UUID("group", "alice")
	if first != again || first == group {
		t.Error("UUID is not stable per kind and key")
	}
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-a[0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(UUID("user", "alice")) {
		t.Errorf("UUID %s is not shaped like a random UUID", UUID("user", "alice"))
	}
	if id := Base62("00u", 17, "user", "alice"); !regexp.MustCompile(`^00u[0-9A-Za-z]{17}$`).MatchString(id) {
		t.Errorf("Base62 %s is not 00u and 17 letters and digits", id)
	}
}

func TestJudgeListsNewAndStaleDifferences(t *testing.T) {
	rows := []Row{
		{Pointer: "/a", Want: 3, Got: float64(3), Written: true},
		{Pointer: "/b", Want: 3, Got: float64(4), Written: true},
		{Pointer: "/c", Want: true, Gap: "not_read"},
		{Pointer: "/d", Want: 50, Got: float64(50), Written: true},
		{Pointer: "/e", Want: nil, Got: nil, Written: true},
		{Pointer: "/f", Want: false},
		{Pointer: "/g", Want: false, Got: true, Written: true},
		{Pointer: "/h", Want: 2, Gap: "not_read"},
		{Pointer: "/i", Want: []string{"a", "b"}, Got: []any{"a", "b"}, Written: true},
		{Pointer: "/j", Want: []any{"a"}, Got: []any{"a"}, Written: true},
		{Pointer: "/k", Want: map[string]int{"linux": 2}, Got: map[string]any{"linux": float64(2)}, Written: true},
	}
	listed := Same(Gap, "not read", "/c").With(Same(Bug, "fixed now", "/d"))
	standing := Same(Unwritten, "never written", "/e", "/f", "/g", "/h")
	table, failures := judge(rows, listed, standing)
	want := []string{
		"/b: derived 3, collector 4",
		"/d: listed as bug (fixed now), but the collector now reports the derived 50",
		"/g: derived false, collector true",
		"/h: derived 2, collector absent, not_read",
	}
	if !slices.Equal(failures, want) {
		t.Errorf("failures:\n%s\nwant:\n%s", strings.Join(failures, "\n"), strings.Join(want, "\n"))
	}
	for _, mark := range []string{"NEW", "gap", "unwritten", "absent, not_read", "absent, no gap"} {
		if !strings.Contains(table, mark) {
			t.Errorf("the table has no %q:\n%s", mark, table)
		}
	}
}

func TestUncoveredFieldsNameTheSchemasFields(t *testing.T) {
	artifact := []byte(`{"schema_version": "1.0.0", "collected_at": "2026-11-11T00:00:00Z",
	  "endpoints": [
	    {"host": "a.example", "port": 443, "reachable": true, "tls": {"protocol_support": {"tls_1_3": true}}},
	    {"host": "b.example", "port": 443, "reachable": true, "tls": {"protocol_support": {"tls_1_3": false}}}],
	  "summary": {"total_endpoints": 2, "reachable_count": 2}}`)
	values := map[string]any{
		"/schema_version": "1.0.0", "/summary/total_endpoints": 2,
		"/endpoints/0/host": "a.example", "/endpoints/0/port": 443, "/endpoints/0/reachable": true,
		"/endpoints/1/host": "b.example", "/endpoints/1/port": 443, "/endpoints/1/reachable": true,
	}
	got, err := uncoveredFields(Artifact{Schema: roster.TLS, Prefix: "tls:"}, artifact, values)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"tls:/endpoints/*/tls/protocol_support/tls_1_3", "tls:/summary/reachable_count"}
	if !slices.Equal(got, want) {
		t.Errorf("uncoveredFields = %v, want %v", got, want)
	}
}

type errorList []string

func (e *errorList) Errorf(format string, args ...any) { *e = append(*e, fmt.Sprintf(format, args...)) }

func TestCheckComparedListsNewAndStaleFields(t *testing.T) {
	listed := map[string]string{"/a": "the roster has no audit log", "/b": "the roster has no backups"}
	met := map[string]bool{}
	var got errorList
	checkCompared(&got, []string{"/a", "/c"}, listed, met)
	staleUncompared(&got, listed, met)
	want := errorList{
		"/c: the collector writes it, and the roster gives no value to compare it with",
		"listed as uncompared (the roster has no backups), but every scenario now compares it: /b",
	}
	if !slices.Equal(got, want) {
		t.Errorf("failures:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestExplainsNeedsEverySetting(t *testing.T) {
	together := []Together{{Settings: []string{"a=1", "b=2"}, Differences: Same(Gap, "both", "/x")}}
	if !explains(together, []string{"a=1", "b=2", "c=3"}, "/x") {
		t.Error("a row with both settings is not explained")
	}
	if explains(together, []string{"a=1"}, "/x") || explains(together, []string{"a=1", "b=2"}, "/y") {
		t.Error("a row with one setting, or another pointer, is explained")
	}
	matched := []Together{{Match: func(c []string) bool { return Any(c, "a=1", "a=2") && Any(c, "b=2") }, Differences: Same(Bug, "either a", "/x")}}
	if !explains(matched, []string{"a=2", "b=2"}, "/x") || explains(matched, []string{"a=3", "b=2"}, "/x") {
		t.Error("Match does not decide which rows the rule explains")
	}
}

func TestNumberRules(t *testing.T) {
	before := map[string]any{"s:/n": float64(5), "s:/m": float64(5), "s:/k": "x"}
	after := map[string]any{"s:/n": float64(4), "s:/m": nil, "s:/k": "y", "s:/new": true}
	if got := NeverLower(before, after, "s:/n", "s:/m", "s:/k"); !slices.Equal(got, []string{"s:/n fell from 5 to 4", "s:/m was 5 and is null"}) {
		t.Errorf("NeverLower: %v", got)
	}
	if got := NeverHigher(before, after, "s:/n"); len(got) != 0 {
		t.Errorf("NeverHigher: %v", got)
	}
	if got := Unchanged(before, after, func(k string) bool { return k != "s:/m" }); !slices.Equal(got, []string{"s:/k was x and is y", "s:/n was 5 and is 4", "s:/new was absent and is true"}) {
		t.Errorf("Unchanged: %v", got)
	}
}

func TestLookupAndFlatten(t *testing.T) {
	var doc any
	_ = json.Unmarshal([]byte(`{"collected_at":"now","a":{"b":[{"c":1},{"c":null}]},"d":true}`), &doc)
	if v, ok := lookup(doc, "/a/b/1/c"); !ok || v != nil {
		t.Errorf("lookup /a/b/1/c = %v, %v", v, ok)
	}
	if _, ok := lookup(doc, "/a/b/2/c"); ok {
		t.Error("lookup found an element past the list")
	}
	out := map[string]any{}
	flatten(doc, "idp-posture:", out)
	if len(out) != 3 || out["idp-posture:/a/b/0/c"] != float64(1) || out["idp-posture:/d"] != true {
		t.Errorf("flatten: %v", out)
	}
	if ShortName(roster.IDPPosture) != "idp-posture" {
		t.Errorf("ShortName(%s) = %s", roster.IDPPosture, ShortName(roster.IDPPosture))
	}
}

func TestSetExtraLeavesTheOriginal(t *testing.T) {
	a := roster.Account{Key: "alice", Extra: roster.Extra{"tier": []byte(`"gold"`)}}
	b := a
	SetExtra(&b.Extra, "tier", "silver")
	var tier string
	Extra(a.Extra, "tier", &tier)
	if tier != "gold" {
		t.Errorf("the original's extra changed to %s", tier)
	}
	Extra(b.Extra, "tier", &tier)
	if tier != "silver" {
		t.Errorf("the copy's extra is %s", tier)
	}
}

// recording is a sandbox recording of two lists: users, where only some
// have a lastLogin and every one has a profile, and an empty group list,
// and one refusal.
const recording = `{
  "name": "sandbox",
  "recorded_at": "2026-11-01T00:00:00Z",
  "responses": [
    {"operation": "users.list", "url": "https://api.example.test/users?limit=2", "status": 200,
     "body": [{"id": "u1", "status": "ACTIVE", "lastLogin": "2026-10-31T00:00:00Z", "profile": {"login": "a@example.com"}},
              {"id": "u2", "status": "STAGED", "lastLogin": null, "profile": {"login": "b@example.com", "userType": "Service"}}]},
    {"operation": "groups.list", "url": "https://api.example.test/groups", "status": 200, "body": {"value": [], "next": null}},
    {"operation": "logs.list", "url": "https://api.example.test/logs", "status": 403, "body": {"errorCode": "E0000006"}}
  ]
}`

func loadRecording(t *testing.T) *Recorded {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sandbox.json")
	if err := os.WriteFile(path, []byte(recording), 0o600); err != nil {
		t.Fatal(err)
	}
	rec, err := LoadRecorded(path)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestRecordedTemplates(t *testing.T) {
	rec := loadRecording(t)
	staged := rec.Like("users.list", "", func(m map[string]any) bool { return m["status"] == "STAGED" })
	if staged["id"] != "u2" {
		t.Errorf("Like picked %v, want the staged user", staged["id"])
	}
	Set(staged, "profile/login", "c@example.com")
	if again := rec.Like("users.list", "", func(m map[string]any) bool { return m["status"] == "STAGED" }); again["profile"].(map[string]any)["login"] != "b@example.com" {
		t.Error("changing a copy changed the recording")
	}
	if first := rec.Like("users.list", "", func(map[string]any) bool { return false }); first["id"] != "u1" {
		t.Errorf("Like with no match picked %v, want the first item", first["id"])
	}
	none := func(map[string]any) bool { return false }
	if second := rec.Like("users.list", "", none, func(m map[string]any) bool { return m["id"] == "u2" }); second["id"] != "u2" {
		t.Errorf("Like picked %v, want the second pick's u2", second["id"])
	}
	if !slices.Equal(rec.Operations(), []string{"groups.list", "users.list"}) {
		t.Errorf("Operations %v", rec.Operations())
	}
}

func TestRecordedShapes(t *testing.T) {
	rec := loadRecording(t)
	user := func(change func(map[string]any)) string {
		u := rec.Like("users.list", "")
		change(u)
		return JSON([]any{u})
	}
	answers := []collectortest.Response{
		{Operation: "users.list", URL: "https://api.example.test/users", Body: user(func(u map[string]any) { u["lastLogin"] = nil })},
		{Operation: "users.list", URL: "https://api.example.test/users", Body: user(func(u map[string]any) { Drop(u, "profile/login") })},
		{Operation: "users.list", URL: "https://api.example.test/users", Body: user(func(u map[string]any) { u["lastLogin"] = 5 })},
		{Operation: "users.list", URL: "https://api.example.test/users", Body: user(func(u map[string]any) { Set(u, "credentials/password", map[string]any{}) })},
		{Operation: "users.list", URL: "https://api.example.test/users", Body: user(func(u map[string]any) { Drop(u, "profile/userType") })},
		{Operation: "groups.list", URL: "https://api.example.test/groups", Body: `{"value": [{"id": "g1"}], "next": null}`},
		{Operation: "apps.list", URL: "https://api.example.test/apps", Body: `[]`},
		{Operation: "users.list", URL: "https://api.example.test/users", Status: http.StatusTooManyRequests, Body: `{}`},
		{Operation: "users.list", URL: "https://api.example.test/users", Status: http.StatusForbidden, Body: `{"errorCode": "E0000006", "errorSummary": "no"}`},
		{URL: "https://api.example.test/nameless", Body: `{}`},
	}
	var got []string
	for _, d := range rec.Check(answers) {
		got = append(got, d.String())
	}
	want := []string{
		"apps.list: unrecorded operation",
		"groups.list value[]: unrecorded field (recorded nothing, simulated object)",
		"https://api.example.test/nameless: names no operation",
		"users.list [].credentials: unrecorded field (recorded nothing, simulated object)",
		"users.list [].lastLogin: type (recorded null or string, simulated number)",
		"users.list [].profile.login: missing field (recorded string, simulated nothing)",
		"users.list errorSummary: unrecorded field (recorded nothing, simulated string)",
		"users.list: unrecorded status 429",
	}
	if !slices.Equal(got, want) {
		t.Errorf("Check found:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
