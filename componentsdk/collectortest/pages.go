package collectortest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/locktivity/epack/componentsdk"
)

// The pages check reports a collector that does not read each list to its
// end. In every scenario's run, the collector must ask for each next page an
// answer offers. The check also adds a next page to the last answer of each
// paged operation, and the run must ask for that page too. An operation in
// Suite.Capped is exempt.

// pageLog keeps a run's requests and the next pages its answers offered.
type pageLog struct {
	asks   []asked
	offers []offer
	styles map[string]*pageStyle
}

// asked is one request: its operation, URL, and body.
type asked struct {
	op   string
	url  *url.URL
	body []byte
}

// offer is a next page an answer offered. It is a URL to ask for, or a
// token a later request must carry. after is the number of requests made
// before the offer. Only a request made after those can follow it.
type offer struct {
	op    string
	from  string
	after int
	link  *url.URL
	token string
}

// pageStyle records how an operation's answers page. They page by Link
// header, by body fields that hold the next page's URL, or by both.
type pageStyle struct {
	link bool
	keys []string
}

func (l *pageLog) ask(op string, u *url.URL, body []byte) {
	l.asks = append(l.asks, asked{op: op, url: u, body: body})
}

// answer records the next pages resp offers and how its operation pages.
func (l *pageLog) answer(op string, resp *http.Response, body string) {
	from := ""
	if resp.Request != nil {
		from = resp.Request.Method + " " + describeURL(resp.Request.URL)
	}
	var base *url.URL
	if resp.Request != nil {
		base = resp.Request.URL
	}
	if l.styles == nil {
		l.styles = map[string]*pageStyle{}
	}
	style := l.styles[op]
	if style == nil {
		style = &pageStyle{}
		l.styles[op] = style
	}
	if len(resp.Header.Values("Link")) > 0 {
		style.link = true
	}
	if resp.StatusCode/100 != 2 {
		return
	}
	add := func(o offer) {
		o.op, o.from, o.after = op, from, len(l.asks)
		l.offers = append(l.offers, o)
	}
	if next, ok := componentsdk.NextLink(resp); ok {
		add(offer{link: next})
	}
	// An answer that is not JSON may be XML, such as AWS's, or text with a
	// token in it.
	doc, isJSON := parseAnswer(body).(jsonDoc)
	if !isJSON {
		for _, m := range xmlTokens.FindAllStringSubmatch(body, -1) {
			if token := strings.TrimSpace(m[2]); token != "" {
				add(offer{token: token})
			}
		}
		return
	}
	for _, key := range topLinkKeys(doc.v) {
		if !slices.Contains(style.keys, key) {
			style.keys = append(style.keys, key)
		}
	}
	for _, o := range bodyOffers(doc.v, base) {
		add(o)
	}
}

// unread lists, by operation, the next pages that no later request asked
// for. It skips the operations in capped.
func (l *pageLog) unread(capped []string) []string {
	var out []string
	reported := map[string]bool{}
	for _, o := range l.offers {
		if reported[o.op] || containsString(capped, o.op) || l.followed(o) {
			continue
		}
		reported[o.op] = true
		out = append(out, fmt.Sprintf("the answer to %s for %s offers the next page %s, and the run never asked for it. "+
			"Read every page, or list %s in Suite.Capped and leave a partial gap where the list stops", opLabel(o.op), o.from, o.describe(), opLabel(o.op)))
	}
	return out
}

func opLabel(op string) string {
	if op == "" {
		return "an unnamed operation"
	}
	return op
}

func (o offer) describe() string {
	if o.link != nil {
		return describeURL(o.link)
	}
	token := o.token
	if len(token) > 24 {
		token = token[:24] + "..."
	}
	return fmt.Sprintf("token %q", token)
}

// followed reports whether a request after the offer asked for its page.
func (l *pageLog) followed(o offer) bool {
	for _, a := range l.asks[o.after:] {
		if o.link != nil && sameTarget(o.link, a.url) {
			return true
		}
		if o.token != "" && carries(a, o.token) {
			return true
		}
	}
	return false
}

// sameTarget reports whether got asks for link. got must have the same
// scheme, host, and path as link, and every query parameter link has. The
// request may add parameters of its own, such as a page size.
func sameTarget(link, got *url.URL) bool {
	if got == nil || !strings.EqualFold(link.Scheme, got.Scheme) || !strings.EqualFold(link.Host, got.Host) || link.EscapedPath() != got.EscapedPath() {
		return false
	}
	have := got.Query()
	for key, values := range link.Query() {
		for _, v := range values {
			if !slices.Contains(have[key], v) {
				return false
			}
		}
	}
	return true
}

// carries reports whether a request holds token in its query or its body.
// The token may appear as sent, URL-decoded, or escaped as a JSON string.
func carries(a asked, token string) bool {
	if a.url != nil {
		if strings.Contains(a.url.RawQuery, token) {
			return true
		}
		if q, err := url.QueryUnescape(a.url.RawQuery); err == nil && strings.Contains(q, token) {
			return true
		}
	}
	if len(a.body) == 0 {
		return false
	}
	body := string(a.body)
	if strings.Contains(body, token) {
		return true
	}
	if unescaped, err := url.QueryUnescape(body); err == nil && strings.Contains(unescaped, token) {
		return true
	}
	quoted, _ := json.Marshal(token)
	return strings.Contains(body, string(quoted[1:len(quoted)-1]))
}

// Body fields that offer the next page, by lowercase name. A link field
// holds a URL, or a token when its value is not a URL.
var (
	linkFields  = []string{"next", "nextlink", "@odata.nextlink", "next_link", "next_url", "nexturl", "next_page_url", "nextpageurl"}
	tokenFields = []string{"nexttoken", "next_token", "nextmarker", "next_marker", "nextpagetoken", "next_page_token",
		"nextcursor", "next_cursor", "nextcontinuationtoken", "next_continuation_token", "continuationtoken", "continuation_token"}
	// pagingObjects are objects that hold paging fields one level down, such
	// as JSON:API's links, HAL's _links, and Slack's response_metadata.
	pagingObjects = []string{"links", "_links", "pagination", "paging", "meta", "response_metadata", "page_info", "pageinfo"}
	// xmlTokens finds the next-page tokens of XML answers, such as AWS's.
	xmlTokens = regexp.MustCompile(`<(NextToken|NextMarker|NextContinuationToken|NextPageToken)>([^<]*)</`)
)

// topLinkKeys lists the top-level fields of doc that hold, or could hold,
// the next page's URL. It returns each name as doc spells it, so the pages
// check can fill the field in. For an OData collection it adds
// @odata.nextLink.
func topLinkKeys(doc any) []string {
	obj, ok := doc.(map[string]any)
	if !ok {
		return nil
	}
	var keys []string
	for key, v := range obj {
		if !slices.Contains(linkFields, strings.ToLower(key)) {
			continue
		}
		if s, isString := v.(string); v == nil || (isString && (s == "" || isLink(s))) {
			keys = append(keys, key)
		}
	}
	if _, ok := obj["@odata.context"]; ok {
		if _, isList := obj["value"].([]any); isList && !slices.ContainsFunc(keys, func(k string) bool { return strings.EqualFold(k, "@odata.nextLink") }) {
			keys = append(keys, "@odata.nextLink")
		}
	}
	slices.Sort(keys)
	return keys
}

// bodyOffers finds the next pages a JSON answer offers. It looks at paging
// fields at the top level or in a paging object. It also looks at GraphQL
// connections anywhere in the answer whose pageInfo has hasNextPage set.
func bodyOffers(doc any, base *url.URL) []offer {
	var out []offer
	obj, ok := doc.(map[string]any)
	if ok {
		out = append(out, fieldOffers(obj, base)...)
		for key, v := range obj {
			if inner, isObj := v.(map[string]any); isObj && slices.Contains(pagingObjects, strings.ToLower(key)) {
				out = append(out, fieldOffers(inner, base)...)
			}
		}
	}
	eachJSON(doc, func(_ place, v any) {
		n, isObj := v.(map[string]any)
		if !isObj {
			return
		}
		if more, _ := n["hasNextPage"].(bool); more {
			if cursor, _ := n["endCursor"].(string); cursor != "" {
				out = append(out, offer{token: cursor})
			}
		}
	})
	return out
}

func fieldOffers(obj map[string]any, base *url.URL) []offer {
	var out []offer
	for key, v := range obj {
		name := strings.ToLower(key)
		if href, isObj := v.(map[string]any); isObj && slices.Contains(linkFields, name) {
			v = href["href"]
		}
		s, _ := v.(string)
		if s == "" {
			continue
		}
		switch {
		case slices.Contains(linkFields, name) && isLink(s):
			u, err := url.Parse(s)
			if err != nil {
				continue
			}
			if base != nil {
				u = base.ResolveReference(u)
			}
			out = append(out, offer{link: u})
		case slices.Contains(linkFields, name), slices.Contains(tokenFields, name):
			out = append(out, offer{token: s})
		}
	}
	return out
}

func isLink(s string) bool {
	return strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "/")
}

// pageParam is the query parameter that marks the page the kit adds to an
// operation's last answer.
const pageParam = "collectortest_page"

// pager adds a next page to the last answer of one operation, in each style
// the operation's answers page by. A request for the added page gets the
// last page's original body again. That body offers no further page.
type pager struct {
	op    string
	last  int
	style pageStyle
	base  http.RoundTripper

	mu     sync.Mutex
	seen   int
	added  *url.URL
	body   []byte
	header http.Header
	asked  bool
}

func (p *pager) install(n *network) {
	p.base = n.transport
	n.transport = p
}

func (p *pager) RoundTrip(req *http.Request) (*http.Response, error) {
	p.mu.Lock()
	added := p.added
	p.mu.Unlock()
	if added != nil && req.URL.Query().Get(pageParam) != "" && req.URL.EscapedPath() == added.EscapedPath() {
		p.mu.Lock()
		p.asked = true
		body, header := p.body, p.header.Clone()
		p.mu.Unlock()
		header.Del("Link")
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: header,
			Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)), Request: req}, nil
	}
	resp, err := p.base.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return resp, err
	}
	op, _ := componentsdk.OperationOf(req.Context())
	if op.Name != p.op || componentsdk.AttemptOf(req.Context()) > 1 {
		return resp, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.seen++
	if p.seen != p.last || p.added != nil {
		return resp, nil
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return resp, nil
	}
	next := *req.URL
	q := next.Query()
	q.Set(pageParam, "2")
	next.RawQuery = q.Encode()
	offered := body
	if len(p.style.keys) > 0 {
		if doc, ok := decodeJSON(string(body)); ok {
			if obj, isObj := doc.(map[string]any); isObj {
				for _, key := range p.style.keys {
					obj[key] = next.String()
				}
				if b, err := json.Marshal(obj); err == nil {
					offered = b
				}
			}
		}
	}
	if !p.style.link && bytes.Equal(offered, body) {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return resp, nil
	}
	p.header = resp.Header.Clone()
	if p.style.link {
		resp.Header.Add("Link", fmt.Sprintf(`<%s>; rel="next"`, next.String()))
	}
	p.added, p.body = &next, body
	resp.Body = io.NopCloser(bytes.NewReader(offered))
	resp.ContentLength = int64(len(offered))
	return resp, nil
}

// checkPageFaults adds a next page to the last answer of each paged
// operation in turn. It checks that the run asks for that page.
func (k *kit) checkPageFaults() {
	styles := k.baselineNet.replay.pageStyles()
	p := perturber{k: k, check: "pages"}
	for _, op := range k.pickOps(opPick{exempt: k.suite.Capped}) {
		style := styles[op.Name]
		if containsString(k.suite.Paged, op.Name) {
			style.link = true
		}
		if !style.link && len(style.keys) == 0 {
			continue
		}
		pg := &pager{op: op.Name, last: op.Calls, style: style}
		label := op.Name + "/next-page"
		run, ok := p.run(perturbation{label: label, op: op.Name, wrap: pg.install, reached: func() bool { return pg.added != nil }})
		switch {
		case !ok:
		case run.failed():
			k.violate("pages", label, "adding a next page to %s's last answer failed the run with %s", op.Name, failureLabel(run.res))
		case !pg.asked:
			k.violate("pages", label, "the kit added the next page %s to %s's last answer, and the run never asked for it. "+
				"Read every page, or list %s in Suite.Capped and leave a partial gap where the list stops", describeURL(pg.added), op.Name, op.Name)
		}
	}
}

// pageStyles returns how each operation's answers paged in the run.
func (r *Replay) pageStyles() map[string]pageStyle {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]pageStyle{}
	for op, s := range r.pages.styles {
		out[op] = pageStyle{link: s.link, keys: append([]string(nil), s.keys...)}
	}
	return out
}

// unreadPages lists the next pages the run never asked for.
func (r *Replay) unreadPages(capped []string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pages.unread(capped)
}
