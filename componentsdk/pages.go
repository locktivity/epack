package componentsdk

import (
	"net/http"
	"net/url"
	"strings"
)

// NextLink returns the URL of the rel="next" link in resp's Link headers,
// as RFC 8288 defines them. It resolves the URL against the requested URL.
// It reads every Link header line and every link on each line, because
// vendors differ. Okta sends self and next on separate lines, and GitHub
// lists first, prev, next, and last on one line. A rel holds space-separated
// relation types, which are matched without regard to case. A quoted
// parameter may hold commas and semicolons. A next link with results="false"
// offers no page, since Sentry marks its last page that way.
func NextLink(resp *http.Response) (*url.URL, bool) {
	if resp == nil {
		return nil, false
	}
	for _, line := range resp.Header.Values("Link") {
		for _, l := range parseLinks(line) {
			if !l.has("next") || strings.EqualFold(l.results, "false") {
				continue
			}
			u, err := url.Parse(l.target)
			if err != nil {
				continue
			}
			if resp.Request != nil && resp.Request.URL != nil {
				u = resp.Request.URL.ResolveReference(u)
			}
			return u, true
		}
	}
	return nil, false
}

// link is one link in a Link header. It holds the target and the relation
// types.
type link struct {
	target string
	rels   []string
	// results is the link's results parameter, which Sentry sets to "false"
	// on the next link of its last page.
	results string
}

func (l link) has(rel string) bool {
	for _, r := range l.rels {
		if strings.EqualFold(r, rel) {
			return true
		}
	}
	return false
}

// parseLinks reads the links in one Link header value. Each is a URI
// reference in angle brackets followed by parameters after semicolons.
// parseLinks uses only the first rel parameter of a link, as RFC 8288
// requires.
func parseLinks(s string) []link {
	var out []link
	i := 0
	for i < len(s) {
		lt := strings.IndexByte(s[i:], '<')
		if lt < 0 {
			break
		}
		i += lt + 1
		gt := strings.IndexByte(s[i:], '>')
		if gt < 0 {
			break
		}
		l := link{target: strings.TrimSpace(s[i : i+gt])}
		i += gt + 1
		sawRel := false
		for i < len(s) && s[i] != ',' {
			if s[i] != ';' {
				i++
				continue
			}
			i++
			name, value, next := linkParam(s, i)
			i = next
			switch {
			case strings.EqualFold(name, "rel") && !sawRel:
				sawRel = true
				l.rels = strings.Fields(value)
			case strings.EqualFold(name, "results"):
				l.results = value
			}
		}
		out = append(out, l)
	}
	return out
}

// linkParam reads one parameter that starts at i, just after its semicolon.
// It returns the name, the value with any quoting removed, and the index
// where the parameter ends.
func linkParam(s string, i int) (name, value string, end int) {
	start := i
	for i < len(s) && s[i] != '=' && s[i] != ';' && s[i] != ',' {
		i++
	}
	name = strings.TrimSpace(s[start:i])
	if i >= len(s) || s[i] != '=' {
		return name, "", i
	}
	i++
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	if i < len(s) && s[i] == '"' {
		var b strings.Builder
		for i++; i < len(s) && s[i] != '"'; i++ {
			if s[i] == '\\' && i+1 < len(s) {
				i++
			}
			b.WriteByte(s[i])
		}
		if i < len(s) {
			i++
		}
		return name, b.String(), i
	}
	start = i
	for i < len(s) && s[i] != ';' && s[i] != ',' {
		i++
	}
	return name, strings.TrimSpace(s[start:i]), i
}
