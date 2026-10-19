package collectortest

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ScrubRules adds a collector's own rules to the scrubbing Record applies.
type ScrubRules struct {
	// Literals maps values to replace, such as an organization's name or a
	// domain, to their replacements. Each matches regardless of case, as
	// written and as URLs and JSON encode it, longest first.
	Literals map[string]string

	// Patterns rewrite their matches after the literals, in order. A
	// replacement can refer to the pattern's groups, as in
	// regexp.Regexp.ReplaceAllString.
	Patterns []ScrubPattern

	// Keep lists values the built-in rules leave as they are, such as a
	// well-known role ID the collector compares against. A kept value the
	// scrub check flags still fails the recording.
	Keep []string

	// Identifiers maps values that identify the tenant, such as its domain,
	// its organization's login, or its account ID, to the stable fakes that
	// replace them. Each is replaced as a literal is, except that a value of
	// digits is replaced only where no digit adjoins it, and the built-in
	// rules leave the fakes as they are. The scrub check fails the recording
	// if one remains, in any case and in any encoding it looks for secrets
	// in. EnvIdentifiers makes them from environment variables.
	Identifiers map[string]string
}

// ScrubPattern replaces each match of Pattern with Replace.
type ScrubPattern struct {
	Pattern *regexp.Regexp
	Replace string
}

// redacted stands in for a credential.
const redacted = "REDACTED"

// minSecretLength is the length below which a secret's value is too short to
// tell from ordinary text, as for the kit's canaries.
const minSecretLength = 6

// maxDepth bounds how deep scrubbing and the scrub check look into base64
// that decodes to text.
const maxDepth = 3

var (
	privateKeyBlock  = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?s:.*?)(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)`)
	privateKeyMarker = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)
	signedJWT        = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{8,}`)
	bearerToken      = regexp.MustCompile(`(?i)\b(bearer\s+)([A-Za-z0-9._~+/-]{16,}=*)`)
	sswsToken        = regexp.MustCompile(`\b(SSWS\s+)([A-Za-z0-9_-]{20,})`)
	githubToken      = regexp.MustCompile(`\b(?:gh[oprsu]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{22,})`)
	slackToken       = regexp.MustCompile(`\bxox[a-z]*(?:\.xox[a-z])?-[A-Za-z0-9-]{10,}`)
	awsKeyID         = regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`)

	jsonField = regexp.MustCompile(`"([^"\\]{1,80})"(\s*:\s*)"((?:[^"\\]|\\.)*)"`)
	xmlField  = regexp.MustCompile(`<([A-Za-z_][\w.:-]{0,80})(\s[^<>]*)?>([^<]+)</([A-Za-z_][\w.:-]{0,80})>`)
	formField = regexp.MustCompile(`(^|[?&;\s"'])([A-Za-z0-9_.%-]{1,80})=([^&;#\s"'<>]+)`)

	emailAddress = regexp.MustCompile(`[A-Za-z0-9._+-]+(?:@|%40)[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)
	fakeEmail    = regexp.MustCompile(`^user[0-9]+@example\.com$`)
	guidPattern  = regexp.MustCompile(`\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b`)
	guidHead     = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-$`)
	fakeGUID     = regexp.MustCompile(`^00000000-0000-(?:0000-0000-0{12}|4000-8000-[0-9]{12})$`)
	digitRun     = regexp.MustCompile(`[0-9]+`)
	ipv4Run      = regexp.MustCompile(`[0-9]{1,3}(?:\.[0-9]{1,3}){3}`)
	ipv6Run      = regexp.MustCompile(`[0-9A-Fa-f:]{3,}`)
	ec2Host      = regexp.MustCompile(`\bec2-([0-9]{1,3})-([0-9]{1,3})-([0-9]{1,3})-([0-9]{1,3})\b`)

	// longRun matches base64 wrapped over lines, with escaped or real line
	// breaks, and single runs of base64, base64url, or hex characters, which
	// may carry URL-escaped +, /, and =.
	longRun = regexp.MustCompile(`[A-Za-z0-9+/]{16,}(?:(?:\\r)?\\n|\r?\n)(?:[A-Za-z0-9+/]{4,}(?:(?:\\r)?\\n|\r?\n))*[A-Za-z0-9+/]*={0,2}` +
		`|(?:[A-Za-z0-9+/_-]|%2[BbFf])+(?:=|%3[Dd]){0,2}`)
)

var (
	reservedIPv4 = cidrs("0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4")
	globalIPv6   = cidrs("2000::/3")[0]
	docIPv6      = cidrs("2001:db8::/32")[0]
)

func cidrs(blocks ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(blocks))
	for _, b := range blocks {
		_, n, err := net.ParseCIDR(b)
		if err != nil {
			panic(err)
		}
		out = append(out, n)
	}
	return out
}

// scrubber rewrites what identifies a tenant or signs in to it. It keeps one
// mapping for a whole recording, so a value replaced in a response is
// replaced the same way in the later requests that carry it, and a replay
// still matches them. Fakes are numbered in the order their values first
// appear, so the same recording always scrubs the same way.
type scrubber struct {
	secretForms []string
	secrets     *regexp.Regexp
	literals    *regexp.Regexp
	literalTo   map[string]string
	literalKind map[string]string
	numbers     []identifier
	patterns    []ScrubPattern
	keep        map[string]bool
	fakes       map[string]map[string]string
	replaced    map[string]map[string]bool
}

func newScrubber(secrets map[string]string, rules ScrubRules) *scrubber {
	s := &scrubber{
		patterns: rules.Patterns,
		keep:     map[string]bool{},
		fakes:    map[string]map[string]string{},
		replaced: map[string]map[string]bool{},
	}
	for _, v := range rules.Keep {
		s.keep[v] = true
	}
	seen := map[string]bool{}
	for _, v := range secrets {
		if len(v) < minSecretLength {
			continue
		}
		for _, form := range encodings(v) {
			if !seen[form] {
				seen[form] = true
				s.secretForms = append(s.secretForms, form)
			}
		}
	}
	s.secrets = alternation(s.secretForms, false)
	s.literalTo, s.literalKind = map[string]string{}, map[string]string{}
	var forms []string
	literal := func(value, replacement, kind string) {
		from, to := encodings(value), encodings(replacement)
		for i, form := range from {
			key := strings.ToLower(form)
			if _, ok := s.literalTo[key]; !ok {
				s.literalTo[key], s.literalKind[key] = to[i], kind
				forms = append(forms, form)
			}
		}
	}
	for _, id := range sortedKeys(rules.Identifiers) {
		fake := rules.Identifiers[id]
		s.keep[fake] = true
		switch {
		case id == "":
		case isDigits(id):
			s.numbers = append(s.numbers, identifier{value: id, fake: fake})
		default:
			literal(id, fake, "identifier")
		}
	}
	sort.SliceStable(s.numbers, func(i, j int) bool { return len(s.numbers[i].value) > len(s.numbers[j].value) })
	for _, lit := range sortedKeys(rules.Literals) {
		if lit != "" {
			literal(lit, rules.Literals[lit], "literal")
		}
	}
	s.literals = alternation(forms, true)
	return s
}

// identifier is a tenant identifier of digits and its fake.
type identifier struct{ value, fake string }

// replaceNumbers replaces each identifier of digits where no digit adjoins
// it, so a value inside a longer number stays.
func (s *scrubber) replaceNumbers(in string) string {
	for _, id := range s.numbers {
		cur := in
		in = replaceIndexed(cur, numberSpans(cur, id.value), func(a, b int) (string, bool) {
			s.note("identifier", id.value)
			return id.fake, true
		})
	}
	return in
}

// numberSpans returns where digits occur in s with no digit adjoining them.
func numberSpans(s, digits string) [][]int {
	var spans [][]int
	for from := 0; ; {
		i := strings.Index(s[from:], digits)
		if i < 0 {
			return spans
		}
		a, b := from+i, from+i+len(digits)
		if (a == 0 || !isDigit(s[a-1])) && (b == len(s) || !isDigit(s[b])) {
			spans = append(spans, []int{a, b})
		}
		from = a + 1
	}
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return s != ""
}

// EnvIdentifiers returns ScrubRules.Identifiers for the environment
// variables whose names start with prefix, such as those a record test reads
// its tenant's domain and IDs from. A variable fakes names gets that fake.
// Any other gets a stable fake made from its name: as many digits as its
// value has when the value is digits, and otherwise its name in lowercase
// with hyphens, such as sandbox-region for SANDBOX_REGION. A value shorter
// than six characters that fakes does not name is left out, since it cannot
// be told from ordinary text.
func EnvIdentifiers(prefix string, fakes map[string]string) map[string]string {
	env := map[string]string{}
	for _, entry := range os.Environ() {
		if name, value, _ := strings.Cut(entry, "="); strings.HasPrefix(name, prefix) && value != "" {
			env[name] = value
		}
	}
	out := map[string]string{}
	for _, name := range sortedKeys(env) {
		value := env[name]
		fake, ok := fakes[name]
		switch {
		case ok:
		case len(value) < minSecretLength:
			continue
		case isDigits(value):
			fake = fakeDigits(name, len(value))
		default:
			fake = strings.ReplaceAll(strings.ToLower(name), "_", "-")
		}
		out[value] = fake
	}
	return out
}

// fakeDigits returns n digits derived from seed, the first not 0.
func fakeDigits(seed string, n int) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(seed))
	digits := strconv.FormatUint(h.Sum64(), 10)
	for len(digits) < n {
		digits += digits
	}
	b := []byte(digits[:n])
	if b[0] == '0' {
		b[0] = '1'
	}
	return string(b)
}

// encodings returns s as written, then as a URL query, a URL path, and a
// JSON string write it, with and without HTML and slash escapes. Each
// position holds the same encoding for every s, so a literal's forms pair up
// with its replacement's.
func encodings(s string) []string {
	plain := jsonText(s, false)
	return []string{s, url.QueryEscape(s), url.PathEscape(s), plain, jsonText(s, true), strings.ReplaceAll(plain, "/", `\/`)}
}

func jsonText(s string, escapeHTML bool) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(escapeHTML)
	_ = enc.Encode(s)
	out := strings.TrimSuffix(b.String(), "\n")
	return out[1 : len(out)-1]
}

// alternation matches any of forms, regardless of case when fold is set,
// preferring the longest at each position.
func alternation(forms []string, fold bool) *regexp.Regexp {
	if len(forms) == 0 {
		return nil
	}
	sorted := append([]string(nil), forms...)
	sort.Slice(sorted, func(i, j int) bool {
		if len(sorted[i]) != len(sorted[j]) {
			return len(sorted[i]) > len(sorted[j])
		}
		return sorted[i] < sorted[j]
	})
	quoted := make([]string, len(sorted))
	for i, f := range sorted {
		quoted[i] = regexp.QuoteMeta(f)
	}
	pattern := strings.Join(quoted, "|")
	if fold {
		pattern = "(?i)" + pattern
	}
	return regexp.MustCompile(pattern)
}

func (s *scrubber) note(kind, value string) {
	if s.replaced[kind] == nil {
		s.replaced[kind] = map[string]bool{}
	}
	s.replaced[kind][value] = true
}

// fake returns the fake for value of kind, making the nth when value is the
// nth of its kind to need one.
func (s *scrubber) fake(kind, value string, nth func(n int) string) string {
	byValue := s.fakes[kind]
	if byValue == nil {
		byValue = map[string]string{}
		s.fakes[kind] = byValue
	}
	if f, ok := byValue[value]; ok {
		return f
	}
	f := nth(len(byValue) + 1)
	byValue[value] = f
	s.note(kind, value)
	return f
}

// counts returns how many distinct values each kind of rule replaced.
func (s *scrubber) counts() map[string]int {
	out := map[string]int{}
	for kind, values := range s.replaced {
		out[kind] = len(values)
	}
	return out
}

func (s *scrubber) text(in string) string { return s.textAt(in, 0) }

// textAt scrubs in. Rules that remove credentials run first, then the
// collector's own, then those that replace identifiers with fakes, and last
// the one for long tokens, which looks inside base64 that decodes to text.
func (s *scrubber) textAt(in string, depth int) string {
	if in == "" {
		return in
	}
	out := privateKeyBlock.ReplaceAllStringFunc(in, func(m string) string {
		s.note("token", m)
		return redacted
	})
	if s.secrets != nil {
		out = s.secrets.ReplaceAllStringFunc(out, func(m string) string {
			s.note("secret", m)
			return redacted
		})
	}
	if s.literals != nil {
		out = s.literals.ReplaceAllStringFunc(out, func(m string) string {
			key := strings.ToLower(m)
			s.note(s.literalKind[key], key)
			return s.literalTo[key]
		})
	}
	out = s.replaceNumbers(out)
	for _, p := range s.patterns {
		out = s.pattern(p, out)
	}
	out = s.tokens(out)
	out = s.fields(out)
	out = s.emails(out)
	out = guidPattern.ReplaceAllStringFunc(out, s.guid)
	out = s.accounts(out)
	out = s.ips(out)
	return rewriteRuns(out, depth, scrubRuns{s})
}

func (s *scrubber) pattern(p ScrubPattern, in string) string {
	if p.Pattern == nil {
		return in
	}
	matches := p.Pattern.FindAllStringSubmatchIndex(in, -1)
	if matches == nil {
		return in
	}
	var b strings.Builder
	last := 0
	for _, m := range matches {
		b.WriteString(in[last:m[0]])
		b.Write(p.Pattern.ExpandString(nil, p.Replace, in, m))
		s.note("pattern", in[m[0]:m[1]])
		last = m[1]
	}
	b.WriteString(in[last:])
	return b.String()
}

func (s *scrubber) redact(m string) string {
	s.note("token", m)
	return redacted
}

func (s *scrubber) tokens(in string) string {
	out := signedJWT.ReplaceAllStringFunc(in, s.redact)
	out = replaceMatches(bearerToken, out, func(g []string) string {
		if g[2] == redacted || !hasDigit(g[2]) {
			return g[0]
		}
		s.note("token", g[2])
		return g[1] + redacted
	})
	out = replaceMatches(sswsToken, out, func(g []string) string {
		if g[2] == redacted {
			return g[0]
		}
		s.note("token", g[2])
		return g[1] + redacted
	})
	out = githubToken.ReplaceAllStringFunc(out, s.redact)
	out = slackToken.ReplaceAllStringFunc(out, s.redact)
	return awsKeyID.ReplaceAllStringFunc(out, func(m string) string {
		if s.keep[m] || strings.Contains(m, "EXAMPLE") {
			return m
		}
		return s.fake("aws_key_id", m, func(n int) string { return fmt.Sprintf("%sEXAMPLE%09d", m[:4], n) })
	})
}

// fields redacts the values of credential fields: JSON members, XML elements,
// and form or query parameters.
func (s *scrubber) fields(in string) string {
	out := replaceMatches(jsonField, in, func(g []string) string {
		if g[3] == "" || g[3] == redacted || !credentialField(g[1]) {
			return g[0]
		}
		s.note("token", g[3])
		return `"` + g[1] + `"` + g[2] + `"` + redacted + `"`
	})
	out = replaceMatches(xmlField, out, func(g []string) string {
		if g[1] != g[4] || strings.TrimSpace(g[3]) == "" || g[3] == redacted || !credentialField(localName(g[1])) {
			return g[0]
		}
		s.note("token", g[3])
		return "<" + g[1] + g[2] + ">" + redacted + "</" + g[4] + ">"
	})
	return replaceMatches(formField, out, func(g []string) string {
		name, err := url.QueryUnescape(g[2])
		if err != nil || g[3] == redacted || !credentialParam(name) {
			return g[0]
		}
		s.note("token", g[3])
		return g[1] + g[2] + "=" + redacted
	})
}

func (s *scrubber) emails(in string) string {
	return emailAddress.ReplaceAllStringFunc(in, func(m string) string {
		sep := "@"
		at := strings.Index(m, "@")
		if at < 0 {
			sep = "%40"
			at = strings.Index(m, sep)
		}
		key := strings.ToLower(m[:at] + "@" + m[at+len(sep):])
		if s.keep[m] || s.keep[key] || fakeEmail.MatchString(key) {
			return m
		}
		f := s.fake("email", key, func(n int) string { return fmt.Sprintf("user%d@example.com", n) })
		return strings.Replace(f, "@", sep, 1)
	})
}

func (s *scrubber) guid(m string) string {
	key := strings.ToLower(m)
	if s.keep[m] || s.keep[key] || fakeGUID.MatchString(key) {
		return m
	}
	return s.fake("guid", key, func(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) })
}

// accounts replaces 12-digit numbers, such as AWS account IDs alone or in
// ARNs, but not where they are part of a longer number, a decimal, a word,
// or a GUID.
func (s *scrubber) accounts(in string) string {
	return replaceIndexed(in, digitRun.FindAllStringIndex(in, -1), func(a, b int) (string, bool) {
		run := in[a:b]
		if len(run) != 12 || !accountBoundary(in, a, b) || s.keep[run] {
			return "", false
		}
		return s.fake("aws_account", run, func(n int) string { return strconv.Itoa(123456789011 + n) }), true
	})
}

func accountBoundary(s string, a, b int) bool {
	if !startBoundary(s, a) || a >= 24 && guidHead.MatchString(s[a-24:a]) {
		return false
	}
	return endBoundary(s, b)
}

// endBoundary reports whether a number ending at b ends there: no word
// character follows, and no dot with a digit after it.
func endBoundary(s string, b int) bool {
	if b >= len(s) {
		return true
	}
	c := s[b]
	if isWordByte(c) {
		return false
	}
	return c != '.' || b+1 >= len(s) || !isDigit(s[b+1])
}

// ips replaces public addresses with addresses from the documentation
// ranges. Private, loopback, link-local, and other special addresses stay,
// since a collector can tell them apart: 0.0.0.0/0 means the whole internet.
func (s *scrubber) ips(in string) string {
	dashed := replaceMatches(ec2Host, in, func(g []string) string {
		ip := net.ParseIP(strings.Join(g[1:], "."))
		if ip == nil || !publicIP(ip) || s.keep[ip.String()] {
			return g[0]
		}
		return "ec2-" + strings.ReplaceAll(s.fake("ip", ip.String(), fakeIPv4), ".", "-")
	})
	v4 := replaceIndexed(dashed, ipv4Run.FindAllStringIndex(dashed, -1), func(a, b int) (string, bool) {
		if !startBoundary(dashed, a) || !endBoundary(dashed, b) {
			return "", false
		}
		ip := net.ParseIP(dashed[a:b])
		if ip == nil || !publicIP(ip) || s.keep[dashed[a:b]] {
			return "", false
		}
		return s.fake("ip", ip.String(), fakeIPv4), true
	})
	return replaceIndexed(v4, ipv6Run.FindAllStringIndex(v4, -1), func(a, b int) (string, bool) {
		run := v4[a:b]
		if strings.Count(run, ":") < 2 || !startBoundary(v4, a) || b < len(v4) && (isWordByte(v4[b]) || v4[b] == '.') {
			return "", false
		}
		ip := net.ParseIP(run)
		if ip == nil || ip.To4() != nil || !publicIP(ip) || s.keep[run] {
			return "", false
		}
		return s.fake("ip", ip.String(), func(n int) string { return fmt.Sprintf("2001:db8::%x", n) }), true
	})
}

// startBoundary reports whether an address starting at a starts there: no
// word character or dot comes before it.
func startBoundary(s string, a int) bool {
	return a == 0 || !isWordByte(s[a-1]) && s[a-1] != '.'
}

func publicIP(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		if !v4.IsGlobalUnicast() || v4.IsPrivate() {
			return false
		}
		for _, n := range reservedIPv4 {
			if n.Contains(v4) {
				return false
			}
		}
		return true
	}
	return globalIPv6.Contains(ip) && !docIPv6.Contains(ip)
}

// fakeIPv4 returns the nth fake address: TEST-NET-1, -2, and -3, then the
// benchmarking range.
func fakeIPv4(n int) string {
	switch {
	case n <= 254:
		return fmt.Sprintf("192.0.2.%d", n)
	case n <= 508:
		return fmt.Sprintf("198.51.100.%d", n-254)
	case n <= 762:
		return fmt.Sprintf("203.0.113.%d", n-508)
	}
	n -= 762
	return fmt.Sprintf("198.%d.%d.%d", 18+n/65536%2, n/256%256, n%256)
}

// scrubRuns replaces tokens with fakes and scrubs base64 that decodes to
// text.
type scrubRuns struct{ s *scrubber }

func (r scrubRuns) token(run string) string {
	if r.s.keep[run] {
		return run
	}
	return r.s.fake("token", run, func(n int) string { return fmt.Sprintf("scrubbed-token-%d", n) })
}

func (r scrubRuns) text(decoded string, depth int) string {
	if depth >= maxDepth {
		return decoded
	}
	return r.s.textAt(decoded, depth+1)
}

// url scrubs a request's URL. A URL without a query ends in ?, so its
// response answers only requests without one. A query that carries a
// credential is left out, so the response answers whatever query the replay
// sends, since a replay signs in with other values.
func (s *scrubber) url(u *url.URL) string {
	out := *u
	out.User = nil
	out.Fragment, out.RawFragment = "", ""
	out.Host = s.text(strings.ToLower(u.Host))
	out.Path = s.text(u.Path)
	out.RawPath = ""
	query := u.Query()
	switch {
	case len(query) == 0:
		out.RawQuery, out.ForceQuery = "", true
	case s.credentialQuery(query):
		out.RawQuery, out.ForceQuery = "", false
	default:
		scrubbed := url.Values{}
		for _, key := range sortedKeys(query) {
			k := s.text(key)
			for _, v := range query[key] {
				scrubbed[k] = append(scrubbed[k], s.text(v))
			}
		}
		out.RawQuery, out.ForceQuery = scrubbed.Encode(), false
	}
	return out.String()
}

func (s *scrubber) credentialQuery(query url.Values) bool {
	for key, values := range query {
		if credentialParam(key) {
			return true
		}
		for _, v := range values {
			if s.carriesCredential(v) {
				return true
			}
		}
	}
	return false
}

// carriesCredential reports whether text holds a secret's value or a token
// the scrubber would redact.
func (s *scrubber) carriesCredential(text string) bool {
	for _, form := range s.secretForms {
		if strings.Contains(text, form) {
			return true
		}
	}
	for _, re := range []*regexp.Regexp{privateKeyMarker, signedJWT, sswsToken, githubToken, slackToken} {
		if re.MatchString(text) {
			return true
		}
	}
	for _, g := range bearerToken.FindAllStringSubmatch(text, -1) {
		if hasDigit(g[2]) {
			return true
		}
	}
	return false
}

// requestBody scrubs a JSON or form request body into the JSON a response's
// RequestBody holds. Members that carry a credential are left out rather
// than redacted, so the replay, which signs in with other values, still
// matches. It returns "" for a body the replay cannot match on.
func (s *scrubber) requestBody(contentType string, body []byte) (string, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return "", nil
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil || dec.More() {
		if !strings.HasPrefix(strings.ToLower(contentType), "application/x-www-form-urlencoded") {
			return "", nil
		}
		form, err := url.ParseQuery(string(body))
		if err != nil {
			return "", nil
		}
		doc = formObject(form)
	}
	if obj, ok := doc.(map[string]any); ok {
		doc = s.withoutCredentials(obj)
	} else if s.carriesCredential(string(body)) {
		return "", nil
	}
	raw, err := marshalJSON(doc)
	if err != nil {
		return "", err
	}
	out := s.text(string(raw))
	if !json.Valid([]byte(out)) {
		return "", fmt.Errorf("scrubbing a request body left it unreadable as JSON; check the ScrubRules replacements")
	}
	return out, nil
}

// formObject turns form fields into the object the replay matches a form
// body as: each field a string, or a list of strings when repeated.
func formObject(form url.Values) map[string]any {
	doc := make(map[string]any, len(form))
	for key, values := range form {
		if len(values) == 1 {
			doc[key] = values[0]
			continue
		}
		list := make([]any, len(values))
		for i, v := range values {
			list[i] = v
		}
		doc[key] = list
	}
	return doc
}

func (s *scrubber) withoutCredentials(obj map[string]any) map[string]any {
	out := make(map[string]any, len(obj))
	for key, value := range obj {
		if credentialField(key) {
			continue
		}
		if child, ok := value.(map[string]any); ok {
			out[key] = s.withoutCredentials(child)
			continue
		}
		raw, err := marshalJSON(value)
		if err != nil || s.carriesCredential(string(raw)) {
			continue
		}
		out[key] = value
	}
	return out
}

// headers keeps the response headers keep allows, with credentials redacted
// and the rest scrubbed.
func (s *scrubber) headers(h http.Header, keep func(string) bool) http.Header {
	var out http.Header
	for _, name := range sortedKeys(h) {
		if !keep(name) {
			continue
		}
		if out == nil {
			out = http.Header{}
		}
		for _, v := range h[name] {
			if containsFold(credentialHeaders, name) || strings.EqualFold(name, "Set-Cookie") {
				v = redacted
			} else {
				v = s.text(v)
			}
			out[name] = append(out[name], v)
		}
	}
	return out
}

func (s *scrubber) config(cfg map[string]any) (map[string]any, error) {
	if len(cfg) == 0 {
		return nil, nil
	}
	raw, err := marshalJSON(cfg)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(s.text(string(raw))), &out); err != nil {
		return nil, fmt.Errorf("scrubbing the config left it unreadable as JSON; check the ScrubRules replacements")
	}
	return out, nil
}

func (s *scrubber) dns(rec DNSRecord) DNSRecord {
	rec.Name = s.text(rec.Name)
	values := make([]string, len(rec.Values))
	for i, v := range rec.Values {
		values[i] = s.text(v)
	}
	rec.Values = values
	return rec
}

// marshalJSON encodes v compactly, with map keys sorted and without HTML
// escapes, so literals with & or < still match.
func marshalJSON(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// credentialField reports whether a JSON member, XML element, or form field
// of this name holds a credential. A name ending in "token" does unless it
// names a page cursor, such as NextToken.
func credentialField(name string) bool {
	n := normalizedName(name)
	switch n {
	case "token", "secret", "password", "passwd", "passphrase", "apikey", "apitoken", "authtoken", "accesstoken",
		"refreshtoken", "idtoken", "sessiontoken", "securitytoken", "secretaccesskey", "clientsecret", "privatekey",
		"assertion", "clientassertion", "samlresponse", "authorization", "proxyauthorization", "cookie", "setcookie",
		"secretstring", "secretbinary", "credential":
		return true
	}
	switch {
	case strings.Contains(n, "privatekey"), strings.HasSuffix(n, "secret"), strings.HasSuffix(n, "password"), strings.HasSuffix(n, "apikey"):
		return true
	case !strings.HasSuffix(n, "token"):
		return false
	}
	for _, cursor := range []string{"next", "page", "continuation", "pagination", "skip", "cursor", "marker", "sync", "delta", "resume", "start", "prev"} {
		if strings.Contains(n, cursor) {
			return false
		}
	}
	return true
}

// credentialParam reports whether a URL query parameter of this name holds a
// credential: a credential field's name, an API key, or a signature, such as
// a presigned URL's.
func credentialParam(name string) bool {
	switch normalizedName(name) {
	case "key", "sig", "signature", "xamzsignature", "xamzcredential", "xgoogsignature", "xgoogcredential":
		return true
	}
	return credentialField(name)
}

func normalizedName(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func localName(name string) string {
	return name[strings.LastIndex(name, ":")+1:]
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// replaceMatches rebuilds s with each match of re replaced by what fn returns
// for its groups.
func replaceMatches(re *regexp.Regexp, s string, fn func(groups []string) string) string {
	matches := re.FindAllStringSubmatchIndex(s, -1)
	if matches == nil {
		return s
	}
	var b strings.Builder
	last := 0
	for _, m := range matches {
		groups := make([]string, len(m)/2)
		for i := range groups {
			if m[2*i] >= 0 {
				groups[i] = s[m[2*i]:m[2*i+1]]
			}
		}
		b.WriteString(s[last:m[0]])
		b.WriteString(fn(groups))
		last = m[1]
	}
	b.WriteString(s[last:])
	return b.String()
}

// replaceIndexed rebuilds s with the spans fn replaces.
func replaceIndexed(s string, spans [][]int, fn func(a, b int) (string, bool)) string {
	var b strings.Builder
	last := 0
	for _, sp := range spans {
		rep, ok := fn(sp[0], sp[1])
		if !ok {
			continue
		}
		b.WriteString(s[last:sp[0]])
		b.WriteString(rep)
		last = sp[1]
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

func isWordByte(c byte) bool {
	return c == '_' || isDigit(c) || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isDigit(c) && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return s != ""
}

func hasDigit(s string) bool { return strings.ContainsAny(s, "0123456789") }

// runVisitor decides what becomes of a long run of base64 or hex characters:
// token returns what replaces a token, and text what replaces the text that
// base64 decodes to.
type runVisitor interface {
	token(run string) string
	text(decoded string, depth int) string
}

// rewriteRuns passes each long run in s to v and returns s with the runs v
// changed. Base64 that decodes to text is passed as its text and encoded
// again, in its own alphabet and line width, when v changes it.
func rewriteRuns(s string, depth int, v runVisitor) string {
	return replaceIndexed(s, longRun.FindAllStringIndex(s, -1), func(start, end int) (string, bool) {
		a := skipEscape(s, start)
		if end-a <= 40 {
			return "", false
		}
		run := s[a:end]
		out := visitRun(run, depth, v)
		if out == run {
			return "", false
		}
		return s[start:a] + out, true
	})
}

// skipEscape moves a past the letter of a JSON escape, such as the n of \n,
// which would otherwise start the run.
func skipEscape(s string, a int) int {
	if a == 0 || s[a-1] != '\\' {
		return a
	}
	switch s[a] {
	case 'n', 'r', 't', 'b', 'f':
		return a + 1
	case 'u':
		if a+5 <= len(s) && isHex(s[a+1:a+5]) {
			return a + 5
		}
	}
	return a
}

// visitRun visits a run. Base64 wrapped at a fixed width that decodes to
// text or public material is visited whole; any other run with line breaks
// is visited line by line.
func visitRun(run string, depth int, v runVisitor) string {
	lines, seps := splitLines(run)
	if len(lines) == 1 {
		return visitSingle(run, depth, v)
	}
	if width, ok := wrapWidth(lines); ok {
		joined := strings.Join(lines, "")
		if b, enc, ok := decodeBase64(joined); ok {
			switch {
			case printable(b):
				out := v.text(string(b), depth)
				if out == string(b) {
					return run
				}
				return wrap(enc.EncodeToString([]byte(out)), width, seps[0], lines[len(lines)-1] == "")
			case publicMaterial(b):
				return run
			}
		}
	}
	var b strings.Builder
	for i, line := range lines {
		b.WriteString(visitSingle(line, depth, v))
		if i < len(seps) {
			b.WriteString(seps[i])
		}
	}
	return b.String()
}

// splitLines splits a run at its escaped or real line breaks.
func splitLines(run string) ([]string, []string) {
	var lines, seps []string
	start := 0
	for i := 0; i < len(run); {
		sep := ""
		for _, candidate := range []string{`\r\n`, `\n`, "\r\n", "\n"} {
			if strings.HasPrefix(run[i:], candidate) {
				sep = candidate
				break
			}
		}
		if sep == "" {
			i++
			continue
		}
		lines = append(lines, run[start:i])
		seps = append(seps, sep)
		i += len(sep)
		start = i
	}
	return append(lines, run[start:]), seps
}

// wrapWidth returns the width lines are wrapped at, when every line but the
// last has it and the last is no longer. An empty line after a final line
// break does not count.
func wrapWidth(lines []string) (int, bool) {
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	width := len(lines[0])
	if width < 16 {
		return 0, false
	}
	for i, line := range lines {
		if line == "" || i < len(lines)-1 && len(line) != width || len(line) > width {
			return 0, false
		}
	}
	return width, true
}

func wrap(encoded string, width int, sep string, trailing bool) string {
	var b strings.Builder
	for i := 0; i < len(encoded); i += width {
		if i > 0 {
			b.WriteString(sep)
		}
		b.WriteString(encoded[i:min(i+width, len(encoded))])
	}
	if trailing {
		b.WriteString(sep)
	}
	return b.String()
}

var (
	unescapeRun = strings.NewReplacer("%2B", "+", "%2b", "+", "%2F", "/", "%2f", "/", "%3D", "=", "%3d", "=")
	escapeRun   = strings.NewReplacer("+", "%2B", "/", "%2F", "=", "%3D")
)

func visitSingle(raw string, depth int, v runVisitor) string {
	run := unescapeRun.Replace(raw)
	escaped := run != raw
	reescape := func(s string) string {
		if !escaped {
			return s
		}
		return escapeRun.Replace(s)
	}
	kind, decoded, enc := judgeRun(run)
	switch kind {
	case runToken:
		if out := v.token(run); out != run {
			return out
		}
	case runText:
		if out := v.text(string(decoded), depth); out != string(decoded) {
			return reescape(enc.EncodeToString([]byte(out)))
		}
	case runPath:
		parts := strings.Split(run, "/")
		for i, p := range parts {
			parts[i] = visitSingle(p, depth, v)
		}
		if joined := strings.Join(parts, "/"); joined != run {
			return reescape(joined)
		}
	}
	return raw
}

// Kinds of long run.
const (
	runPlain = iota // not a token
	runToken        // a token
	runText         // base64 of text
	runPath         // slash-separated parts, each judged on its own
)

// digestLengths are the lengths of hex SHA-224, SHA-256, SHA-384, and SHA-512
// digests, which are no secret.
var digestLengths = map[int]bool{56: true, 64: true, 96: true, 128: true}

// judgeRun says what a run of base64, base64url, or hex characters is. A run
// of 40 characters or fewer is not a token, nor is a hex digest, nor base64
// of a certificate or public key. Base64 of text is judged by its text. A
// run with slashes and no other sign of base64 is a path, whose parts are
// judged on their own. Anything else over 40 characters is a token when it
// mixes upper and lower case letters and digits, as random tokens do and
// identifiers rarely do.
func judgeRun(run string) (int, []byte, *base64.Encoding) {
	body := strings.TrimRight(run, "=")
	switch {
	case len(body) <= 40, sriDigest(run):
		return runPlain, nil, nil
	case body == run && isHex(run):
		if digestLengths[len(run)] {
			return runPlain, nil, nil
		}
		return runToken, nil, nil
	}
	if b, enc, ok := decodeBase64(run); ok {
		switch {
		case printable(b):
			return runText, b, enc
		case publicMaterial(b):
			return runPlain, nil, nil
		}
	}
	if strings.Contains(run, "/") && !strings.ContainsAny(run, "+=") {
		return runPath, nil, nil
	}
	if strings.IndexFunc(body, unicode.IsUpper) >= 0 && strings.IndexFunc(body, unicode.IsLower) >= 0 && hasDigit(body) {
		return runToken, nil, nil
	}
	return runPlain, nil, nil
}

// sriDigest reports whether run is a digest as subresource integrity writes
// it, such as sha256-<base64>.
func sriDigest(run string) bool {
	for _, prefix := range []string{"sha1-", "sha256-", "sha384-", "sha512-"} {
		if strings.HasPrefix(run, prefix) {
			return true
		}
	}
	return false
}

// decodeBase64 decodes run in the alphabet its characters allow. A run with
// padding, or whose length is a multiple of 4, is taken as padded base64, so
// text encoded again gets the padding its readers expect.
func decodeBase64(run string) ([]byte, *base64.Encoding, bool) {
	padded := strings.HasSuffix(run, "=") || len(run)%4 == 0
	var candidates []*base64.Encoding
	if !strings.ContainsAny(run, "-_") {
		candidates = append(candidates, pick(padded, base64.StdEncoding, base64.RawStdEncoding))
	}
	if !strings.ContainsAny(run, "+/") {
		candidates = append(candidates, pick(padded, base64.URLEncoding, base64.RawURLEncoding))
	}
	for _, enc := range candidates {
		if b, err := enc.DecodeString(run); err == nil && len(b) > 0 {
			return b, enc, true
		}
	}
	return nil, nil, false
}

func pick(padded bool, withPadding, raw *base64.Encoding) *base64.Encoding {
	if padded {
		return withPadding
	}
	return raw
}

// printable reports whether b is text: valid UTF-8 of printable characters,
// tabs, and line breaks. Random bytes almost never are.
func printable(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, r := range string(b) {
		if !unicode.IsPrint(r) && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}

// publicMaterial reports whether b is a certificate or a public key, in DER
// or SSH's wire format, which are public by design.
func publicMaterial(b []byte) bool {
	if _, err := x509.ParseCertificate(b); err == nil {
		return true
	}
	if _, err := x509.ParsePKIXPublicKey(b); err == nil {
		return true
	}
	if _, err := x509.ParsePKCS1PublicKey(b); err == nil {
		return true
	}
	if len(b) < 4 {
		return false
	}
	n := binary.BigEndian.Uint32(b)
	if n == 0 || n > 64 || int(n) > len(b)-4 {
		return false
	}
	keyType := string(b[4 : 4+n])
	return strings.HasPrefix(keyType, "ssh-") || strings.HasPrefix(keyType, "ecdsa-sha2-") || strings.HasPrefix(keyType, "sk-")
}

// leak is something the scrub check found: where, and what it looks like.
// It never holds the value itself.
type leak struct{ where, what string }

func (l leak) String() string { return l.where + ": " + l.what }

// secretForm is an encoding of a secret's value, named by the secret's key.
type secretForm struct{ key, form string }

// scanner is the scrub check. It flags what a recording must not hold: a
// known secret's value in any of its encodings, a tenant identifier in any
// case and encoding, and anything that looks like a credential, as the
// scrubber would have removed it.
type scanner struct {
	forms []secretForm
	ids   []identifierForm
	where string
	leaks []leak
	seen  map[leak]bool
}

// identifierForm is an encoding of a tenant identifier in lowercase, or its
// digits, named by its fake.
type identifierForm struct {
	fake, form string
	digits     bool
}

func newScanner(secrets []canary, identifiers map[string]string) *scanner {
	c := &scanner{seen: map[leak]bool{}}
	for _, s := range secrets {
		if len(s.value) >= minSecretLength {
			for _, form := range encodings(s.value) {
				c.forms = append(c.forms, secretForm{key: s.key, form: form})
			}
		}
	}
	for _, id := range sortedKeys(identifiers) {
		fake := identifiers[id]
		switch {
		case id == "":
		case isDigits(id):
			c.ids = append(c.ids, identifierForm{fake: fake, form: id, digits: true})
		default:
			seen := map[string]bool{}
			for _, form := range encodings(id) {
				if f := strings.ToLower(form); !seen[f] {
					seen[f] = true
					c.ids = append(c.ids, identifierForm{fake: fake, form: f})
				}
			}
		}
	}
	return c
}

func (c *scanner) add(what string) {
	l := leak{where: c.where, what: what}
	if !c.seen[l] {
		c.seen[l] = true
		c.leaks = append(c.leaks, l)
	}
}

func (c *scanner) scan(where, text string) {
	c.where = where
	c.textAt(text, 0)
}

func (c *scanner) textAt(s string, depth int) {
	for _, f := range c.forms {
		if strings.Contains(s, f.form) {
			c.add("the value of secret " + f.key)
		}
	}
	lower := strings.ToLower(s)
	for _, id := range c.ids {
		if id.digits && len(numberSpans(s, id.form)) > 0 || !id.digits && strings.Contains(lower, id.form) {
			c.add("the tenant identifier ScrubRules.Identifiers replaces with " + id.fake)
		}
	}
	if privateKeyMarker.MatchString(s) {
		c.add("a private key")
	}
	if signedJWT.MatchString(s) {
		c.add("a signed JWT")
	}
	for _, g := range bearerToken.FindAllStringSubmatch(s, -1) {
		if g[2] != redacted && hasDigit(g[2]) {
			c.add("a bearer token")
		}
	}
	for _, g := range sswsToken.FindAllStringSubmatch(s, -1) {
		if g[2] != redacted {
			c.add("an Okta API token")
		}
	}
	if githubToken.MatchString(s) {
		c.add("a GitHub token")
	}
	if slackToken.MatchString(s) {
		c.add("a Slack token")
	}
	for _, m := range awsKeyID.FindAllString(s, -1) {
		if !strings.Contains(m, "EXAMPLE") {
			c.add("an AWS access key ID")
		}
	}
	rewriteRuns(s, depth, c)
}

func (c *scanner) token(run string) string {
	c.add("a long token")
	return run
}

func (c *scanner) text(decoded string, depth int) string {
	if depth < maxDepth {
		c.textAt(decoded, depth+1)
	}
	return decoded
}

// scanScenario runs the scrub check on what a recording holds: its config,
// responses, DNS records, and endpoints.
func scanScenario(s Scenario, secrets []canary, identifiers map[string]string) []leak {
	c := newScanner(secrets, identifiers)
	if len(s.Config) > 0 {
		if raw, err := marshalJSON(s.Config); err == nil {
			c.scan("config", string(raw))
		}
	}
	for i, r := range s.Responses {
		at := fmt.Sprintf("responses[%d]", i)
		c.scan(at+".url", r.URL)
		c.scan(at+".request_body", r.RequestBody)
		for _, name := range sortedKeys(r.Header) {
			for _, v := range r.Header[name] {
				c.scan(at+".header."+name, v)
			}
		}
		c.scan(at+".body", r.Body)
	}
	for i, rec := range s.DNS {
		at := fmt.Sprintf("dns[%d]", i)
		c.scan(at+".name", rec.Name)
		for _, v := range rec.Values {
			c.scan(at+".values", v)
		}
	}
	for i, ep := range s.Endpoints {
		at := fmt.Sprintf("endpoints[%d]", i)
		c.scan(at+".address", ep.Address)
		for _, name := range ep.Cert.DNSNames {
			c.scan(at+".cert.dns_names", name)
		}
	}
	return c.leaks
}
