package roster

import (
	"cmp"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Normalized email DNS terms. A DKIM selector is common when it is one of
// the common selectors the email-dns schema counts DKIM records at, the ones
// the check reads.
const (
	DKIMSelectorCommon = "common"
	DKIMSelectorOther  = "other"
)

// The policies a DMARC record can request, and the one the email-dns schema
// gives when no DMARC processing applies.
const (
	dmarcNone       = "none"
	dmarcQuarantine = "quarantine"
	dmarcReject     = "reject"
	dmarcUnknown    = "unknown"
)

// spfLookupLimit is RFC 7208's limit on the terms that cause DNS lookups.
const spfLookupLimit = 10

// dmarcDefaultPct is the pct RFC 7489 gives a record without a valid pct
// tag.
const dmarcDefaultPct = 100

// dmarcWalkLabels is the most labels RFC 9989's DNS tree walk queries a name
// with after the first query.
const dmarcWalkLabels = 7

// MailDomains is the domains an email DNS check reads, and the DNS records
// the internet holds for them and for the names above them. In a roster
// file:
//
//	"email_dns": {
//	  "domains": ["example.com", "news.example.com"],
//	  "names": {"<DNS name>": {"mx": [{"host": "mx1.example.com", "priority": 10}],
//	    "txt": ["v=spf1 -all", ...]}}
//	}
//
// and in the terms block:
//
//	"dkim_selectors": {"<selector>": "common" or "other"}
//
// domains is in the order the check lists them. names holds the MX and TXT
// records at each DNS name the check could query: the domains themselves,
// _dmarc under each name a DMARC tree walk reaches, and
// <selector>._domainkey under a domain for its DKIM keys. A name not in
// names has no MX or TXT records, like one that doesn't exist. Names match
// ignoring ASCII case and a trailing dot. Each TXT record is one string,
// its character-strings joined.
//
// dkim_selectors says, for each selector names has a key under, whether it
// is a common selector. The check reads no other.
type MailDomains struct {
	Domains []string
	// Names gives each DNS name's records, by the name in lowercase without
	// a trailing dot.
	Names map[string]MailRecords
	Extra Extra
}

// MailRecords is the MX and TXT records at one DNS name.
type MailRecords struct {
	MX    []MailExchanger
	TXT   []string
	Extra Extra
}

// MailExchanger is an MX record.
type MailExchanger struct {
	Host     string
	Priority int
	Extra    Extra
}

// MailDomainsTerms maps the vendor terms a roster's email_dns block uses to
// normalized ones.
type MailDomainsTerms struct {
	DKIMSelectors map[string]string `json:"dkim_selectors"`
}

var mailDomain = domain{
	key: "email_dns",
	parse: func(r *Roster, raw json.RawMessage) error {
		m, err := parseMail(raw)
		if err != nil {
			return err
		}
		r.MailDomains = m
		return nil
	},
	validate: validateMail,
	clone: func(c, r *Roster) {
		if r.MailDomains != nil {
			c.MailDomains = r.MailDomains.clone()
		}
	},
	derive: deriveMail,
	notDerived: map[string]map[string]string{EmailDNS: {
		"/domains/*/errors":            "free text the schema doesn't enumerate",
		"/domains/*/assessment/issues": "free text the schema doesn't enumerate",
		"/diagnostics/domain_errors":   "free text the schema doesn't enumerate",
		"/diagnostics/warnings":        "free text the schema doesn't enumerate",
	}},
}

// mailName is a DNS name as names keys it.
func mailName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

func parseMail(raw json.RawMessage) (*MailDomains, error) {
	var b struct {
		Domains []string                   `json:"domains"`
		Names   map[string]json.RawMessage `json:"names"`
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, err
	}
	m := &MailDomains{Domains: b.Domains, Names: map[string]MailRecords{}}
	var err error
	if m.Extra, err = extra(raw, "domains", "names"); err != nil {
		return nil, err
	}
	for _, name := range sortedKeys(b.Names) {
		key := mailName(name)
		if _, dup := m.Names[key]; dup {
			return nil, fmt.Errorf("names lists %s twice, ignoring case and a trailing dot", key)
		}
		var n struct {
			MX  []json.RawMessage `json:"mx"`
			TXT []string          `json:"txt"`
		}
		if err := json.Unmarshal(b.Names[name], &n); err != nil {
			return nil, fmt.Errorf("name %s: %w", name, err)
		}
		recs := MailRecords{TXT: n.TXT}
		if recs.Extra, err = extra(b.Names[name], "mx", "txt"); err != nil {
			return nil, fmt.Errorf("name %s: %w", name, err)
		}
		for _, mr := range n.MX {
			var mx struct {
				Host     string `json:"host"`
				Priority *int   `json:"priority"`
			}
			if err := json.Unmarshal(mr, &mx); err != nil {
				return nil, fmt.Errorf("name %s mx: %w", name, err)
			}
			if mx.Priority == nil {
				return nil, fmt.Errorf("name %s mx %s has no priority", name, mx.Host)
			}
			e, err := extra(mr, "host", "priority")
			if err != nil {
				return nil, fmt.Errorf("name %s mx: %w", name, err)
			}
			recs.MX = append(recs.MX, MailExchanger{Host: mx.Host, Priority: *mx.Priority, Extra: e})
		}
		m.Names[key] = recs
	}
	return m, nil
}

func validateMail(r *Roster) error {
	for _, selector := range sortedKeys(r.Terms.DKIMSelectors) {
		if class := r.Terms.DKIMSelectors[selector]; class != DKIMSelectorCommon && class != DKIMSelectorOther {
			return fmt.Errorf("terms.dkim_selectors maps %q to %q, which is none of %v", selector, class, []string{DKIMSelectorCommon, DKIMSelectorOther})
		}
	}
	m := r.MailDomains
	if m == nil {
		return nil
	}
	seen := map[string]bool{}
	for _, d := range m.Domains {
		name := mailName(d)
		if name == "" || strings.ContainsFunc(name, func(c rune) bool { return c > 0x7e || c <= ' ' }) {
			return fmt.Errorf("domain %q is not a DNS name in A-label form", d)
		}
		if seen[name] {
			return fmt.Errorf("domain %s is listed twice", d)
		}
		seen[name] = true
	}
	for _, name := range sortedKeys(m.Names) {
		hosts := map[string]bool{}
		for _, mx := range m.Names[name].MX {
			if mx.Host == "" || mx.Priority < 0 || mx.Priority > 65535 {
				return fmt.Errorf("name %s: an MX record has a host and a priority of 0 to 65535", name)
			}
			if hosts[mailName(mx.Host)] {
				return fmt.Errorf("name %s lists MX host %s twice", name, mx.Host)
			}
			hosts[mailName(mx.Host)] = true
		}
		labels := strings.Split(name, ".")
		if i := slices.Index(labels, "_domainkey"); i > 0 && len(m.Names[name].TXT) > 0 {
			selector := strings.Join(labels[:i], ".")
			if err := mapped(r.Terms.DKIMSelectors, "dkim_selectors", "name "+name+" selector", selector); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *MailDomains) clone() *MailDomains {
	c := &MailDomains{Domains: slices.Clone(m.Domains), Names: make(map[string]MailRecords, len(m.Names)), Extra: m.Extra}
	for name, recs := range m.Names {
		recs.MX, recs.TXT = slices.Clone(recs.MX), slices.Clone(recs.TXT)
		c.Names[name] = recs
	}
	return c
}

// mailAssessment is what a domain has, as the email-dns schema's summary
// counts it.
type mailAssessment struct {
	mx, spf, dmarc, dkim, enforced, reporting bool
}

// deriveMail gives the email-dns schema's domains, in roster order, and its
// summary over them. A domain's MX records are listed by priority, as a
// resolver answers them, and those of equal priority in roster order. Its
// SPF record is the one TXT record at the domain that RFC 7208 section 4.5
// selects. Its DMARC record is the one RFC 9989 section 4.10.1 discovers:
// the domain's own, or the one a DNS tree walk finds above it. Its DKIM
// records are those at the common selectors.
func deriveMail(r *Roster, out Values) error {
	m := r.MailDomains
	if m == nil {
		return nil
	}
	v := out[EmailDNS]
	if v == nil {
		v = map[string]any{}
		out[EmailDNS] = v
	}
	var all []mailAssessment
	for i, d := range m.Domains {
		at := "/domains/" + strconv.Itoa(i)
		name := mailName(d)
		var a mailAssessment
		v[at+"/domain"] = d

		mxs := slices.Clone(m.Names[name].MX)
		slices.SortStableFunc(mxs, func(a, b MailExchanger) int { return cmp.Compare(a.Priority, b.Priority) })
		for j, mx := range mxs {
			v[fmt.Sprintf("%s/mx/%d/host", at, j)] = mx.Host
			v[fmt.Sprintf("%s/mx/%d/priority", at, j)] = mx.Priority
		}
		a.mx = len(m.Names[name].MX) > 0

		// RFC 7208 makes more than one SPF record a permerror, and leaves
		// none of them the domain's record.
		spf := spfRecords(m.Names[name].TXT)
		switch len(spf) {
		case 0:
			v[at+"/spf"] = nil
		case 1:
			v[at+"/spf/record"] = spf[0]
			v[at+"/spf/valid"] = spfValid(spf[0])
		default:
			v[at+"/spf/valid"] = false
		}
		a.spf = len(spf) > 0

		rec, own, ok := m.dmarcFor(name)
		if ok {
			policy, sub := rec.policies()
			v[at+"/dmarc/record"] = rec.text
			v[at+"/dmarc/policy"] = policy
			v[at+"/dmarc/subdomain_policy"] = sub
			v[at+"/dmarc/pct"] = rec.pct()
			for _, tag := range []string{"rua", "ruf"} {
				if uris, set := rec.tags[tag]; set {
					v[at+"/dmarc/"+tag] = uris
				}
			}
			v[at+"/dmarc/valid"] = rec.valid
			applied := sub
			if own {
				applied = policy
			}
			a.dmarc = true
			a.enforced = applied == dmarcReject && !rec.testing()
			a.reporting = rec.reports()
		} else {
			v[at+"/dmarc"] = nil
		}

		k := 0
		for _, selector := range sortedKeys(r.Terms.DKIMSelectors) {
			if r.Terms.DKIMSelectors[selector] != DKIMSelectorCommon {
				continue
			}
			keys := m.dkimRecords(selector, name)
			if len(keys) == 0 {
				continue
			}
			dk := fmt.Sprintf("%s/dkim/%d", at, k)
			v[dk+"/selector"] = selector
			// RFC 6376 section 3.6.2.2 leaves more than one record at a
			// selector undefined, so none of them is the selector's key.
			if len(keys) == 1 {
				v[dk+"/record"] = keys[0]
			}
			v[dk+"/valid"] = len(keys) == 1 && dkimValid(keys[0])
			k++
		}
		a.dkim = k > 0

		v[at+"/assessment/enforced"] = a.enforced
		v[at+"/assessment/has_reporting"] = a.reporting
		all = append(all, a)
	}
	v["/summary/total_domains"] = len(m.Domains)
	v["/summary/with_mx_count"] = count(all, func(a mailAssessment) bool { return a.mx })
	v["/summary/with_spf_count"] = count(all, func(a mailAssessment) bool { return a.spf })
	v["/summary/with_dmarc_count"] = count(all, func(a mailAssessment) bool { return a.dmarc })
	v["/summary/with_dkim_count"] = count(all, func(a mailAssessment) bool { return a.dkim })
	v["/summary/with_all_three_count"] = count(all, func(a mailAssessment) bool { return a.mx && a.spf && a.dmarc })
	v["/summary/enforced_count"] = count(all, func(a mailAssessment) bool { return a.enforced })
	v["/summary/with_reporting_count"] = count(all, func(a mailAssessment) bool { return a.reporting })
	return nil
}

// spfRecords lists the SPF records among a domain's TXT records: those that
// begin with the version section v=spf1, which a space or the record's end
// ends. Case doesn't matter, as RFC 7208's ABNF reads quoted text.
func spfRecords(txt []string) []string {
	var out []string
	for _, t := range txt {
		if len(t) >= 6 && strings.EqualFold(t[:6], "v=spf1") && (len(t) == 6 || t[6] == ' ') {
			out = append(out, t)
		}
	}
	return out
}

var (
	spfModifierName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]*$`)
	spfTopLabel     = regexp.MustCompile(`^([A-Za-z0-9]*[A-Za-z][A-Za-z0-9]*|[A-Za-z0-9]+-[A-Za-z0-9-]*[A-Za-z0-9])$`)
	spfIP4Network   = regexp.MustCompile(`^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$`)
	spfDualCIDR     = regexp.MustCompile(`(?:/([0-9]+))?(?://([0-9]+))?$`)
	// spfMacroBody is a macro-expand's letter, transformers and delimiters.
	// The letters c, r and t are left out, since RFC 7208 section 7.2
	// allows them only in explanation text, not in a record.
	spfMacroBody = regexp.MustCompile(`(?i)^[slodiphv]([0-9]*)r?[-.+,/_=]*$`)
)

// spfValid reports whether record, an SPF record, is valid: it follows RFC
// 7208's ABNF (section 12), uses only the mechanisms the RFC defines, has
// at most one redirect and one exp (section 6), and has at most 10 terms
// that cause DNS lookups (section 4.6.4). The lookups are counted in the
// record itself, without following its includes or redirect.
func spfValid(record string) bool {
	var lookups, redirects, exps int
	for _, term := range strings.Split(record[len("v=spf1"):], " ") {
		if term == "" {
			continue
		}
		if i := strings.IndexAny(term, "=:/"); i >= 0 && term[i] == '=' {
			name, value := term[:i], term[i+1:]
			if !spfModifierName.MatchString(name) {
				return false
			}
			var ok bool
			switch strings.ToLower(name) {
			case "redirect":
				redirects++
				lookups++
				ok = spfDomainSpec(value)
			case "exp":
				exps++
				ok = spfDomainSpec(value)
			default:
				_, ok = spfMacroString(value)
			}
			if !ok {
				return false
			}
			continue
		}
		if strings.ContainsAny(term[:1], "+-?~") {
			term = term[1:]
		}
		name, arg := term, ""
		if i := strings.IndexAny(term, ":/"); i >= 0 {
			name, arg = term[:i], term[i:]
		}
		domain := func(arg string, optional bool) bool {
			if arg == "" {
				return optional
			}
			return arg[0] == ':' && spfDomainSpec(arg[1:])
		}
		var ok bool
		switch strings.ToLower(name) {
		case "all":
			ok = arg == ""
		case "include", "exists":
			lookups++
			ok = domain(arg, false)
		case "ptr":
			lookups++
			ok = domain(arg, true)
		case "a", "mx":
			lookups++
			rest, cidr := spfCutDualCIDR(arg)
			ok = cidr && domain(rest, true)
		case "ip4":
			network, cidr, hasCIDR := strings.Cut(strings.TrimPrefix(arg, ":"), "/")
			ok = strings.HasPrefix(arg, ":") && spfIP4Network.MatchString(network) && (!hasCIDR || spfCIDR(cidr, 32))
		case "ip6":
			network, cidr, hasCIDR := strings.Cut(strings.TrimPrefix(arg, ":"), "/")
			addr, err := netip.ParseAddr(network)
			ok = strings.HasPrefix(arg, ":") && err == nil && strings.Contains(network, ":") && addr.Zone() == "" && (!hasCIDR || spfCIDR(cidr, 128))
		}
		if !ok {
			return false
		}
	}
	return redirects <= 1 && exps <= 1 && lookups <= spfLookupLimit
}

// spfCutDualCIDR cuts the dual-cidr-length off the end of an a or mx
// mechanism's argument, and reports whether its lengths are in range.
func spfCutDualCIDR(arg string) (string, bool) {
	m := spfDualCIDR.FindStringSubmatchIndex(arg)
	ok := true
	for i, limit := range []int{32, 128} {
		if start := m[2+2*i]; start >= 0 {
			ok = ok && spfCIDR(arg[start:m[3+2*i]], limit)
		}
	}
	return arg[:m[0]], ok
}

// spfCIDR reports whether digits is a prefix length of at most limit,
// without a leading zero.
func spfCIDR(digits string, limit int) bool {
	n, err := strconv.Atoi(digits)
	return err == nil && digits != "" && (digits == "0" || digits[0] != '0') && n <= limit
}

// spfDomainSpec reports whether s is a domain-spec: a macro-string that
// ends with a macro, or with a dot and a top label, then an optional dot.
func spfDomainSpec(s string) bool {
	endsInMacro, ok := spfMacroString(s)
	if !ok || s == "" {
		return false
	}
	if endsInMacro {
		return true
	}
	t := strings.TrimSuffix(s, ".")
	i := strings.LastIndexByte(t, '.')
	return i >= 0 && spfTopLabel.MatchString(t[i+1:])
}

// spfMacroString reports whether s is a macro-string, and whether it ends
// with a macro.
func spfMacroString(s string) (endsInMacro, ok bool) {
	for i := 0; i < len(s); {
		if s[i] != '%' {
			if s[i] < 0x21 || s[i] > 0x7e {
				return false, false
			}
			i++
			endsInMacro = false
			continue
		}
		if i+1 == len(s) {
			return false, false
		}
		switch s[i+1] {
		case '%', '_', '-':
			i += 2
		case '{':
			j := strings.IndexByte(s[i:], '}')
			if j < 0 {
				return false, false
			}
			body := spfMacroBody.FindStringSubmatch(s[i+2 : i+j])
			if body == nil || (body[1] != "" && strings.Trim(body[1], "0") == "") {
				return false, false
			}
			i += j + 1
		default:
			return false, false
		}
		endsInMacro = true
	}
	return endsInMacro, true
}

// mailTags reads a tag-list, as RFC 6376 section 3.2 defines it and RFC
// 9989 section 4.7 adopts it: name=value specs separated by semicolons,
// with an optional semicolon at the end and whitespace around each name and
// value. It gives each well-formed tag by name, and the name of the first
// spec. It reports whether every spec is well formed and no name repeats.
// A name that repeats makes the whole list invalid, so then it gives no
// tags.
func mailTags(text string, name *regexp.Regexp, value func(string) bool) (map[string]string, string, bool) {
	tags := map[string]string{}
	var first string
	ok := true
	specs := strings.Split(text, ";")
	for i, spec := range specs {
		if strings.Trim(spec, " \t\r\n") == "" {
			ok = ok && i == len(specs)-1 && i > 0
			continue
		}
		n, val, hasEquals := strings.Cut(spec, "=")
		n, val = strings.Trim(n, " \t\r\n"), strings.Trim(val, " \t\r\n")
		if i == 0 {
			first = n
		}
		if !hasEquals || !name.MatchString(n) || !value(val) {
			ok = false
			continue
		}
		if _, dup := tags[n]; dup {
			return nil, first, false
		}
		tags[n] = val
	}
	return tags, first, ok
}

var (
	dmarcTagName = regexp.MustCompile(`^[A-Za-z]+$`)
	dmarcPct     = regexp.MustCompile(`^[0-9]{1,3}$`)
	dmarcSize    = regexp.MustCompile(`![0-9]+[kmgtKMGT]?$`)
	uriScheme    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*$`)
	dkimTagName  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)
	dkimWord     = regexp.MustCompile(`^[A-Za-z]([A-Za-z0-9-]*[A-Za-z0-9])?$`)
	dkimBase64   = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
)

// dmarcValue reports whether s is a DMARC tag's value: printing characters
// and spaces, at least one.
func dmarcValue(s string) bool {
	return s != "" && !strings.ContainsFunc(s, func(c rune) bool { return c < 0x20 || c > 0x7e })
}

// dmarcRules check the value of each tag RFC 9989 section 4.8 gives a
// syntax for. Any other tag is ignored.
var dmarcRules = map[string]func(string) bool{
	"v":     func(s string) bool { return s == "DMARC1" },
	"p":     dmarcRequest,
	"sp":    dmarcRequest,
	"np":    dmarcRequest,
	"t":     func(s string) bool { return oneOfFold(s, "y", "n") },
	"psd":   func(s string) bool { return oneOfFold(s, "y", "n", "u") },
	"adkim": func(s string) bool { return oneOfFold(s, "r", "s") },
	"aspf":  func(s string) bool { return oneOfFold(s, "r", "s") },
	"rua":   dmarcURIList,
	"ruf":   dmarcURIList,
	"fo":    dmarcFailureOptions,
}

// dmarcURIList reports whether every URI in a rua or ruf value is valid.
func dmarcURIList(s string) bool {
	return !slices.ContainsFunc(dmarcURIs(s), func(u string) bool { return !dmarcURI(u) })
}

func dmarcRequest(s string) bool { return oneOfFold(s, dmarcNone, dmarcQuarantine, dmarcReject) }

func oneOfFold(s string, values ...string) bool {
	return slices.ContainsFunc(values, func(v string) bool { return strings.EqualFold(s, v) })
}

// dmarcFailureOptions reports whether s is an fo value: 0 or 1, d, and s,
// each at most once and separated by colons, without both 0 and 1.
func dmarcFailureOptions(s string) bool {
	seen := map[string]bool{}
	for _, opt := range strings.Split(s, ":") {
		if !oneOfFold(opt, "0", "1", "d", "s") || seen[strings.ToLower(opt)] {
			return false
		}
		seen[strings.ToLower(opt)] = true
	}
	return !seen["0"] || !seen["1"]
}

// dmarcURIs splits a rua or ruf value into its URIs.
func dmarcURIs(s string) []string {
	uris := strings.Split(s, ",")
	for i := range uris {
		uris[i] = strings.Trim(uris[i], " \t")
	}
	return uris
}

// dmarcURI reports whether s is a DMARC reporting URI: an RFC 3986 URI,
// which has a scheme, with its commas and exclamation points encoded, and
// perhaps the obsolete size limit RFC 9989 still allows after it.
func dmarcURI(s string) bool {
	if loc := dmarcSize.FindStringIndex(s); loc != nil {
		s = s[:loc[0]]
	}
	scheme, rest, ok := strings.Cut(s, ":")
	if !ok || !uriScheme.MatchString(scheme) {
		return false
	}
	fragments := 0
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		switch {
		case c == '%':
			if i+2 >= len(rest) || !isHex(rest[i+1]) || !isHex(rest[i+2]) {
				return false
			}
			i += 2
		case c == '#':
			fragments++
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', strings.IndexByte("-._~$&'()*+=:@/?[]", c) >= 0:
		default:
			return false
		}
	}
	return fragments <= 1
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// dmarcRecord is a DMARC record and its tags.
type dmarcRecord struct {
	text string
	tags map[string]string
	// valid is whether the record follows RFC 9989 section 4.8's formal
	// definition, with a valid value for each tag that has a syntax.
	valid bool
}

func parseDMARC(text string) dmarcRecord {
	tags, _, ok := mailTags(text, dmarcTagName, dmarcValue)
	d := dmarcRecord{text: text, tags: tags, valid: ok}
	for name, value := range tags {
		if check, known := dmarcRules[name]; known && !check(value) {
			d.valid = false
		}
	}
	return d
}

// policies gives the policy the record requests for the domain it is
// published at, from p, and for that domain's subdomains, from sp or p when
// it has no sp. As RFC 9989 section 4.10.1 says, a record whose p is
// missing or not valid, or whose sp or np is not valid, acts as p=none when
// it lists a valid rua URI. Otherwise no DMARC processing applies, and both
// are unknown.
func (d dmarcRecord) policies() (domain, subdomains string) {
	p, pSet := d.tags["p"]
	sp, spSet := d.tags["sp"]
	np, npSet := d.tags["np"]
	if pSet && dmarcRequest(p) && (!spSet || dmarcRequest(sp)) && (!npSet || dmarcRequest(np)) {
		if spSet {
			return strings.ToLower(p), strings.ToLower(sp)
		}
		return strings.ToLower(p), strings.ToLower(p)
	}
	if d.reports() {
		return dmarcNone, dmarcNone
	}
	return dmarcUnknown, dmarcUnknown
}

// reports reports whether the record lists at least one valid rua URI.
func (d dmarcRecord) reports() bool {
	rua, ok := d.tags["rua"]
	return ok && slices.ContainsFunc(dmarcURIs(rua), dmarcURI)
}

// testing reports whether the record sets t=y, which asks receivers to
// apply the policy one level lower.
func (d dmarcRecord) testing() bool { return strings.EqualFold(d.tags["t"], "y") }

func (d dmarcRecord) psd() string { return strings.ToLower(d.tags["psd"]) }

// pct is the record's pct tag, as RFC 7489 section 6.3 defines it: an
// integer from 0 to 100, and 100 when the tag is missing or not valid.
func (d dmarcRecord) pct() int {
	s := d.tags["pct"]
	if n, err := strconv.Atoi(s); err == nil && dmarcPct.MatchString(s) && n <= 100 {
		return n
	}
	return dmarcDefaultPct
}

// dmarcAt gives the DMARC record published for name, at _dmarc.name: the
// one TXT record there that starts with a v tag of DMARC1. It reports false
// when there is none, or more than one, which RFC 9989 section 4.10
// discards.
func (m *MailDomains) dmarcAt(name string) (dmarcRecord, bool) {
	var found []string
	for _, t := range m.Names["_dmarc."+name].TXT {
		spec, _, _ := strings.Cut(t, ";")
		tag, value, ok := strings.Cut(spec, "=")
		if ok && strings.TrimRight(tag, " \t") == "v" && strings.Trim(value, " \t") == "DMARC1" {
			found = append(found, t)
		}
	}
	if len(found) != 1 {
		return dmarcRecord{}, false
	}
	return parseDMARC(found[0]), true
}

// dmarcFor gives the DMARC record that applies to domain, as RFC 9989
// section 4.10.1 discovers it, and reports whether it is the domain's own
// and whether there is one. Without a record of its own, a DNS tree walk
// queries the domain's parent, or its last 7 labels when it has more than
// 8, and then each shorter name, until a record sets psd=n or psd=y. The
// record that applies is then the Organizational Domain's, as section
// 4.10.2 selects it: the record with psd=n, the record one label below the
// one with psd=y, or else the record at the name with the fewest labels.
// When the domain one label below a psd=y record has no record, the PSD's
// applies.
func (m *MailDomains) dmarcFor(domain string) (rec dmarcRecord, own, ok bool) {
	if rec, ok := m.dmarcAt(domain); ok {
		return rec, true, true
	}
	labels := strings.Split(domain, ".")
	keep := len(labels) - 1
	if len(labels) > dmarcWalkLabels+1 {
		keep = dmarcWalkLabels
	}
	type found struct {
		labels int
		rec    dmarcRecord
	}
	var walk []found
	for ; keep >= 1; keep-- {
		rec, ok := m.dmarcAt(strings.Join(labels[len(labels)-keep:], "."))
		if !ok {
			continue
		}
		walk = append(walk, found{keep, rec})
		if psd := rec.psd(); psd == "y" || psd == "n" {
			break
		}
	}
	if len(walk) == 0 {
		return dmarcRecord{}, false, false
	}
	last := walk[len(walk)-1]
	if last.rec.psd() == "y" {
		for _, f := range walk {
			if f.labels == last.labels+1 {
				return f.rec, false, true
			}
		}
	}
	return last.rec, false, true
}

// dkimRecords gives the DKIM key records at selector under domain: its TXT
// records, but for any that begins with a v tag other than DKIM1, which RFC
// 6376 section 3.6.1 discards.
func (m *MailDomains) dkimRecords(selector, domain string) []string {
	var out []string
	for _, t := range m.Names[mailName(selector)+"._domainkey."+domain].TXT {
		tags, first, _ := mailTags(t, dkimTagName, dkimValue)
		if v, ok := tags["v"]; ok && first == "v" && v != "DKIM1" {
			continue
		}
		out = append(out, t)
	}
	return out
}

// dkimValue reports whether s is a DKIM tag's value: printing characters
// but semicolons, in runs that whitespace separates, or empty.
func dkimValue(s string) bool {
	return !strings.ContainsFunc(s, func(c rune) bool { return (c < 0x21 || c > 0x7e) && !strings.ContainsRune(" \t\r\n", c) })
}

// dkimList splits a colon-separated DKIM value and reports whether each
// item is a hyphenated word, or * where star allows it.
func dkimList(s string, star bool) ([]string, bool) {
	items := strings.Split(s, ":")
	for i := range items {
		items[i] = strings.ToLower(strings.Trim(items[i], " \t\r\n"))
		if !dkimWord.MatchString(items[i]) && (!star || items[i] != "*") {
			return nil, false
		}
	}
	return items, true
}

// dkimValid reports whether a DKIM key record is valid. It must be a
// tag-list as RFC 6376 section 3.2 defines it, with a v tag of DKIM1 first
// if it has one, and h, k, s and t tags in their syntax (section 3.6.1). It
// must give a key that verifiers can use for mail: p must not be empty,
// which revokes the key, and must be the base64 of a key of k's type. That
// is an RSA key of 1024 bits or more (RFC 8301 section 3.2), as a DER
// RSAPublicKey or SubjectPublicKeyInfo, or a 32-byte Ed25519 key (RFC 8463).
// A key of any other type is ignored. h, if given, must allow sha256, the
// one hash RFC 8301 leaves, and s, if given, must list email or *.
func dkimValid(text string) bool {
	tags, first, ok := mailTags(text, dkimTagName, dkimValue)
	if !ok {
		return false
	}
	if v, set := tags["v"]; set && (first != "v" || v != "DKIM1") {
		return false
	}
	lists := map[string][]string{"k": {"rsa"}}
	for _, tag := range []string{"h", "k", "s", "t"} {
		if value, set := tags[tag]; set {
			items, ok := dkimList(value, tag == "s")
			if !ok || (tag == "k" && len(items) != 1) {
				return false
			}
			lists[tag] = items
		}
	}
	if h, set := lists["h"]; set && !slices.Contains(h, "sha256") {
		return false
	}
	if s, set := lists["s"]; set && !slices.Contains(s, "email") && !slices.Contains(s, "*") {
		return false
	}
	p := strings.Join(strings.Fields(tags["p"]), "")
	if p == "" || !dkimBase64.MatchString(p) {
		return false
	}
	key, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(p, "="))
	if err != nil {
		return false
	}
	switch lists["k"][0] {
	case "rsa":
		pub, err := x509.ParsePKIXPublicKey(key)
		rsaKey, isRSA := pub.(*rsa.PublicKey)
		if err != nil {
			rsaKey, err = x509.ParsePKCS1PublicKey(key)
			isRSA = err == nil
		}
		return isRSA && rsaKey.N.BitLen() >= 1024
	case "ed25519":
		return len(key) == 32
	}
	return false
}
