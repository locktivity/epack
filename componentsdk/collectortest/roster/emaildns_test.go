package roster

import (
	"encoding/json"
	"strings"
	"testing"
)

// Keys from RFC 8463's appendix A.2: an Ed25519 key and a 1024-bit RSA key
// as a SubjectPublicKeyInfo. The others are a 512-bit RSA key, too short for
// RFC 8301, and a 2048-bit RSA key as an RSAPublicKey.
const (
	dkimEd25519 = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
	dkimRSA1024 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB"
	dkimRSA512  = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALqlmCA9fU1uoouZRCVpgAJjNAtIo38pO7AbkqI9DQ1HkLhGmu5ZfuXNErcmKDYaAaBAuG6Z+4tNiMo+4Wt0gYsCAwEAAQ=="
	dkimPKCS1   = "MIIBCgKCAQEAy4YYmnXSiuUinDnOM9orsZT1iboZ5UUvVqy9AVOrIqh8uJ9ykZ3H81RtyxXxDSkDDlgXVNCMIprKktyamslrUjsVxh1Yk67ovJoRNiWqL2gZ7WyJNkp35zaeetWmWX5/WXGy1sukNOoepG5z88gzNWo559FbeKKOtrUkARUEv6q8b65/Pp6FGylIyOdqSqCnyHwDThg/Ex0vyN8XfhEpuijjnVOHdOKBpzAgKKS6fTZe/1pXectBwaIb/u8KYLxz33naulvB0/yVgW/+YoZ1ZmrmhoV1xHkSVGMpLtjUx29JS/8L+vq8Ba3sDfujdxcP5NcoK5xDFN7cX9eT67DHdwIDAQAB"
)

// mailRoster parses a roster that checks domains, with names, a map of DNS
// names to their records, and s1 and google as common selectors.
func mailRoster(t *testing.T, domains []string, names map[string]any) *Roster {
	t.Helper()
	r, err := Parse([]byte(mailRosterJSON(t, domains, names)))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func mailRosterJSON(t *testing.T, domains []string, names map[string]any) string {
	t.Helper()
	block, err := json.Marshal(map[string]any{"domains": domains, "names": names})
	if err != nil {
		t.Fatal(err)
	}
	return `{"version": 1, "vendor": "internet", "email_dns": ` + string(block) +
		`, "terms": {"dkim_selectors": {"s1": "common", "google": "common", "custom": "other"}}}`
}

// mailTXT is a name's records with these TXT records alone.
func mailTXT(records ...string) map[string]any { return map[string]any{"txt": records} }

func deriveMailValues(t *testing.T, r *Roster) map[string]any {
	t.Helper()
	values, err := Derive(r)
	if err != nil {
		t.Fatal(err)
	}
	return values[EmailDNS]
}

func checkMail(t *testing.T, got map[string]any, want map[string]any) {
	t.Helper()
	for _, pointer := range sortedKeys(want) {
		if g, ok := got[pointer]; !ok || !sameValue(g, want[pointer]) {
			t.Errorf("%s = %v (set %t), want %v", pointer, g, ok, want[pointer])
		}
	}
}

// An SPF record is valid when it follows RFC 7208's grammar, names only the
// RFC's mechanisms, has redirect and exp at most once each, and has no more
// than 10 terms that cause DNS lookups.
func TestSPFValidity(t *testing.T) {
	cases := map[string]bool{
		"v=spf1":                              true,
		"v=spf1 -all":                         true,
		"v=spf1 ~all":                         true,
		"v=spf1 +all":                         true,
		"V=SPF1 MX -ALL":                      true,
		"v=spf1  mx   -all  ":                 true,
		"v=spf1 include:_spf.google.com ~all": true,
		"v=spf1 include:example.test. -all":   true,
		"v=spf1 a mx ptr a:mail.example.test/24//64 -all": true,
		"v=spf1 a/24 mx//64 -all":                         true,
		"v=spf1 ip4:192.0.2.0/24 ip4:192.0.2.1 -all":      true,
		"v=spf1 ip6:2001:db8::/32 ip6:::1 -all":           true,
		"v=spf1 exists:%{ir}.%{l1r+-}._spf.%{d} -all":     true,
		"v=spf1 redirect=_spf.example.test":               true,
		"v=spf1 -all exp=explain._spf.%{d}":               true,
		"v=spf1 -all moo=cow foo.bar=":                    true,
		"v=spf1 a:%{d}":                                   true,

		"v=spf1 ipv4:192.0.2.10 -all":                                      false,
		"v=spf1 ip4:192.0.2.300 -all":                                      false,
		"v=spf1 ip4:192.0.2.1/33 -all":                                     false,
		"v=spf1 ip4:192.0.2.1/08 -all":                                     false,
		"v=spf1 ip4:192.0.02.1 -all":                                       false,
		"v=spf1 ip6:192.0.2.1 -all":                                        false,
		"v=spf1 ip6:2001:db8::/129 -all":                                   false,
		"v=spf1 a/33 -all":                                                 false,
		"v=spf1 include: -all":                                             false,
		"v=spf1 include -all":                                              false,
		"v=spf1 all:example.test":                                          false,
		"v=spf1 include:example -all":                                      false,
		"v=spf1 include:192.0.2.1 -all":                                    false,
		"v=spf1 exists:%(ir).sbl.example.test -all":                        false,
		"v=spf1 exists:%{c}.example.test -all":                             false,
		"v=spf1 exists:%{d0}.example.test -all":                            false,
		"v=spf1 redirect=a.example.test redirect=b.example.test":           false,
		"v=spf1 -all exp=a.example.test exp=b.example.test":                false,
		"v=spf1\t-all":                                                     false,
		"v=spf1 *all":                                                      false,
		"v=spf1 -all 1bad=x":                                               false,
		"v=spf1 " + strings.Repeat("include:a.example.test ", 10) + "-all": true,
		"v=spf1 " + strings.Repeat("include:a.example.test ", 11) + "-all": false,
		"v=spf1 " + strings.Repeat("a ", 10) + "redirect=b.example.test":   false,
		"v=spf1 " + strings.Repeat("ip4:192.0.2.1 ", 20) + "-all":          true,
	}
	for record, want := range cases {
		if got := spfValid(record); got != want {
			t.Errorf("spfValid(%q) = %t, want %t", record, got, want)
		}
	}
}

// The SPF record is the one TXT record that starts with v=spf1. A domain
// with none has a null spf, and one with more than one has an SPF record
// that isn't valid, whose text Derive leaves out.
func TestDeriveSPFSelection(t *testing.T) {
	r := mailRoster(t, []string{"one.example.test", "none.example.test", "two.example.test", "spf10.example.test"}, map[string]any{
		"one.example.test":   mailTXT("google-site-verification=x", "v=spf1 -all"),
		"none.example.test":  mailTXT("hello"),
		"two.example.test":   mailTXT("v=spf1 -all", "v=spf1 mx -all"),
		"spf10.example.test": mailTXT("v=spf10 -all"),
	})
	v := deriveMailValues(t, r)
	checkMail(t, v, map[string]any{
		"/domains/0/spf/record":     "v=spf1 -all",
		"/domains/0/spf/valid":      true,
		"/domains/1/spf":            nil,
		"/domains/2/spf/valid":      false,
		"/domains/3/spf":            nil,
		"/summary/with_spf_count":   2,
		"/summary/with_spf_pct":     50,
		"/summary/total_domains":    4,
		"/summary/with_dmarc_count": 0,
	})
	if _, ok := v["/domains/2/spf/record"]; ok {
		t.Error("a domain with two SPF records has a record")
	}
}

// A DMARC record's policy is its p tag, and its subdomain policy its sp tag
// or p. A record whose p is missing or not valid, or whose sp or np is not
// valid, acts as p=none when it lists a valid rua URI, and requests nothing
// otherwise. pct is RFC 7489's, 100 when the record doesn't set it.
func TestDMARCPolicies(t *testing.T) {
	cases := []struct {
		record, policy, sub string
		pct                 int
		valid, reports      bool
	}{
		{"v=DMARC1; p=reject", dmarcReject, dmarcReject, 100, true, false},
		{"v=DMARC1; p=reject; sp=none; pct=20", dmarcReject, dmarcNone, 20, true, false},
		{"v=DMARC1;p=Quarantine;", dmarcQuarantine, dmarcQuarantine, 100, true, false},
		{"v = DMARC1 ; p = reject ; rua = mailto:a@example.test , mailto:b@example.test!10m", dmarcReject, dmarcReject, 100, true, true},
		{"v=DMARC1; p=quarentine", dmarcUnknown, dmarcUnknown, 100, false, false},
		{"v=DMARC1; p=quarentine; rua=mailto:a@example.test", dmarcNone, dmarcNone, 100, false, true},
		{"v=DMARC1; rua=mailto:a@example.test", dmarcNone, dmarcNone, 100, true, true},
		{"v=DMARC1", dmarcUnknown, dmarcUnknown, 100, true, false},
		{"v=DMARC1; p=reject; sp=bogus", dmarcUnknown, dmarcUnknown, 100, false, false},
		{"v=DMARC1; p=reject; np=bogus; rua=mailto:a@example.test", dmarcNone, dmarcNone, 100, false, true},
		{"v=DMARC1; p=reject; rua=a@example.test", dmarcReject, dmarcReject, 100, false, false},
		{"v=DMARC1; p=reject; rua=a@example.test,mailto:b@example.test", dmarcReject, dmarcReject, 100, false, true},
		{"v=DMARC1; p=reject; pct=150", dmarcReject, dmarcReject, 100, true, false},
		{"v=DMARC1; p=reject; P=none; future=1", dmarcReject, dmarcReject, 100, true, false},
		{"v=DMARC1; p=reject; p=none", dmarcUnknown, dmarcUnknown, 100, false, false},
		{"v=DMARC1; p=reject; ; rua=mailto:a@example.test", dmarcReject, dmarcReject, 100, false, true},
		{"v=DMARC1; p=reject; junk", dmarcReject, dmarcReject, 100, false, false},
		{"v=DMARC1; p=reject; t=maybe", dmarcReject, dmarcReject, 100, false, false},
		{"v=DMARC1; p=reject; fo=0:1", dmarcReject, dmarcReject, 100, false, false},
		{"v=DMARC1; p=reject; fo=d:1:s; adkim=s; aspf=r; psd=n", dmarcReject, dmarcReject, 100, true, false},
	}
	for _, tc := range cases {
		d := parseDMARC(tc.record)
		policy, sub := d.policies()
		if policy != tc.policy || sub != tc.sub || d.pct() != tc.pct || d.valid != tc.valid || d.reports() != tc.reports {
			t.Errorf("%q: policy %s, subdomains %s, pct %d, valid %t, reports %t; want %s, %s, %d, %t, %t",
				tc.record, policy, sub, d.pct(), d.valid, d.reports(), tc.policy, tc.sub, tc.pct, tc.valid, tc.reports)
		}
	}
}

// A reporting URI is an RFC 3986 URI: it has a scheme.
func TestDMARCReportingURIs(t *testing.T) {
	cases := map[string]bool{
		"mailto:dmarc@example.test":               true,
		"mailto:dmarc@example.test!10m":           true,
		"mailto:dmarc+tag@example.test?subject=x": true,
		"https://reports.example.test/dmarc":      true,
		"mailto:a%2Cb@example.test":               true,
		"dmarc@example.test":                      false,
		"mailto:a,b@example.test":                 false,
		"mailto:a!b@example.test":                 false,
		"1mailto:dmarc@example.test":              false,
		"mailto:dmarc@example.test#a#b":           false,
		"mailto:a%2@example.test":                 false,
		"mailto:dmarc @example.test":              false,
	}
	for uri, want := range cases {
		if got := dmarcURI(uri); got != want {
			t.Errorf("dmarcURI(%q) = %t, want %t", uri, got, want)
		}
	}
}

// The DMARC record that applies is the domain's own or, without one, the
// one RFC 9989's DNS tree walk selects above it. The policy that applies is
// p on the domain's own record and sp or p on one above it, and enforced
// means that policy is reject without t=y.
func TestDMARCTreeWalk(t *testing.T) {
	cases := []struct {
		name     string
		domain   string
		records  map[string]string
		applies  string
		enforced bool
	}{
		{"own record", "mail.example.test", map[string]string{
			"mail.example.test": "v=DMARC1; p=reject; sp=none", "example.test": "v=DMARC1; p=none",
		}, "v=DMARC1; p=reject; sp=none", true},
		{"parent's subdomain policy", "mail.example.test", map[string]string{"example.test": "v=DMARC1; p=none; sp=reject"}, "v=DMARC1; p=none; sp=reject", true},
		{"parent's p without sp", "mail.example.test", map[string]string{"example.test": "v=DMARC1; p=reject"}, "v=DMARC1; p=reject", true},
		{"parent's sp of none", "mail.example.test", map[string]string{"example.test": "v=DMARC1; p=reject; sp=none"}, "v=DMARC1; p=reject; sp=none", false},
		{"testing", "example.test", map[string]string{"example.test": "v=DMARC1; p=reject; t=y"}, "v=DMARC1; p=reject; t=y", false},
		{"testing off", "example.test", map[string]string{"example.test": "v=DMARC1; p=reject; t=n"}, "v=DMARC1; p=reject; t=n", true},
		{"fewest labels", "a.b.example.test", map[string]string{
			"b.example.test": "v=DMARC1; p=none", "example.test": "v=DMARC1; p=reject",
		}, "v=DMARC1; p=reject", true},
		{"psd=n stops the walk", "a.b.example.test", map[string]string{
			"b.example.test": "v=DMARC1; p=none; psd=n", "example.test": "v=DMARC1; p=reject",
		}, "v=DMARC1; p=none; psd=n", false},
		{"one label below psd=y", "a.b.example.test", map[string]string{
			"example.test": "v=DMARC1; p=reject", "test": "v=DMARC1; p=none; psd=y",
		}, "v=DMARC1; p=reject", true},
		{"psd=y with nothing below it", "a.b.example.test", map[string]string{
			"b.example.test": "v=DMARC1; p=reject", "test": "v=DMARC1; p=none; psd=y",
		}, "v=DMARC1; p=none; psd=y", false},
		{"two records at the domain are discarded", "mail.example.test", map[string]string{
			"mail.example.test": "v=DMARC1; p=none\x00v=DMARC1; p=quarantine", "example.test": "v=DMARC1; p=reject",
		}, "v=DMARC1; p=reject", true},
		{"a record that doesn't start with v=DMARC1 is not one", "mail.example.test", map[string]string{
			"mail.example.test": "p=none; v=DMARC1\x00v=DMARC1 p=none\x00 v=DMARC1; p=none", "example.test": "v=DMARC1; p=reject",
		}, "v=DMARC1; p=reject", true},
		{"an invalid record of its own stops the walk", "mail.example.test", map[string]string{
			"mail.example.test": "v=DMARC1; p=quarentine", "example.test": "v=DMARC1; p=reject",
		}, "v=DMARC1; p=quarentine", false},
		{"eight labels walk from the parent", "a.b.c.d.e.f.example.test", map[string]string{
			"b.c.d.e.f.example.test": "v=DMARC1; p=reject",
		}, "v=DMARC1; p=reject", true},
		{"nine labels walk from the last seven", "a.b.c.d.e.f.g.example.test", map[string]string{
			"b.c.d.e.f.g.example.test": "v=DMARC1; p=none", "c.d.e.f.g.example.test": "v=DMARC1; p=reject; psd=n",
		}, "v=DMARC1; p=reject; psd=n", true},
		{"nine labels skip the eighth", "a.b.c.d.e.f.g.example.test", map[string]string{
			"b.c.d.e.f.g.example.test": "v=DMARC1; p=reject",
		}, "", false},
		{"no record", "mail.example.test", map[string]string{"mail.example.test": "v=spf1 -all"}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			names := map[string]any{}
			for name, records := range tc.records {
				names["_dmarc."+name] = mailTXT(strings.Split(records, "\x00")...)
			}
			v := deriveMailValues(t, mailRoster(t, []string{tc.domain}, names))
			if tc.applies == "" {
				checkMail(t, v, map[string]any{"/domains/0/dmarc": nil, "/summary/with_dmarc_count": 0, "/domains/0/assessment/enforced": false})
				return
			}
			checkMail(t, v, map[string]any{
				"/domains/0/dmarc/record":        tc.applies,
				"/domains/0/assessment/enforced": tc.enforced,
				"/summary/with_dmarc_count":      1,
			})
		})
	}
}

// has_reporting reads the rua of the record that applies, the domain's own
// or one above it.
func TestDeriveDMARCReporting(t *testing.T) {
	r := mailRoster(t, []string{"a.example.test", "b.example.test", "c.example.test"}, map[string]any{
		"_dmarc.a.example.test": mailTXT("v=DMARC1; p=none; rua=dmarc@example.test"),
		"_dmarc.b.example.test": mailTXT("v=DMARC1; p=none; rua=mailto:dmarc@example.test; ruf=mailto:f@example.test"),
		"_dmarc.example.test":   mailTXT("v=DMARC1; p=reject; rua=mailto:dmarc@example.test"),
	})
	checkMail(t, deriveMailValues(t, r), map[string]any{
		"/domains/0/assessment/has_reporting": false,
		"/domains/0/dmarc/rua":                "dmarc@example.test",
		"/domains/0/dmarc/valid":              false,
		"/domains/1/assessment/has_reporting": true,
		"/domains/1/dmarc/ruf":                "mailto:f@example.test",
		"/domains/2/assessment/has_reporting": true,
		"/domains/2/assessment/enforced":      true,
		"/domains/2/dmarc/policy":             dmarcReject,
		"/summary/with_reporting_count":       2,
		"/summary/with_reporting_pct":         66,
	})
}

// A DKIM key record is valid when it is a well-formed tag-list whose key
// verifiers can use for mail.
func TestDKIMValidity(t *testing.T) {
	cases := map[string]bool{
		"v=DKIM1; k=ed25519; p=" + dkimEd25519:                     true,
		"v=DKIM1; k=rsa; p=" + dkimRSA1024:                         true,
		"p=" + dkimRSA1024:                                         true,
		"v=DKIM1; p=" + dkimPKCS1:                                  true,
		"v=DKIM1; h=sha1:sha256; s=email; t=y:s; p=" + dkimRSA1024: true,
		"v=DKIM1; s=*; n=notes for people; future=x; p=" + dkimRSA1024[:40] + " \t" + dkimRSA1024[40:]: true,
		" v = DKIM1 ; p = " + dkimEd25519 + " ; k = ed25519 ;":                                         true,
		"v=DKIM1; k=rsa; p=":                               false,
		"v=DKIM1; k=rsa":                                   false,
		"v=DKIM1; p=" + dkimRSA512:                         false,
		"v=DKIM1; k=rsa; p=" + dkimEd25519:                 false,
		"v=DKIM1; k=ed25519; p=" + dkimRSA1024:             false,
		"v=DKIM1; k=ecdsa; p=" + dkimRSA1024:               false,
		"v=DKIM1; h=sha1; p=" + dkimRSA1024:                false,
		"v=DKIM1; s=tlsrpt; p=" + dkimRSA1024:              false,
		"k=rsa; v=DKIM1; p=" + dkimRSA1024:                 false,
		"v=DKIM1; p=" + dkimRSA1024 + "; p=" + dkimRSA1024: false,
		"v=DKIM1; k=rsa; p=not base64!":                    false,
		"v=DKIM1; 1k=rsa; p=" + dkimRSA1024:                false,
		"v=DKIM1; k=rsa; p=" + dkimRSA1024 + ";;":          false,
		"hello world":                                      false,
	}
	for record, want := range cases {
		if got := dkimValid(record); got != want {
			t.Errorf("dkimValid(%q) = %t, want %t", record, got, want)
		}
	}
}

// DKIM records are read at the common selectors only. A record whose v tag
// isn't DKIM1 isn't a DKIM record, and a selector with more than one record
// has one that isn't valid.
func TestDeriveDKIMSelectors(t *testing.T) {
	r := mailRoster(t, []string{"a.example.test", "b.example.test", "c.example.test"}, map[string]any{
		"s1._domainkey.a.example.test":     mailTXT("v=DKIM1; k=ed25519; p=" + dkimEd25519),
		"google._domainkey.a.example.test": mailTXT("v=DKIM1; p="),
		"custom._domainkey.a.example.test": mailTXT("v=DKIM1; p=" + dkimRSA1024),
		"custom._domainkey.b.example.test": mailTXT("v=DKIM1; p=" + dkimRSA1024),
		"s1._domainkey.b.example.test":     mailTXT("v=DKIM2; p=" + dkimRSA1024),
		"s1._domainkey.c.example.test":     mailTXT("v=DKIM1; p="+dkimRSA1024, "v=DKIM1; k=ed25519; p="+dkimEd25519),
	})
	v := deriveMailValues(t, r)
	checkMail(t, v, map[string]any{
		"/domains/0/dkim/0/selector": "google",
		"/domains/0/dkim/0/record":   "v=DKIM1; p=",
		"/domains/0/dkim/0/valid":    false,
		"/domains/0/dkim/1/selector": "s1",
		"/domains/0/dkim/1/valid":    true,
		"/domains/2/dkim/0/selector": "s1",
		"/domains/2/dkim/0/valid":    false,
		"/summary/with_dkim_count":   2,
		"/summary/with_dkim_pct":     66,
	})
	for _, pointer := range []string{"/domains/0/dkim/2/selector", "/domains/1/dkim/0/selector", "/domains/2/dkim/0/record"} {
		if got, ok := v[pointer]; ok {
			t.Errorf("%s = %v, want it unset", pointer, got)
		}
	}
}

// The summary counts domains with MX records, with SPF and DMARC records
// valid or not, with DKIM records, with all three of MX, SPF and DMARC, that
// enforce DMARC, and that get reports.
func TestDeriveMailSummary(t *testing.T) {
	full := map[string]any{"mx": []map[string]any{{"host": "mx.example.test", "priority": 10}}, "txt": []string{"v=spf1 mx -all"}}
	r := mailRoster(t, []string{"a.example.test", "b.example.test", "c.example.test"}, map[string]any{
		"a.example.test":        full,
		"_dmarc.a.example.test": mailTXT("v=DMARC1; p=reject; rua=mailto:d@example.test"),
		"b.example.test":        mailTXT("v=spf1 bogus"),
		"_dmarc.b.example.test": mailTXT("v=DMARC1; p=quarantine"),
		"c.example.test":        map[string]any{"mx": []map[string]any{{"host": "mx.example.test", "priority": 0}}},
	})
	checkMail(t, deriveMailValues(t, r), map[string]any{
		"/domains/0/mx/0/host":          "mx.example.test",
		"/domains/0/mx/0/priority":      10,
		"/summary/total_domains":        3,
		"/summary/with_mx_count":        2,
		"/summary/with_mx_pct":          66,
		"/summary/with_spf_count":       2,
		"/summary/with_spf_pct":         66,
		"/summary/with_dmarc_count":     2,
		"/summary/with_dmarc_pct":       66,
		"/summary/with_dkim_count":      0,
		"/summary/with_dkim_pct":        0,
		"/summary/with_all_three_count": 1,
		"/summary/with_all_three_pct":   33,
		"/summary/enforced_count":       1,
		"/summary/enforced_pct":         33,
		"/summary/with_reporting_count": 1,
		"/summary/with_reporting_pct":   33,
		"/summary/all_enforced":         false,
	})

	one := mailRoster(t, []string{"a.example.test"}, map[string]any{"_dmarc.a.example.test": mailTXT("v=DMARC1; p=reject")})
	checkMail(t, deriveMailValues(t, one), map[string]any{"/summary/all_enforced": true, "/summary/enforced_pct": 100})

	none := mailRoster(t, []string{}, map[string]any{})
	checkMail(t, deriveMailValues(t, none), map[string]any{
		"/summary/total_domains":  0,
		"/summary/enforced_count": 0,
		"/summary/enforced_pct":   nil,
		"/summary/with_mx_pct":    nil,
		"/summary/all_enforced":   nil,
	})
	none.MailDomains = nil
	if values, err := Derive(none); err != nil {
		t.Fatal(err)
	} else if _, ok := values[EmailDNS]; ok {
		t.Error("a roster without an email_dns block gives email-dns values")
	}
}

// Names match ignoring case and a trailing dot, and a domain is reported as
// the roster lists it.
func TestMailNamesIgnoreCase(t *testing.T) {
	r := mailRoster(t, []string{"Example.Test."}, map[string]any{
		"EXAMPLE.test":         mailTXT("v=spf1 -all"),
		"_dmarc.example.TEST.": mailTXT("v=DMARC1; p=reject"),
	})
	checkMail(t, deriveMailValues(t, r), map[string]any{
		"/domains/0/domain":       "Example.Test.",
		"/domains/0/spf/record":   "v=spf1 -all",
		"/domains/0/dmarc/policy": dmarcReject,
	})
}

func TestParseRefusesBadMailRosters(t *testing.T) {
	cases := map[string]struct {
		domains []string
		names   map[string]any
		want    string
	}{
		"selector": {[]string{"a.example.test"}, map[string]any{"mailo._domainkey.a.example.test": mailTXT("v=DKIM1; p=")},
			`selector "mailo" has no entry in terms.dkim_selectors`},
		"domain twice": {[]string{"a.example.test", "A.example.test."}, nil, "is listed twice"},
		"name twice": {[]string{"a.example.test"}, map[string]any{"a.example.test": mailTXT("x"), "A.example.test.": mailTXT("y")},
			"names lists a.example.test twice"},
		"mx host twice": {[]string{"a.example.test"}, map[string]any{"a.example.test": map[string]any{"mx": []map[string]any{
			{"host": "mx.example.test", "priority": 10}, {"host": "MX.example.test", "priority": 20}}}}, "lists MX host MX.example.test twice"},
		"mx priority": {[]string{"a.example.test"}, map[string]any{"a.example.test": map[string]any{"mx": []map[string]any{
			{"host": "mx.example.test", "priority": 70000}}}}, "priority of 0 to 65535"},
		"mx without priority": {[]string{"a.example.test"}, map[string]any{"a.example.test": map[string]any{"mx": []map[string]any{
			{"host": "mx.example.test"}}}}, "has no priority"},
		"domain": {[]string{"bücher.example.test"}, nil, "A-label form"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(mailRosterJSON(t, tc.domains, tc.names)))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Parse() error = %v, want one containing %q", err, tc.want)
			}
		})
	}
	bad := strings.Replace(mailRosterJSON(t, nil, nil), `"custom": "other"`, `"custom": "rare"`, 1)
	if _, err := Parse([]byte(bad)); err == nil || !strings.Contains(err.Error(), `terms.dkim_selectors maps "custom" to "rare"`) {
		t.Errorf("Parse() error = %v, want one about the selector's term", err)
	}
}

func TestMailCloneIsDeepAndKeepsExtras(t *testing.T) {
	r := mailRoster(t, []string{"a.example.test"}, map[string]any{
		"a.example.test": map[string]any{"txt": []string{"v=spf1 -all"}, "ttl": 300,
			"mx": []map[string]any{{"host": "mx.example.test", "priority": 10, "preference_note": "primary"}}},
	})
	var ttl int
	if ok, err := r.MailDomains.Names["a.example.test"].Extra.Get("ttl", &ttl); !ok || err != nil || ttl != 300 {
		t.Errorf("ttl = %d, %t, %v", ttl, ok, err)
	}
	c := r.Clone()
	c.MailDomains.Domains[0] = "b.example.test"
	c.MailDomains.Names["a.example.test"].TXT[0] = "v=spf1 +all"
	c.MailDomains.Names["a.example.test"].MX[0].Priority = 99
	got := r.MailDomains
	if got.Domains[0] != "a.example.test" || got.Names["a.example.test"].TXT[0] != "v=spf1 -all" || got.Names["a.example.test"].MX[0].Priority != 10 {
		t.Errorf("changing the clone changed the roster: %+v", got)
	}
	var note string
	if ok, err := got.Names["a.example.test"].MX[0].Extra.Get("preference_note", &note); !ok || err != nil || note != "primary" {
		t.Errorf("preference_note = %q, %t, %v", note, ok, err)
	}
}
