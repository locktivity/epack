package roster

import (
	"fmt"
	"strings"
	"testing"
)

// tlsTerms maps OpenSSL's version names, and trusts one root.
const tlsTerms = `{
  "tls_versions": {"SSLv3": "ssl_3_0", "TLSv1": "tls_1_0", "TLSv1.1": "tls_1_1", "TLSv1.2": "tls_1_2", "TLSv1.3": "tls_1_3"},
  "tls_roots": {"ISRG Root X1": "trusted", "Self": "untrusted"}
}`

// tlsRoster parses a roster whose tls block has endpoints, a JSON list's
// entries.
func tlsRoster(t *testing.T, endpoints ...string) *Roster {
	t.Helper()
	r, err := Parse([]byte(tlsRosterJSON(endpoints...)))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func tlsRosterJSON(endpoints ...string) string {
	return `{"version": 1, "vendor": "internet", "tls": {"endpoints": [` + strings.Join(endpoints, ",") + `]}, "terms": ` + tlsTerms + `}`
}

// tlsEndpoint is an endpoint at host that accepts TLS 1.2 and 1.3 and
// presents cert, a certificate's JSON.
func tlsEndpoint(host, cert string) string {
	return fmt.Sprintf(`{"host": %q, "port": 443, "accepts": ["TLSv1.2", "TLSv1.3"],
	  "negotiates": {"version": "TLSv1.3", "cipher_suite": "TLS_AES_128_GCM_SHA256"}, "certificate": %s}`, host, cert)
}

func deriveTLSValues(t *testing.T, r *Roster) map[string]any {
	t.Helper()
	values, err := Derive(r)
	if err != nil {
		t.Fatal(err)
	}
	return values[TLS]
}

func checkTLS(t *testing.T, got map[string]any, want map[string]any) {
	t.Helper()
	for _, pointer := range sortedKeys(want) {
		if g, ok := got[pointer]; !ok || !sameValue(g, want[pointer]) {
			t.Errorf("%s = %v (set %t), want %v", pointer, g, ok, want[pointer])
		}
	}
}

// Protocol support is each version the server accepts. Modern is TLS 1.2 or
// 1.3, and so is reachable, a TLS 1.2 or 1.3 handshake that succeeds.
// Legacy is TLS 1.0 or 1.1. SSL 3.0 is neither.
func TestDeriveTLSProtocolSupport(t *testing.T) {
	cases := []struct {
		accepts, negotiated string
		support             [4]bool
		modern, legacy      bool
		version             string
	}{
		{`["TLSv1.2", "TLSv1.3"]`, "TLSv1.3", [4]bool{false, false, true, true}, true, false, "TLS 1.3"},
		{`["TLSv1.2"]`, "TLSv1.2", [4]bool{false, false, true, false}, true, false, "TLS 1.2"},
		{`["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]`, "TLSv1.3", [4]bool{true, true, true, true}, true, true, "TLS 1.3"},
		{`["TLSv1", "TLSv1.1"]`, "TLSv1.1", [4]bool{true, true, false, false}, false, true, "TLS 1.1"},
		{`["SSLv3"]`, "SSLv3", [4]bool{false, false, false, false}, false, false, "SSL 3.0"},
	}
	for _, tc := range cases {
		t.Run(tc.accepts, func(t *testing.T) {
			v := deriveTLSValues(t, tlsRoster(t, fmt.Sprintf(`{"host": "a.example.test", "port": 443, "accepts": %s,
			  "negotiates": {"version": %q, "cipher_suite": "X"}, "certificate": null}`, tc.accepts, tc.negotiated)))
			want := map[string]any{
				"/endpoints/0/reachable":                            tc.modern,
				"/endpoints/0/assessment/modern_protocol":           tc.modern,
				"/endpoints/0/assessment/legacy_protocol_supported": tc.legacy,
				"/endpoints/0/tls/negotiated_version":               tc.version,
				"/endpoints/0/tls/negotiated_cipher_suite":          "X",
			}
			for i, version := range tlsSupportVersions {
				want["/endpoints/0/tls/protocol_support/"+version] = tc.support[i]
			}
			checkTLS(t, v, want)
		})
	}
}

// A certificate matches its endpoint's host as RFC 9525 says: by subject
// alternative name only, with a wildcard standing for exactly one whole
// left-most label.
func TestTLSHostnameMatching(t *testing.T) {
	cases := []struct {
		host     string
		dns, ips []string
		want     bool
	}{
		{"www.example.test", []string{"www.example.test"}, nil, true},
		{"WWW.Example.Test.", []string{"www.example.test"}, nil, true},
		{"www.example.test", []string{"other.example.test", "www.example.test"}, nil, true},
		{"www.example.test", []string{"*.example.test"}, nil, true},
		{"a.b.example.test", []string{"*.example.test"}, nil, false},
		{"example.test", []string{"*.example.test"}, nil, false},
		{"www.example.test", []string{"w*.example.test"}, nil, false},
		{"www.example.test", []string{"*.*.test"}, nil, false},
		{"www.example.test", []string{"www.*.test"}, nil, false},
		{"www.example.test", nil, nil, false},
		{"192.0.2.10", nil, []string{"192.0.2.10"}, true},
		{"192.0.2.10", []string{"192.0.2.10"}, nil, false},
		{"2001:db8::1", nil, []string{"2001:0db8:0:0::1"}, true},
		{"192.0.2.10", nil, []string{"::ffff:192.0.2.10"}, false},
	}
	for _, tc := range cases {
		if got := tlsMatchesHost(tc.host, tc.dns, tc.ips); got != tc.want {
			t.Errorf("tlsMatchesHost(%q, %v, %v) = %t, want %t", tc.host, tc.dns, tc.ips, got, tc.want)
		}
	}
	// The subject common name identifies nothing.
	v := deriveTLSValues(t, tlsRoster(t, tlsEndpoint("cn.example.test", `{"subject_common_name": "cn.example.test", "expires_in_days": 40, "root": "ISRG Root X1"}`)))
	checkTLS(t, v, map[string]any{
		"/endpoints/0/certificate/hostname_valid":      false,
		"/endpoints/0/assessment/hostname_valid":       false,
		"/endpoints/0/assessment/certificate_valid":    false,
		"/endpoints/0/certificate/dns_names":           []string{},
		"/endpoints/0/certificate/ip_addresses":        []string{},
		"/endpoints/0/certificate/subject_common_name": "cn.example.test",
	})
}

// A certificate is valid when it chains to a trusted root, matches its host,
// and is within its validity period. It has expired once it has fewer than 0
// whole days left, and expires soon when it has fewer than 30, since 30
// whole days is 30 days or more.
func TestDeriveTLSCertificateValidity(t *testing.T) {
	cases := []struct {
		name                                    string
		cert                                    string
		trusted, hostname, expired, soon, valid bool
	}{
		{"valid", `"root": "ISRG Root X1", "expires_in_days": 60, "valid_from_days_ago": 29`, true, true, false, false, true},
		{"untrusted root", `"root": "Self", "expires_in_days": 60`, false, true, false, false, false},
		{"no root", `"expires_in_days": 60`, false, true, false, false, false},
		{"another host", `"root": "ISRG Root X1", "expires_in_days": 60, "dns_names": ["other.example.test"]`, true, false, false, false, false},
		{"30 days left", `"root": "ISRG Root X1", "expires_in_days": 30`, true, true, false, false, true},
		{"29 days left", `"root": "ISRG Root X1", "expires_in_days": 29`, true, true, false, true, true},
		{"expires today", `"root": "ISRG Root X1", "expires_in_days": 0`, true, true, false, true, true},
		{"expired", `"root": "ISRG Root X1", "expires_in_days": -1`, true, true, true, false, false},
		{"valid from today", `"root": "ISRG Root X1", "expires_in_days": 60, "valid_from_days_ago": 0`, true, true, false, false, true},
		{"not yet valid", `"root": "ISRG Root X1", "expires_in_days": 60, "valid_from_days_ago": -1`, true, true, false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cert := `{"dns_names": ["a.example.test"], ` + tc.cert + `}`
			if strings.Contains(tc.cert, "dns_names") {
				cert = `{` + tc.cert + `}`
			}
			v := deriveTLSValues(t, tlsRoster(t, tlsEndpoint("a.example.test", cert)))
			checkTLS(t, v, map[string]any{
				"/endpoints/0/certificate/trusted_chain":    tc.trusted,
				"/endpoints/0/certificate/hostname_valid":   tc.hostname,
				"/endpoints/0/assessment/hostname_valid":    tc.hostname,
				"/endpoints/0/assessment/expired":           tc.expired,
				"/endpoints/0/assessment/expiring_soon":     tc.soon,
				"/endpoints/0/assessment/certificate_valid": tc.valid,
			})
		})
	}
}

// An endpoint that presents no certificate, or completes no handshake, has
// a null certificate, and none that is valid, matches its host, has expired
// or expires soon.
func TestDeriveTLSWithoutCertificate(t *testing.T) {
	r := tlsRoster(t,
		`{"host": "anon.example.test", "port": 443, "accepts": ["TLSv1.2"], "negotiates": {"version": "TLSv1.2", "cipher_suite": "TLS_ECDH_anon_WITH_AES_128_CBC_SHA"}, "certificate": null}`,
		`{"host": "closed.example.test", "port": 443, "accepts": []}`,
	)
	v := deriveTLSValues(t, r)
	for i, reachable := range []bool{true, false} {
		at := fmt.Sprintf("/endpoints/%d", i)
		checkTLS(t, v, map[string]any{
			at + "/certificate":                  nil,
			at + "/reachable":                    reachable,
			at + "/assessment/modern_protocol":   reachable,
			at + "/assessment/certificate_valid": false,
			at + "/assessment/hostname_valid":    false,
			at + "/assessment/expired":           false,
			at + "/assessment/expiring_soon":     false,
		})
		if _, ok := v[at+"/certificate/trusted_chain"]; ok {
			t.Errorf("%s/certificate/trusted_chain is set for an endpoint with no certificate", at)
		}
	}
	for _, version := range tlsSupportVersions {
		if v["/endpoints/1/tls/protocol_support/"+version] != false {
			t.Errorf("closed endpoint supports %s", version)
		}
	}
	if _, ok := v["/endpoints/1/tls/negotiated_version"]; ok {
		t.Error("closed endpoint has a negotiated version")
	}
}

// The certificate's facts are as the roster states them, and the chain's
// length counts the leaf.
func TestDeriveTLSCertificateFacts(t *testing.T) {
	v := deriveTLSValues(t, tlsRoster(t, tlsEndpoint("a.example.test", `{
	  "subject_common_name": "a.example.test", "issuer_common_name": "E5", "serial_number": "42",
	  "not_before": "2026-10-12T00:00:00Z", "not_after": "2027-01-10T00:00:00Z",
	  "valid_from_days_ago": 30, "expires_in_days": 59, "dns_names": ["a.example.test"], "ip_addresses": ["192.0.2.1"],
	  "fingerprint_sha256": "9F2A417C6B8E0D3F5A1B2C4D6E8F0A1B3C5D7E9F1A3B5C7D9E1F3A5B7C9D0E2F",
	  "signature_algorithm": "ECDSA-SHA384", "public_key_algorithm": "ECDSA",
	  "chain": ["a.example.test", "E5", "ISRG Root X1"], "root": "ISRG Root X1", "der": "MIIB"}`)))
	const at = "/endpoints/0/certificate"
	checkTLS(t, v, map[string]any{
		at + "/subject_common_name":  "a.example.test",
		at + "/issuer_common_name":   "E5",
		at + "/serial_number":        "42",
		at + "/not_before":           "2026-10-12T00:00:00Z",
		at + "/not_after":            "2027-01-10T00:00:00Z",
		at + "/expires_in_days":      59,
		at + "/dns_names":            []string{"a.example.test"},
		at + "/ip_addresses":         []string{"192.0.2.1"},
		at + "/fingerprint_sha256":   "9F2A417C6B8E0D3F5A1B2C4D6E8F0A1B3C5D7E9F1A3B5C7D9E1F3A5B7C9D0E2F",
		at + "/signature_algorithm":  "ECDSA-SHA384",
		at + "/public_key_algorithm": "ECDSA",
		at + "/chain_length":         3,
	})
	if _, ok := v["/endpoints/0/certificate/der"]; ok {
		t.Error("a vendor extra became a value")
	}
	r := tlsRoster(t, tlsEndpoint("a.example.test", `{"expires_in_days": 59, "der": "MIIB"}`))
	var der string
	if ok, err := r.Hosts.Endpoints[0].Certificate.Extra.Get("der", &der); !ok || err != nil || der != "MIIB" {
		t.Errorf("der = %q, %t, %v", der, ok, err)
	}
	v = deriveTLSValues(t, r)
	for _, field := range []string{"serial_number", "not_after", "fingerprint_sha256", "chain_length"} {
		if _, ok := v[at+"/"+field]; ok {
			t.Errorf("%s is set, but the roster doesn't state it", field)
		}
	}
}

// The summary counts each judgment over every endpoint, and its
// percentages are each count over them all, rounded as the schema says.
func TestDeriveTLSSummary(t *testing.T) {
	valid := `{"dns_names": ["%s"], "root": "ISRG Root X1", "expires_in_days": %d}`
	r := tlsRoster(t,
		tlsEndpoint("a.example.test", fmt.Sprintf(valid, "a.example.test", 60)),
		tlsEndpoint("b.example.test", fmt.Sprintf(valid, "b.example.test", 10)),
		tlsEndpoint("c.example.test", fmt.Sprintf(valid, "other.example.test", 60)),
		`{"host": "d.example.test", "port": 443, "accepts": ["TLSv1", "TLSv1.1"], "negotiates": {"version": "TLSv1.1", "cipher_suite": "X"}, "certificate": null}`,
		`{"host": "e.example.test", "port": 443, "accepts": ["TLSv1", "TLSv1.2"], "negotiates": {"version": "TLSv1.2", "cipher_suite": "X"}, "certificate": null}`,
		`{"host": "f.example.test", "port": 443, "accepts": []}`,
	)
	checkTLS(t, deriveTLSValues(t, r), map[string]any{
		"/summary/total_endpoints":                 6,
		"/summary/reachable_count":                 4,
		"/summary/reachable_pct":                   66,
		"/summary/certificate_valid_count":         2,
		"/summary/certificate_valid_pct":           33,
		"/summary/hostname_valid_count":            2,
		"/summary/hostname_valid_pct":              33,
		"/summary/modern_protocol_count":           4,
		"/summary/modern_protocol_pct":             66,
		"/summary/expiring_soon_count":             1,
		"/summary/expiring_soon_pct":               17,
		"/summary/legacy_protocol_supported_count": 2,
		"/summary/legacy_protocol_supported_pct":   34,
		"/summary/all_certificates_valid":          false,
		"/summary/all_modern_protocol":             false,
	})

	all := tlsRoster(t, tlsEndpoint("a.example.test", fmt.Sprintf(valid, "a.example.test", 60)))
	checkTLS(t, deriveTLSValues(t, all), map[string]any{
		"/summary/all_certificates_valid": true,
		"/summary/all_modern_protocol":    true,
	})

	none := tlsRoster(t)
	checkTLS(t, deriveTLSValues(t, none), map[string]any{
		"/summary/total_endpoints":        0,
		"/summary/reachable_count":        0,
		"/summary/reachable_pct":          nil,
		"/summary/expiring_soon_pct":      nil,
		"/summary/all_certificates_valid": nil,
		"/summary/all_modern_protocol":    nil,
	})

	if values, err := Derive(tlsRoster(t)); err != nil {
		t.Fatal(err)
	} else if _, ok := values[TLS]; !ok {
		t.Error("a roster with a tls block and no endpoints gives no tls values")
	}
	r.Hosts = nil
	if values, err := Derive(r); err != nil {
		t.Fatal(err)
	} else if _, ok := values[TLS]; ok {
		t.Error("a roster without a tls block gives tls values")
	}
}

func TestParseRefusesBadTLSRosters(t *testing.T) {
	cert := `{"dns_names": ["a.example.test"], "root": "ISRG Root X1", "expires_in_days": 60}`
	good := tlsEndpoint("a.example.test", cert)
	cases := map[string]struct{ endpoints, want string }{
		"version": {strings.Replace(good, `"TLSv1.2", "TLSv1.3"]`, `"TLSv1.2", "TLS13"]`, 1), `accepts "TLS13" has no entry in terms.tls_versions`},
		"root":    {strings.Replace(good, `"ISRG Root X1"`, `"DST Root CA X3"`, 1), `root "DST Root CA X3" has no entry in terms.tls_roots`},
		"negotiated version": {
			strings.Replace(good, `"accepts": ["TLSv1.2", "TLSv1.3"]`, `"accepts": ["TLSv1.2"]`, 1), "negotiates TLSv1.3, which it doesn't accept",
		},
		"twice":              {good + "," + strings.Replace(good, "a.example.test", "A.example.test", 1), "is listed twice"},
		"port":               {strings.Replace(good, `"port": 443`, `"port": 0`, 1), "port is 1 to 65535"},
		"no certificate key": {`{"host": "a.example.test", "port": 443, "accepts": ["TLSv1.2"], "negotiates": {"version": "TLSv1.2", "cipher_suite": "X"}}`, "or null for a server that presents none"},
		"no negotiates":      {`{"host": "a.example.test", "port": 443, "accepts": ["TLSv1.2"], "certificate": null}`, "gives no negotiates"},
		"closed with a certificate": {
			`{"host": "a.example.test", "port": 443, "accepts": [], "certificate": ` + cert + `}`, "accepts no version",
		},
		"no expiry":   {tlsEndpoint("a.example.test", `{"root": "ISRG Root X1"}`), "no expires_in_days"},
		"fingerprint": {tlsEndpoint("a.example.test", `{"expires_in_days": 60, "fingerprint_sha256": "9f2a"}`), "64 uppercase hex digits"},
		"ip address":  {tlsEndpoint("a.example.test", `{"expires_in_days": 60, "ip_addresses": ["192.0.2"]}`), "ip_addresses"},
		"dates out of order": {
			tlsEndpoint("a.example.test", `{"expires_in_days": 60, "not_before": "2027-01-10T00:00:00Z", "not_after": "2026-10-12T00:00:00Z"}`), "is after not_after",
		},
		"dates and days disagree": {
			tlsEndpoint("a.example.test", `{"expires_in_days": 60, "valid_from_days_ago": 60, "not_before": "2026-10-12T00:00:00Z", "not_after": "2027-01-10T00:00:00Z"}`),
			"valid_from_days_ago 60 and expires_in_days 60 give 120 days",
		},
		"host": {tlsEndpoint("bücher.example.test", cert), "A-label form"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(tlsRosterJSON(tc.endpoints)))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Parse() error = %v, want one containing %q", err, tc.want)
			}
		})
	}
	if _, err := Parse([]byte(strings.Replace(tlsRosterJSON(good), `"Self": "untrusted"`, `"Self": "distrusted"`, 1))); err == nil || !strings.Contains(err.Error(), `terms.tls_roots maps "Self" to "distrusted"`) {
		t.Errorf("Parse() error = %v, want one about the root's term", err)
	}
}

func TestTLSCloneIsDeep(t *testing.T) {
	r := tlsRoster(t, tlsEndpoint("a.example.test", `{"dns_names": ["a.example.test"], "expires_in_days": 60, "valid_from_days_ago": 3}`))
	c := r.Clone()
	c.Hosts.Endpoints[0].Accepts[0] = "TLSv1"
	c.Hosts.Endpoints[0].Certificate.DNSNames[0] = "b.example.test"
	*c.Hosts.Endpoints[0].Certificate.ValidFromDaysAgo = -1
	e := r.Hosts.Endpoints[0]
	if e.Accepts[0] != "TLSv1.2" || e.Certificate.DNSNames[0] != "a.example.test" || *e.Certificate.ValidFromDaysAgo != 3 {
		t.Errorf("changing the clone changed the roster: %+v %+v", e, *e.Certificate)
	}
}
