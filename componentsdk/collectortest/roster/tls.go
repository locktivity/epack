package roster

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Normalized TLS terms. A protocol version is one of the TLS or SSL
// versions, and a root a certificate chains to is trusted when it is in the
// trust store a client checks against.
const (
	TLSv10 = "tls_1_0"
	TLSv11 = "tls_1_1"
	TLSv12 = "tls_1_2"
	TLSv13 = "tls_1_3"
	SSLv2  = "ssl_2_0"
	SSLv3  = "ssl_3_0"

	TLSRootTrusted   = "trusted"
	TLSRootUntrusted = "untrusted"
)

// tlsVersionNames gives each normalized version's name as the tls schema
// writes versions in its labels and summaries, such as TLS 1.3.
var tlsVersionNames = map[string]string{
	TLSv10: "TLS 1.0", TLSv11: "TLS 1.1", TLSv12: "TLS 1.2", TLSv13: "TLS 1.3",
	SSLv2: "SSL 2.0", SSLv3: "SSL 3.0",
}

// tlsSupportVersions are the versions the tls schema's protocol_support
// reports, each under its normalized term.
var tlsSupportVersions = []string{TLSv10, TLSv11, TLSv12, TLSv13}

// tlsExpiringSoonDays is the window the tls schema's expiring_soon uses.
const tlsExpiringSoonDays = 30

var tlsFingerprint = regexp.MustCompile(`^[A-F0-9]{64}$`)

// Hosts is the endpoints a TLS scan connects to, and what the server at each
// does. In a roster file:
//
//	"tls": {"endpoints": [{"host": "...", "port": 443,
//	  "accepts": ["TLSv1.2", "TLSv1.3"],
//	  "negotiates": {"version": "TLSv1.3", "cipher_suite": "TLS_AES_128_GCM_SHA256"},
//	  "certificate": {"subject_common_name": "...", "issuer_common_name": "...",
//	    "serial_number": "...", "not_before": "2026-01-01T00:00:00Z",
//	    "not_after": "2026-04-01T00:00:00Z", "valid_from_days_ago": 30,
//	    "expires_in_days": 59, "dns_names": [...], "ip_addresses": [...],
//	    "fingerprint_sha256": "...", "signature_algorithm": "...",
//	    "public_key_algorithm": "...", "chain": [...], "root": "..."}}]}
//
// and in the terms block:
//
//	"tls_versions": {"TLSv1.2": "tls_1_2", ...},
//	"tls_roots": {"ISRG Root X1": "trusted", ...}
//
// The endpoints are in the order the scan lists them, and no two have the
// same host and port. A host is a DNS name in A-label form or an IP address.
//
// accepts lists the protocol versions the server completes a handshake with,
// when a client offers that version alone and every cipher suite. An
// endpoint that completes none, because nothing listens there or it refuses
// every version, has an empty list. negotiates is the version and cipher
// suite the server picks for a client that offers every version, with the
// suite's IANA name. It is left out when accepts is empty.
//
// certificate is the leaf certificate the server presents, or null when it
// completes a handshake and presents none. It is left out, or null, when the
// server completes no handshake. Its names, serial number, fingerprint, and
// algorithms are as the artifact writes them, and not_before and not_after
// are absolute RFC 3339 times. Each may be left out when the roster can't fix
// it in advance, and Derive then gives no value for it. dns_names and
// ip_addresses are the subject alternative names; left out, the certificate
// has none.
//
// expires_in_days is the whole days from the run to not_after, rounded down,
// so it is negative once the certificate has expired. valid_from_days_ago is
// the whole days from not_before to the run, rounded down, so it is negative
// while the certificate is not yet valid. Left out, the certificate's
// validity began before the run.
//
// chain lists the certificates the server presents, leaf first, by name.
// root is the root the leaf chains to through them, and is left out when it
// chains to none, as when an intermediate is missing. A self-signed leaf is
// its own root.
type Hosts struct {
	Endpoints []TLSEndpoint
	Extra     Extra
}

// TLSEndpoint is one host and port a TLS scan connects to.
type TLSEndpoint struct {
	Host string
	Port int
	// Accepts lists the vendor protocol versions the server completes a
	// handshake with.
	Accepts []string
	// Version and CipherSuite are what the server negotiates with a client
	// that offers every version, empty when it accepts none.
	Version     string
	CipherSuite string
	// Certificate is the leaf the server presents, nil when it presents none
	// or completes no handshake.
	Certificate *TLSCertificate
	Extra       Extra
}

// TLSCertificate is the leaf certificate a server presents.
type TLSCertificate struct {
	SubjectCommonName  string
	IssuerCommonName   string
	SerialNumber       string
	NotBefore          string
	NotAfter           string
	ValidFromDaysAgo   *int
	ExpiresInDays      int
	DNSNames           []string
	IPAddresses        []string
	Fingerprint        string
	SignatureAlgorithm string
	PublicKeyAlgorithm string
	// Chain names the certificates presented, leaf first.
	Chain []string
	// Root is the root the leaf chains to, or empty when it chains to none.
	Root  string
	Extra Extra
}

// HostsTerms maps the vendor terms a roster's tls block uses to normalized
// ones.
type HostsTerms struct {
	TLSVersions map[string]string `json:"tls_versions"`
	TLSRoots    map[string]string `json:"tls_roots"`
}

var tlsDomain = domain{
	key: "tls",
	parse: func(r *Roster, raw json.RawMessage) error {
		h, err := parseTLS(raw)
		if err != nil {
			return err
		}
		r.Hosts = h
		return nil
	},
	validate: validateTLS,
	clone: func(c, r *Roster) {
		if r.Hosts != nil {
			c.Hosts = r.Hosts.clone()
		}
	},
	derive: deriveTLS,
	notDerived: map[string]map[string]string{TLS: {
		"/endpoints/*/errors":            "free text the schema doesn't enumerate",
		"/endpoints/*/assessment/issues": "free text the schema doesn't enumerate",
		"/diagnostics/endpoint_errors":   "free text the schema doesn't enumerate",
		"/diagnostics/warnings":          "free text the schema doesn't enumerate",
	}},
}

func parseTLS(raw json.RawMessage) (*Hosts, error) {
	var b struct {
		Endpoints []json.RawMessage `json:"endpoints"`
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, err
	}
	h := &Hosts{}
	var err error
	if h.Extra, err = extra(raw, "endpoints"); err != nil {
		return nil, err
	}
	for i, er := range b.Endpoints {
		e, err := parseTLSEndpoint(er)
		if err != nil {
			return nil, fmt.Errorf("endpoint %d: %w", i, err)
		}
		h.Endpoints = append(h.Endpoints, e)
	}
	return h, nil
}

func parseTLSEndpoint(raw json.RawMessage) (TLSEndpoint, error) {
	var e struct {
		Host       string   `json:"host"`
		Port       int      `json:"port"`
		Accepts    []string `json:"accepts"`
		Negotiates *struct {
			Version     string `json:"version"`
			CipherSuite string `json:"cipher_suite"`
		} `json:"negotiates"`
		Certificate json.RawMessage `json:"certificate"`
	}
	if err := json.Unmarshal(raw, &e); err != nil {
		return TLSEndpoint{}, err
	}
	out := TLSEndpoint{Host: e.Host, Port: e.Port, Accepts: e.Accepts}
	var err error
	if out.Extra, err = extra(raw, "host", "port", "accepts", "negotiates", "certificate"); err != nil {
		return TLSEndpoint{}, err
	}
	what := fmt.Sprintf("%s:%d", e.Host, e.Port)
	if e.Negotiates != nil {
		out.Version, out.CipherSuite = e.Negotiates.Version, e.Negotiates.CipherSuite
		if out.Version == "" || out.CipherSuite == "" {
			return TLSEndpoint{}, fmt.Errorf("%s: negotiates gives a version and a cipher_suite", what)
		}
	}
	certSet := len(e.Certificate) > 0 && string(e.Certificate) != "null"
	switch {
	case len(e.Accepts) > 0 && e.Negotiates == nil:
		return TLSEndpoint{}, fmt.Errorf("%s accepts a version and gives no negotiates", what)
	case len(e.Accepts) > 0 && len(e.Certificate) == 0:
		return TLSEndpoint{}, fmt.Errorf("%s accepts a version and gives no certificate; give one, or null for a server that presents none", what)
	case len(e.Accepts) == 0 && (e.Negotiates != nil || certSet):
		return TLSEndpoint{}, fmt.Errorf("%s accepts no version, so it negotiates nothing and presents no certificate", what)
	}
	if certSet {
		c, err := parseTLSCertificate(e.Certificate)
		if err != nil {
			return TLSEndpoint{}, fmt.Errorf("%s certificate: %w", what, err)
		}
		out.Certificate = c
	}
	return out, nil
}

func parseTLSCertificate(raw json.RawMessage) (*TLSCertificate, error) {
	var c struct {
		SubjectCommonName  string   `json:"subject_common_name"`
		IssuerCommonName   string   `json:"issuer_common_name"`
		SerialNumber       string   `json:"serial_number"`
		NotBefore          string   `json:"not_before"`
		NotAfter           string   `json:"not_after"`
		ValidFromDaysAgo   *int     `json:"valid_from_days_ago"`
		ExpiresInDays      *int     `json:"expires_in_days"`
		DNSNames           []string `json:"dns_names"`
		IPAddresses        []string `json:"ip_addresses"`
		Fingerprint        string   `json:"fingerprint_sha256"`
		SignatureAlgorithm string   `json:"signature_algorithm"`
		PublicKeyAlgorithm string   `json:"public_key_algorithm"`
		Chain              []string `json:"chain"`
		Root               string   `json:"root"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	if c.ExpiresInDays == nil {
		return nil, fmt.Errorf("no expires_in_days")
	}
	e, err := extra(raw, "subject_common_name", "issuer_common_name", "serial_number", "not_before", "not_after",
		"valid_from_days_ago", "expires_in_days", "dns_names", "ip_addresses", "fingerprint_sha256",
		"signature_algorithm", "public_key_algorithm", "chain", "root")
	if err != nil {
		return nil, err
	}
	return &TLSCertificate{
		SubjectCommonName: c.SubjectCommonName, IssuerCommonName: c.IssuerCommonName, SerialNumber: c.SerialNumber,
		NotBefore: c.NotBefore, NotAfter: c.NotAfter, ValidFromDaysAgo: c.ValidFromDaysAgo, ExpiresInDays: *c.ExpiresInDays,
		DNSNames: c.DNSNames, IPAddresses: c.IPAddresses, Fingerprint: c.Fingerprint,
		SignatureAlgorithm: c.SignatureAlgorithm, PublicKeyAlgorithm: c.PublicKeyAlgorithm,
		Chain: c.Chain, Root: c.Root, Extra: e,
	}, nil
}

func validateTLS(r *Roster) error {
	t := r.Terms
	for name, m := range map[string]struct {
		terms map[string]string
		allow []string
	}{
		"tls_versions": {t.TLSVersions, []string{TLSv10, TLSv11, TLSv12, TLSv13, SSLv2, SSLv3}},
		"tls_roots":    {t.TLSRoots, []string{TLSRootTrusted, TLSRootUntrusted}},
	} {
		for _, vendor := range sortedKeys(m.terms) {
			if !slices.Contains(m.allow, m.terms[vendor]) {
				return fmt.Errorf("terms.%s maps %q to %q, which is none of %v", name, vendor, m.terms[vendor], m.allow)
			}
		}
	}
	h := r.Hosts
	if h == nil {
		return nil
	}
	seen := map[string]bool{}
	for _, e := range h.Endpoints {
		what := fmt.Sprintf("endpoint %s:%d", e.Host, e.Port)
		if e.Host == "" || strings.ContainsFunc(e.Host, func(c rune) bool { return c > 0x7e || c <= ' ' }) {
			return fmt.Errorf("%s: host is a DNS name in A-label form or an IP address", what)
		}
		if e.Port < 1 || e.Port > 65535 {
			return fmt.Errorf("%s: port is 1 to 65535", what)
		}
		id := strings.ToLower(strings.TrimSuffix(e.Host, ".")) + ":" + strconv.Itoa(e.Port)
		if seen[id] {
			return fmt.Errorf("%s is listed twice", what)
		}
		seen[id] = true
		if err := mapped(t.TLSVersions, "tls_versions", what+" accepts", e.Accepts...); err != nil {
			return err
		}
		if e.Version != "" {
			if err := mapped(t.TLSVersions, "tls_versions", what+" negotiates", e.Version); err != nil {
				return err
			}
			if !slices.Contains(e.Accepts, e.Version) {
				return fmt.Errorf("%s negotiates %s, which it doesn't accept", what, e.Version)
			}
		}
		if e.Certificate != nil {
			if err := r.validateTLSCertificate(what+" certificate", *e.Certificate); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *Roster) validateTLSCertificate(what string, c TLSCertificate) error {
	if c.Fingerprint != "" && !tlsFingerprint.MatchString(c.Fingerprint) {
		return fmt.Errorf("%s fingerprint_sha256 %q is not 64 uppercase hex digits", what, c.Fingerprint)
	}
	for _, ip := range c.IPAddresses {
		if _, err := netip.ParseAddr(ip); err != nil {
			return fmt.Errorf("%s ip_addresses: %w", what, err)
		}
	}
	if c.Root != "" {
		if err := mapped(r.Terms.TLSRoots, "tls_roots", what+" root", c.Root); err != nil {
			return err
		}
	}
	var times [2]time.Time
	for i, s := range []string{c.NotBefore, c.NotAfter} {
		if s == "" {
			continue
		}
		at, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return fmt.Errorf("%s: %w", what, err)
		}
		times[i] = at
	}
	if c.NotBefore == "" || c.NotAfter == "" {
		return nil
	}
	lifetime := times[1].Sub(times[0])
	if lifetime < 0 {
		return fmt.Errorf("%s not_before %s is after not_after %s", what, c.NotBefore, c.NotAfter)
	}
	// Each relative count is rounded down, so the lifetime they give
	// together falls short of not_after less not_before by under two days.
	if c.ValidFromDaysAgo != nil {
		days := c.ExpiresInDays + *c.ValidFromDaysAgo
		if lifetime < time.Duration(days)*24*time.Hour || lifetime >= time.Duration(days+2)*24*time.Hour {
			return fmt.Errorf("%s runs %s from not_before to not_after, but valid_from_days_ago %d and expires_in_days %d give %d days", what, lifetime, *c.ValidFromDaysAgo, c.ExpiresInDays, days)
		}
	}
	return nil
}

func (h *Hosts) clone() *Hosts {
	c := &Hosts{Endpoints: slices.Clone(h.Endpoints), Extra: h.Extra}
	for i := range c.Endpoints {
		e := &c.Endpoints[i]
		e.Accepts = slices.Clone(e.Accepts)
		if e.Certificate != nil {
			cert := *e.Certificate
			cert.DNSNames, cert.IPAddresses, cert.Chain = slices.Clone(cert.DNSNames), slices.Clone(cert.IPAddresses), slices.Clone(cert.Chain)
			if cert.ValidFromDaysAgo != nil {
				days := *cert.ValidFromDaysAgo
				cert.ValidFromDaysAgo = &days
			}
			e.Certificate = &cert
		}
	}
	return c
}

// tlsAccepts reports whether e's server completes a handshake with version,
// a normalized version.
func (r *Roster) tlsAccepts(e TLSEndpoint, version string) bool {
	return slices.ContainsFunc(e.Accepts, func(v string) bool { return r.Terms.TLSVersions[v] == version })
}

// tlsAssessment is an endpoint's judgments, as the tls schema defines them.
type tlsAssessment struct {
	// modern is whether the server supports TLS 1.2 or TLS 1.3. A TLS 1.2
	// or TLS 1.3 handshake succeeds exactly then, so it is also reachable.
	modern, legacy bool
	// The certificate's judgments are all false for an endpoint that
	// presents no certificate.
	trusted, hostname, expired, expiringSoon, valid bool
}

// assessTLS judges e. A certificate is within its validity period from
// not_before through not_after, both included, so on the day of either it
// counts 0 days and is still valid. It expires within 30 days when it has
// fewer than 30 whole days left, since 30 whole days leaves 30 days or more.
func (r *Roster) assessTLS(e TLSEndpoint) tlsAssessment {
	a := tlsAssessment{
		modern: r.tlsAccepts(e, TLSv12) || r.tlsAccepts(e, TLSv13),
		legacy: r.tlsAccepts(e, TLSv10) || r.tlsAccepts(e, TLSv11),
	}
	c := e.Certificate
	if c == nil {
		return a
	}
	a.trusted = c.Root != "" && r.Terms.TLSRoots[c.Root] == TLSRootTrusted
	a.hostname = tlsMatchesHost(e.Host, c.DNSNames, c.IPAddresses)
	a.expired = c.ExpiresInDays < 0
	a.expiringSoon = !a.expired && c.ExpiresInDays < tlsExpiringSoonDays
	started := c.ValidFromDaysAgo == nil || *c.ValidFromDaysAgo >= 0
	a.valid = a.trusted && a.hostname && started && !a.expired
	return a
}

// tlsMatchesHost reports whether a certificate's subject alternative names
// identify host, as RFC 9525 section 6 matches them. An IP address matches
// an iPAddress entry octet for octet. A DNS name matches a dNSName entry
// label by label, ignoring ASCII case, where a * that is the whole
// left-most label matches any one label. A name with any other * is
// ignored, and the subject common name identifies nothing.
func tlsMatchesHost(host string, dnsNames, ipAddresses []string) bool {
	if addr, err := netip.ParseAddr(host); err == nil {
		return slices.ContainsFunc(ipAddresses, func(s string) bool {
			ip, err := netip.ParseAddr(s)
			return err == nil && ip == addr
		})
	}
	labels := func(name string) []string { return strings.Split(strings.ToLower(strings.TrimSuffix(name, ".")), ".") }
	want := labels(host)
	return slices.ContainsFunc(dnsNames, func(name string) bool {
		got := labels(name)
		wildcard := got[0] == "*"
		if strings.Count(name, "*") > 1 || (strings.Contains(name, "*") && !wildcard) || len(got) != len(want) {
			return false
		}
		for i := range got {
			if want[i] == "" || (got[i] != want[i] && (i > 0 || !wildcard)) {
				return false
			}
		}
		return true
	})
}

// deriveTLS gives the tls schema's endpoints, in roster order, and its
// summary over them. Each judgment follows the schema's summary from the
// facts the roster gives: what the server accepts, and the certificate it
// presents. An endpoint that presents no certificate has none valid,
// matching its host, expired or expiring soon.
func deriveTLS(r *Roster, out Values) error {
	h := r.Hosts
	if h == nil {
		return nil
	}
	v := out[TLS]
	if v == nil {
		v = map[string]any{}
		out[TLS] = v
	}
	var all []tlsAssessment
	for i, e := range h.Endpoints {
		at := "/endpoints/" + strconv.Itoa(i)
		a := r.assessTLS(e)
		v[at+"/host"] = e.Host
		v[at+"/port"] = e.Port
		v[at+"/reachable"] = a.modern
		for _, version := range tlsSupportVersions {
			v[at+"/tls/protocol_support/"+version] = r.tlsAccepts(e, version)
		}
		if e.Version != "" {
			v[at+"/tls/negotiated_version"] = tlsVersionNames[r.Terms.TLSVersions[e.Version]]
			v[at+"/tls/negotiated_cipher_suite"] = e.CipherSuite
		}
		if c := e.Certificate; c == nil {
			v[at+"/certificate"] = nil
		} else {
			putTLSCertificate(v, at+"/certificate", *c)
			v[at+"/certificate/trusted_chain"] = a.trusted
			v[at+"/certificate/hostname_valid"] = a.hostname
		}
		v[at+"/assessment/certificate_valid"] = a.valid
		v[at+"/assessment/hostname_valid"] = a.hostname
		v[at+"/assessment/expired"] = a.expired
		v[at+"/assessment/expiring_soon"] = a.expiringSoon
		v[at+"/assessment/modern_protocol"] = a.modern
		v[at+"/assessment/legacy_protocol_supported"] = a.legacy
		all = append(all, a)
	}
	v["/summary/total_endpoints"] = len(h.Endpoints)
	v["/summary/reachable_count"] = count(all, func(a tlsAssessment) bool { return a.modern })
	v["/summary/certificate_valid_count"] = count(all, func(a tlsAssessment) bool { return a.valid })
	v["/summary/hostname_valid_count"] = count(all, func(a tlsAssessment) bool { return a.hostname })
	v["/summary/modern_protocol_count"] = count(all, func(a tlsAssessment) bool { return a.modern })
	v["/summary/expiring_soon_count"] = count(all, func(a tlsAssessment) bool { return a.expiringSoon })
	v["/summary/legacy_protocol_supported_count"] = count(all, func(a tlsAssessment) bool { return a.legacy })
	return nil
}

// putTLSCertificate adds the certificate's facts to v at at, each the roster
// gives.
func putTLSCertificate(v map[string]any, at string, c TLSCertificate) {
	for field, s := range map[string]string{
		"subject_common_name": c.SubjectCommonName, "issuer_common_name": c.IssuerCommonName,
		"serial_number": c.SerialNumber, "not_before": c.NotBefore, "not_after": c.NotAfter,
		"fingerprint_sha256": c.Fingerprint, "signature_algorithm": c.SignatureAlgorithm,
		"public_key_algorithm": c.PublicKeyAlgorithm,
	} {
		if s != "" {
			v[at+"/"+field] = s
		}
	}
	v[at+"/expires_in_days"] = c.ExpiresInDays
	v[at+"/dns_names"] = append([]string{}, c.DNSNames...)
	v[at+"/ip_addresses"] = append([]string{}, c.IPAddresses...)
	if len(c.Chain) > 0 {
		v[at+"/chain_length"] = len(c.Chain)
	}
}
