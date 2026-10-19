package collectortest

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk"
)

func TestTheKitAnswersLookupsLikeAResolver(t *testing.T) {
	srv, err := newDNSServer(Scenario{DNS: []DNSRecord{
		{Name: "Example.com.", Type: "txt", Values: []string{"v=spf1 -all", "verification=abc"}},
		{Name: "example.com", Type: "MX", Values: []string{"20 mx2.example.com", "10 mx1.example.com."}},
		{Name: "example.com", Type: "A", Values: []string{"192.0.2.10"}},
		{Name: "example.com", Type: "AAAA", Values: []string{"2001:db8::10"}},
		{Name: "example.com", Type: "NS", Values: []string{"ns1.example.net"}},
		{Name: "www.example.com", Type: "CNAME", Values: []string{"example.com."}},
		{Name: "_dmarc.example.com", Type: "CNAME", Values: []string{"_dmarc.provider.example"}},
		{Name: "_dmarc.provider.example", Type: "TXT", Values: []string{"v=DMARC1; p=reject"}},
		{Name: "broken.example.com", Type: "TXT", Rcode: "servfail"},
		{Name: "gone.example.com", Type: "TXT", Rcode: "NXDOMAIN"},
		{Name: "v4.example.com", Type: "A", Values: []string{"192.0.2.20"}},
		{Name: "v4.example.com", Type: "AAAA", Rcode: "SERVFAIL"},
		{Name: "v6.example.com", Type: "AAAA", Rcode: "SERVFAIL"},
		{Name: "loop1.example.com", Type: "CNAME", Values: []string{"loop2.example.com"}},
		{Name: "loop2.example.com", Type: "CNAME", Values: []string{"loop1.example.com"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	answer := func(v any, err error) string {
		if err != nil {
			return "error: " + err.Error()
		}
		return fmt.Sprint(v)
	}
	mxHosts := func(mx []*net.MX, err error) (string, error) {
		hosts := make([]string, 0, len(mx))
		for _, m := range mx {
			hosts = append(hosts, fmt.Sprintf("%d %s", m.Pref, m.Host))
		}
		return strings.Join(hosts, ","), err
	}
	nsHosts := func(ns []*net.NS, err error) (string, error) {
		hosts := make([]string, 0, len(ns))
		for _, n := range ns {
			hosts = append(hosts, n.Host)
		}
		return strings.Join(hosts, ","), err
	}
	cases := []struct{ name, got, want string }{
		{"TXT", answer(srv.LookupTXT(ctx, "EXAMPLE.com")), "[v=spf1 -all verification=abc]"},
		{"MX", answer(mxHosts(srv.LookupMX(ctx, "example.com"))), "10 mx1.example.com.,20 mx2.example.com."},
		{"NS", answer(nsHosts(srv.LookupNS(ctx, "example.com"))), "ns1.example.net."},
		{"host", answer(srv.LookupHost(ctx, "example.com")), "[192.0.2.10 2001:db8::10]"},
		{"IP addresses", answer(srv.LookupIPAddr(ctx, "example.com")), "[{192.0.2.10 } {2001:db8::10 }]"},
		{"IP literal", answer(srv.LookupHost(ctx, "198.51.100.1")), "[198.51.100.1]"},
		{"CNAME", answer(srv.LookupCNAME(ctx, "www.example.com")), "example.com."},
		{"own canonical name", answer(srv.LookupCNAME(ctx, "example.com")), "example.com."},
		{"TXT through a CNAME", answer(srv.LookupTXT(ctx, "_dmarc.example.com")), "[v=DMARC1; p=reject]"},
		{"one family failing", answer(srv.LookupHost(ctx, "v4.example.com")), "[192.0.2.20]"},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %s, want %s", tc.name, tc.got, tc.want)
		}
	}

	notFound := map[string]error{}
	_, notFound["unknown name"] = srv.LookupTXT(ctx, "nothing.example.com")
	_, notFound["no MX at a name with TXT"] = srv.LookupMX(ctx, "_dmarc.provider.example")
	_, notFound["NXDOMAIN rcode"] = srv.LookupTXT(ctx, "gone.example.com")
	_, notFound["no CNAME or address"] = srv.LookupCNAME(ctx, "_dmarc.provider.example")
	for name, err := range notFound {
		dnsErr, ok := err.(*net.DNSError)
		if !ok || !dnsErr.IsNotFound || dnsErr.Err != "no such host" {
			t.Errorf("%s: err = %#v, want net.Resolver's not-found error", name, err)
		}
	}
	failed := map[string]error{}
	_, failed["SERVFAIL rcode"] = srv.LookupTXT(ctx, "broken.example.com")
	_, failed["the only family failing"] = srv.LookupHost(ctx, "v6.example.com")
	_, failed["a CNAME loop"] = srv.LookupTXT(ctx, "loop1.example.com")
	for name, err := range failed {
		dnsErr, ok := err.(*net.DNSError)
		if !ok || dnsErr.IsNotFound || !dnsErr.IsTemporary || dnsErr.Err != "server misbehaving" {
			t.Errorf("%s: err = %#v, want net.Resolver's SERVFAIL error", name, err)
		}
		if code := componentsdk.Classify(err); code != componentsdk.CodeVendorError {
			t.Errorf("%s classifies as %s, want vendor_error", name, code)
		}
	}
}

func TestDNSRecordsAreChecked(t *testing.T) {
	for _, rec := range []DNSRecord{
		{Type: "TXT", Values: []string{"x"}},
		{Name: "example.com", Type: "SRV", Values: []string{"x"}},
		{Name: "example.com", Type: "A", Values: []string{"2001:db8::1"}},
		{Name: "example.com", Type: "AAAA", Values: []string{"192.0.2.1"}},
		{Name: "example.com", Type: "MX", Values: []string{"mx.example.com"}},
		{Name: "example.com", Type: "CNAME", Values: []string{"a.example.", "b.example."}},
		{Name: "example.com", Type: "TXT"},
		{Name: "example.com", Type: "TXT", Rcode: "REFUSED"},
	} {
		if _, err := newDNSServer(Scenario{Name: "bad", DNS: []DNSRecord{rec}}); err == nil {
			t.Errorf("record %+v should be rejected", rec)
		}
	}
}

// dnsDemo is a small collector that reads a domain's SPF and DMARC records
// and mail servers, with one bug behind a switch. With the switch off it
// tells a record that does not exist from a lookup that failed.
type dnsDemo struct {
	failureAsNone bool // reads a failed SPF lookup as "no SPF record"
}

const dnsDemoPath = "artifacts/dnsdemo.json"

func (d dnsDemo) run(ctx componentsdk.CollectorContext) error {
	resolver := componentsdk.NewResolver(ctx)
	rec := componentsdk.Records(ctx)
	domain, _ := ctx.Config()["domain"].(string)
	named := func(op string) context.Context {
		return componentsdk.WithOperation(ctx.Context(), componentsdk.Operation{Name: op})
	}
	answered := func(pointer string, err error) bool {
		if err == nil || isNotFound(err) {
			return true
		}
		rec.NotCollected(componentsdk.Location{Path: dnsDemoPath, Pointer: pointer}, err)
		return false
	}
	has := func(records []string, prefix string) bool {
		for _, r := range records {
			if strings.HasPrefix(strings.ToLower(r), prefix) {
				return true
			}
		}
		return false
	}
	out := map[string]any{"domain": domain}
	txt, err := resolver.LookupTXT(named("dns.spf.lookup"), domain)
	if d.failureAsNone || answered("/has_spf", err) {
		out["has_spf"] = has(txt, "v=spf1")
	}
	txt, err = resolver.LookupTXT(named("dns.dmarc.lookup"), "_dmarc."+domain)
	if answered("/has_dmarc", err) {
		out["has_dmarc"] = has(txt, "v=dmarc1")
	}
	mx, err := resolver.LookupMX(ctx.Context(), domain)
	if answered("/mx", err) {
		hosts := []any{}
		for _, m := range mx {
			hosts = append(hosts, strings.TrimSuffix(m.Host, "."))
		}
		out["mx"] = hosts
	}
	return ctx.Emit([]componentsdk.CollectedArtifact{{Data: out, Path: dnsDemoPath}})
}

func dnsDemoRecords(spf DNSRecord) []DNSRecord {
	return []DNSRecord{
		spf,
		{Name: "_dmarc.example.com", Type: "CNAME", Values: []string{"example.com._dmarc.provider.example."}},
		{Name: "example.com._dmarc.provider.example", Type: "TXT", Values: []string{"v=DMARC1; p=reject"}},
		{Name: "example.com", Type: "MX", Values: []string{"20 mx2.example.com.", "10 mx1.example.com."}},
	}
}

func dnsDemoSuite(d dnsDemo) Suite {
	return Suite{
		Spec:   componentsdk.CollectorSpec{Name: "dnsdemo", Version: "0.0.1"},
		Run:    d.run,
		Config: map[string]any{"domain": "example.com", "level": "audit"},
		Scenarios: []Scenario{
			{
				Name: "clean",
				DNS:  dnsDemoRecords(DNSRecord{Name: "example.com", Type: "TXT", Values: []string{"verification=abc", "v=spf1 include:_spf.example.net -all"}}),
				Expect: map[string]map[string]any{dnsDemoPath: {
					"/has_spf": true, "/has_dmarc": true, "/mx": []any{"mx1.example.com", "mx2.example.com"},
				}},
			},
			{
				Name:   "no records",
				Expect: map[string]map[string]any{dnsDemoPath: {"/has_spf": false, "/has_dmarc": false, "/mx": []any{}}},
			},
			{
				Name: "SPF lookup fails",
				DNS:  dnsDemoRecords(DNSRecord{Name: "example.com", Type: "TXT", Rcode: "SERVFAIL"}),
				Expect: map[string]map[string]any{
					dnsDemoPath: {"/has_spf": nil, "/has_dmarc": true},
					"artifacts/dnsdemo.collector-result.json": {"/outcome/code": "vendor_error", "/gaps/0/pointer": "/has_spf"},
				},
			},
		},
		Operations: []string{"dns.spf.lookup", "dns.dmarc.lookup", "dns.mx"},
	}
}

func TestADNSOnlyCollectorPasses(t *testing.T) {
	report := checkSuite(t, dnsDemoSuite(dnsDemo{}))
	for _, v := range report.Violations {
		t.Errorf("%s/%s: %s", v.Check, v.Case, v.Message)
	}
	if got := strings.Join(report.Operations, ","); got != "dns.dmarc.lookup,dns.mx,dns.spf.lookup" {
		t.Errorf("operations = %s", got)
	}
	// Three scenarios, two determinism runs, three levels, and the three DNS
	// faults on each of three operations. No credentials or sensitivity runs,
	// and no HTTP faults.
	if report.Runs != 3+2+3+9 {
		t.Errorf("runs = %d, want %d", report.Runs, 3+2+3+9)
	}
}

// noRecordsFirst makes the scenario with no records the clean one, which the
// fault matrix runs on.
func noRecordsFirst(s Suite) Suite {
	s.Scenarios = append([]Scenario{s.Scenarios[1], s.Scenarios[0]}, s.Scenarios[2:]...)
	return s
}

// A failed lookup read as "no record" changes no value when the clean answer
// is already "no record", so only the missing gap shows it.
func TestTheKitCatchesAFailureReadAsNoRecordWhereNoneExists(t *testing.T) {
	for _, v := range checkSuite(t, noRecordsFirst(dnsDemoSuite(dnsDemo{}))).Violations {
		t.Errorf("%s/%s: %s", v.Check, v.Case, v.Message)
	}
	report := checkSuite(t, noRecordsFirst(dnsDemoSuite(dnsDemo{failureAsNone: true})))
	codes := map[string]componentsdk.Code{"servfail": componentsdk.CodeVendorError, "timeout": componentsdk.CodeTimeout, "refused": componentsdk.CodeVendorError}
	for fault, code := range codes {
		expectCase(t, report, "dns.spf.lookup/"+fault+"/all", fmt.Sprintf("the fault reached dns.spf.lookup but left no new gap with code %s", code))
	}
	for _, v := range violationsOf(report, "faults") {
		if !strings.HasPrefix(v.Case, "dns.spf.lookup/") {
			t.Errorf("only the SPF lookup reads a failure as no record: %s: %s", v.Case, v.Message)
		}
	}
}

// expectCase fails unless report has a faults violation in the named case
// whose message contains want.
func expectCase(t *testing.T, report *Report, name, want string) {
	t.Helper()
	for _, v := range violationsOf(report, "faults") {
		if v.Case == name && strings.Contains(v.Message, want) {
			return
		}
	}
	t.Errorf("no faults violation in %s saying %q; got %+v", name, want, violationsOf(report, "faults"))
}

func TestAFaultNeedNotLeaveAGapWhereExempt(t *testing.T) {
	t.Run("a semantic declares its meaning", func(t *testing.T) {
		s := noRecordsFirst(dnsDemoSuite(dnsDemo{failureAsNone: true}))
		s.Semantics = []Semantic{{Operation: "dns.spf.lookup", Fault: "servfail", Meaning: "the domain publishes no SPF record"}}
		report := checkSuite(t, s)
		for _, v := range violationsOf(report, "faults") {
			if strings.HasPrefix(v.Case, "dns.spf.lookup/servfail/") {
				t.Errorf("a declared meaning should exempt the fault: %s", v.Message)
			}
		}
		expectCase(t, report, "dns.spf.lookup/timeout/all", "left no new gap")
	})
	t.Run("an insensitive operation", func(t *testing.T) {
		s := mixedSuite(demo{})
		s.Insensitive = []string{"demo.me.get"}
		expectCase(t, checkSuite(t, s), "a.lookup/servfail/all", "the fault reached a.lookup but left no new gap with code vendor_error")
		for _, v := range checkSuite(t, mixedSuite(demo{})).Violations {
			t.Errorf("an operation listed in Suite.Insensitive need not leave a gap: %s/%s: %s", v.Check, v.Case, v.Message)
		}
	})
	t.Run("a required operation fails the run", func(t *testing.T) {
		s := demoSuite(demo{})
		s.Insensitive = nil
		for _, v := range checkSuite(t, s).Violations {
			t.Errorf("a required operation that fails the run need not leave a gap: %s/%s: %s", v.Check, v.Case, v.Message)
		}
	})
}

func TestTheKitCatchesAFailedLookupReadAsNoRecord(t *testing.T) {
	report := checkSuite(t, dnsDemoSuite(dnsDemo{failureAsNone: true}))
	for _, fault := range []string{"servfail", "timeout", "refused"} {
		expectViolation(t, report, "faults", "dns.spf.lookup/"+fault+"/all")
	}
	expectViolation(t, report, "faults", "artifacts/dnsdemo.json /has_spf: value changed from true to false")
	expectViolation(t, report, "scenario", "artifacts/dnsdemo.json /has_spf is false, want null")
}

// mixedSuite runs d after a DNS lookup whose answer it never uses.
func mixedSuite(d demo) Suite {
	s := demoSuite(d)
	s.Run = func(ctx componentsdk.CollectorContext) error {
		lookup := componentsdk.WithOperation(ctx.Context(), componentsdk.Operation{Name: "a.lookup"})
		_, _ = componentsdk.NewResolver(ctx).LookupTXT(lookup, "demo.test")
		return d.run(ctx)
	}
	s.Operations = append(s.Operations, "a.lookup")
	s.Insensitive = append(s.Insensitive, "a.lookup")
	return s
}

func TestHTTPChecksSkipTheDNSCallsOfAMixedCollector(t *testing.T) {
	report := checkSuite(t, mixedSuite(demo{noHostList: true}))
	expectViolation(t, report, "credentials", "X-Demo-Token")
	for _, v := range report.Violations {
		if v.Check != "credentials" {
			t.Errorf("%s/%s: %s", v.Check, v.Case, v.Message)
		}
	}
}
