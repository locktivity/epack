package componentsdk

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
)

// fakeResolver answers every lookup, except that a name in errs fails with
// its error, and records the operation each lookup carried.
type fakeResolver struct {
	errs map[string]error

	mu  sync.Mutex
	ops []string
}

func (f *fakeResolver) start(ctx context.Context, name string) error {
	op, _ := OperationOf(ctx)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ops = append(f.ops, op.Name)
	return f.errs[name]
}

func (f *fakeResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if err := f.start(ctx, name); err != nil {
		return nil, err
	}
	return []string{"v=spf1 -all"}, nil
}

func (f *fakeResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	if err := f.start(ctx, name); err != nil {
		return nil, err
	}
	return []*net.MX{{Host: "mx.example.com.", Pref: 10}}, nil
}

func (f *fakeResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	if err := f.start(ctx, host); err != nil {
		return nil, err
	}
	return []string{"192.0.2.1"}, nil
}

func (f *fakeResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if err := f.start(ctx, host); err != nil {
		return nil, err
	}
	return []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}}, nil
}

func (f *fakeResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	if err := f.start(ctx, host); err != nil {
		return "", err
	}
	return "example.com.", nil
}

func (f *fakeResolver) LookupNS(ctx context.Context, name string) ([]*net.NS, error) {
	if err := f.start(ctx, name); err != nil {
		return nil, err
	}
	return []*net.NS{{Host: "ns1.example.com."}}, nil
}

func TestResolverNamesAndCountsEachLookup(t *testing.T) {
	fake := &fakeResolver{}
	c := testContext(nil)
	c.run.resolver = fake
	r := NewResolver(c)
	ctx := context.Background()
	if txt, err := r.LookupTXT(ctx, "Example.COM."); err != nil || txt[0] != "v=spf1 -all" {
		t.Fatalf("LookupTXT = %v, %v", txt, err)
	}
	if mx, err := r.LookupMX(ctx, "example.com"); err != nil || mx[0].Host != "mx.example.com." {
		t.Fatalf("LookupMX = %v, %v", mx, err)
	}
	if _, err := r.LookupHost(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.LookupIPAddr(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	if cname, err := r.LookupCNAME(ctx, "www.example.com"); err != nil || cname != "example.com." {
		t.Fatalf("LookupCNAME = %q, %v", cname, err)
	}
	if _, err := r.LookupNS(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.LookupTXT(WithOperation(ctx, Operation{Name: "dns.spf.lookup"}), "example.com"); err != nil {
		t.Fatal(err)
	}

	want := "dns.txt,dns.mx,dns.host,dns.ipaddr,dns.cname,dns.ns,dns.spf.lookup"
	if got := strings.Join(fake.ops, ","); got != want {
		t.Errorf("the resolver saw operations %s, want %s", got, want)
	}
	for _, op := range c.run.calls.operations() {
		if op.Calls != 1 || op.Attempts != 1 || op.Retries != 0 || op.Statuses[rcodeNoError] != 1 || len(op.Errors) != 0 {
			t.Errorf("%s = %+v, want one NOERROR call", op.Name, op)
		}
	}
	rows, _ := c.run.calls.requests()
	methods := make([]string, 0, len(rows))
	for _, row := range rows {
		methods = append(methods, row.Method)
		if row.Route != "" || row.Rcode != rcodeNoError || row.Attempt != 1 || row.Status != 0 {
			t.Errorf("row = %+v, want an answered lookup with no route or status", row)
		}
	}
	if got := strings.Join(methods, ","); got != "DNS TXT,DNS MX,DNS A/AAAA,DNS A/AAAA,DNS CNAME,DNS NS,DNS TXT" {
		t.Errorf("methods = %s", got)
	}
	if rows[0].Host != "example.com" || rows[4].Host != "www.example.com" {
		t.Errorf("hosts = %q and %q, want the queried names in lower case without the root dot", rows[0].Host, rows[4].Host)
	}
}

func TestResolverTellsAnswersFromFailures(t *testing.T) {
	failures := map[string]error{
		"missing.example.com": &net.DNSError{Err: "no such host", Name: "missing.example.com", IsNotFound: true},
		"broken.example.com":  &net.DNSError{Err: "server misbehaving", Name: "broken.example.com", IsTemporary: true},
		"slow.example.com":    &net.DNSError{Err: "i/o timeout", Name: "slow.example.com", IsTimeout: true, IsTemporary: true},
		"refused.example.com": &net.DNSError{Err: "server misbehaving", Name: "refused.example.com"},
		"socket.example.com":  &net.DNSError{Err: "read udp 192.0.2.9:53: connection refused", Name: "socket.example.com", IsTemporary: true},
	}
	c := testContext(nil)
	c.run.resolver = &fakeResolver{errs: failures}
	r := NewResolver(c)
	ctx := WithOperation(context.Background(), Operation{Name: "dns.spf.lookup"})
	names := []string{"example.com", "missing.example.com", "broken.example.com", "slow.example.com", "refused.example.com", "socket.example.com"}
	for _, name := range names {
		_, err := r.LookupTXT(ctx, name)
		if err != failures[name] {
			t.Errorf("LookupTXT(%s) err = %v, want the resolver's error unchanged", name, err)
		}
	}
	if _, err := r.LookupTXT(ctx, "missing.example.com"); err == nil {
		t.Fatal("a not-found answer should still return its error")
	} else if dnsErr, ok := err.(*net.DNSError); !ok || !dnsErr.IsNotFound {
		t.Errorf("err = %#v, want a *net.DNSError with IsNotFound, as a type assertion reads it", err)
	}

	ops := c.run.calls.operations()
	if len(ops) != 1 {
		t.Fatalf("operations = %+v", ops)
	}
	op := ops[0]
	if op.Statuses[rcodeNoError] != 1 || op.Statuses[rcodeNXDomain] != 2 || op.Statuses[rcodeServFail] != 1 || len(op.Statuses) != 3 {
		t.Errorf("statuses = %v, want NOERROR 1, NXDOMAIN 2, SERVFAIL 1", op.Statuses)
	}
	if op.Errors[CodeVendorError] != 3 || op.Errors[CodeTimeout] != 1 || len(op.Errors) != 2 {
		t.Errorf("errors = %v, want vendor_error for SERVFAIL, REFUSED, and the socket error, timeout for the timeout, and none for NXDOMAIN", op.Errors)
	}
	rows, _ := c.run.calls.requests()
	got := make([]string, 0, len(rows))
	for _, row := range rows {
		got = append(got, row.Host+":"+row.Rcode+":"+string(row.Error))
	}
	want := "example.com:NOERROR:,missing.example.com:NXDOMAIN:,broken.example.com:SERVFAIL:vendor_error," +
		"slow.example.com::timeout,refused.example.com::vendor_error,socket.example.com::vendor_error,missing.example.com:NXDOMAIN:"
	if strings.Join(got, ",") != want {
		t.Errorf("rows = %s\nwant %s", strings.Join(got, ","), want)
	}
}

func TestResolverUsesTheNetworkOutsideTests(t *testing.T) {
	if r := NewResolver(testContext(nil)); r.resolver != DNSResolver(net.DefaultResolver) {
		t.Errorf("resolver = %T, want net.DefaultResolver", r.resolver)
	}
}
