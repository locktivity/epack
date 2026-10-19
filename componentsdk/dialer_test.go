package componentsdk

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk/internal/outputcheck"
)

// fakeDial connects every dial to a pipe, except that an address in errs
// fails with its error, and records the operation each dial carried.
type fakeDial struct {
	errs map[string]error

	mu  sync.Mutex
	ops []string
}

func (f *fakeDial) dial(ctx context.Context, network, address string) (net.Conn, error) {
	op, _ := OperationOf(ctx)
	f.mu.Lock()
	f.ops = append(f.ops, op.Name)
	f.mu.Unlock()
	if err := f.errs[address]; err != nil {
		return nil, err
	}
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}

func TestDialerNamesAndCountsEachDial(t *testing.T) {
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}}
	slow := &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}
	fake := &fakeDial{errs: map[string]error{"refused.example.com:443": refused, "slow.example.com:443": slow}}
	c := testContext(nil)
	c.run.dial = fake.dial
	d := NewDialer(c)
	conn, err := d.DialContext(context.Background(), "tcp", "API.Example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	probe := WithOperation(context.Background(), Operation{Name: "tls.probe"})
	if _, err := d.DialContext(probe, "tcp", "refused.example.com:443"); err != refused {
		t.Errorf("err = %v, want the dial's error unchanged", err)
	}
	if _, err := d.DialContext(probe, "tcp", "slow.example.com:443"); err != slow {
		t.Errorf("err = %v, want the dial's error unchanged", err)
	}

	if got := strings.Join(fake.ops, ","); got != "dial,tls.probe,tls.probe" {
		t.Errorf("the dialer saw operations %s", got)
	}
	ops := c.run.calls.operations()
	if len(ops) != 2 || ops[0].Name != "dial" || ops[0].Calls != 1 || len(ops[0].Errors) != 0 || len(ops[0].Statuses) != 0 {
		t.Fatalf("operations = %+v", ops)
	}
	if probes := ops[1]; probes.Calls != 2 || probes.Attempts != 2 || probes.Errors[CodeVendorError] != 1 || probes.Errors[CodeTimeout] != 1 {
		t.Errorf("tls.probe = %+v, want a refused dial and a timeout", probes)
	}
	rows, _ := c.run.calls.requests()
	if len(rows) != 3 || rows[0].Method != "DIAL" || rows[0].Host != "api.example.com" || rows[0].Route != "" || rows[0].Error != "" {
		t.Fatalf("rows = %+v", rows)
	}
	if rows[1].Error != CodeVendorError || rows[2].Error != CodeTimeout {
		t.Errorf("rows = %+v", rows)
	}
	if d.RootCAs() != nil {
		t.Error("RootCAs outside a test run should be nil, meaning the system's roots")
	}
}

// brokenConn is a connection whose reads fail with err.
type brokenConn struct {
	net.Conn
	err error
}

func (c brokenConn) Read([]byte) (int, error) { return 0, c.err }

func TestDialerCountsAFailureOnTheConnection(t *testing.T) {
	readErrs := map[string]error{
		"reset.example.com:443":  &net.OpError{Op: "read", Net: "tcp", Err: &os.SyscallError{Syscall: "read", Err: syscall.ECONNRESET}},
		"slow.example.com:443":   &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded},
		"closed.example.com:443": &net.OpError{Op: "read", Net: "tcp", Err: net.ErrClosed},
		"done.example.com:443":   io.EOF,
	}
	var servers []net.Conn
	c := testContext(nil)
	c.run.dial = func(_ context.Context, _, address string) (net.Conn, error) {
		client, server := net.Pipe()
		servers = append(servers, server)
		if err := readErrs[address]; err != nil {
			return brokenConn{Conn: client, err: err}, nil
		}
		return client, nil
	}
	defer func() {
		for _, s := range servers {
			_ = s.Close()
		}
	}()
	d := NewDialer(c)
	for address, want := range readErrs {
		op := "conn." + strings.SplitN(address, ".", 2)[0]
		conn, err := d.DialContext(WithOperation(context.Background(), Operation{Name: op}), "tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, want) {
				t.Errorf("%s: read err = %v, want %v unchanged", address, err, want)
			}
		}
		_ = conn.Close()
	}

	handshake := WithOperation(context.Background(), Operation{Name: "tls.handshake"})
	conn, err := d.DialContext(handshake, "tcp", "stalled.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(-time.Second))
	if err := tls.Client(conn, &tls.Config{ServerName: "stalled.example.com"}).Handshake(); Classify(err) != CodeTimeout {
		t.Errorf("handshake err = %v, want a timeout", err)
	}
	_ = conn.Close()

	want := map[string]map[Code]int{
		"conn.closed":   nil,
		"conn.done":     nil,
		"conn.reset":    {CodeVendorError: 1},
		"conn.slow":     {CodeTimeout: 1},
		"tls.handshake": {CodeTimeout: 1},
	}
	for _, op := range c.run.calls.operations() {
		if op.Calls != 1 || !reflect.DeepEqual(op.Errors, want[op.Name]) {
			t.Errorf("%s = %+v, want one call with errors %v", op.Name, op, want[op.Name])
		}
	}
	rows, _ := c.run.calls.requests()
	for _, row := range rows {
		if got := row.Error; (got == "") != (want[row.Operation] == nil) {
			t.Errorf("row for %s has error %q, want the connection's failure", row.Operation, got)
		}
	}
}

func TestDialerUsesTheNetworkOutsideTests(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local listener unavailable: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		if conn, err := ln.Accept(); err == nil {
			_ = conn.Close()
		}
	}()
	conn, err := NewDialer(testContext(nil)).DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial without a test dialer: %v", err)
	}
	_ = conn.Close()
}

func TestRunInProcessTakesAResolverDialAndRootCAs(t *testing.T) {
	pool := x509.NewCertPool()
	fake := &fakeDial{}
	handler := func(ctx CollectorContext) error {
		resolver, dialer := NewResolver(ctx), NewDialer(ctx)
		if dialer.RootCAs() != pool {
			return errors.New("RootCAs is not the run's pool")
		}
		_, err := resolver.LookupTXT(ctx.Context(), "missing.example.com")
		if err == nil {
			return errors.New("the lookup should not find missing.example.com")
		}
		conn, err := dialer.DialContext(ctx.Context(), "tcp", "example.com:443")
		if err != nil {
			return err
		}
		_ = conn.Close()
		return ctx.Emit([]CollectedArtifact{{Data: map[string]any{}, Path: "artifacts/demo.json"}})
	}
	res := RunInProcess(CollectorSpec{Name: "demo"}, handler, InProcessOptions{
		Config:   map[string]any{"level": "audit"},
		Resolver: &fakeResolver{errs: map[string]error{"missing.example.com": &net.DNSError{Err: "no such host", IsNotFound: true}}},
		Dial:     fake.dial,
		RootCAs:  pool,
	})
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("exit = %d: %s", res.ExitCode, res.Stderr)
	}
	ops := res.Result.Calls.Operations
	if len(ops) != 2 || ops[0].Name != "dial" || ops[1].Name != "dns.txt" || ops[1].Statuses[rcodeNXDomain] != 1 {
		t.Errorf("operations = %+v", ops)
	}
	if len(res.Result.Calls.Requests) != 2 {
		t.Errorf("requests = %+v, want the lookup and the dial", res.Result.Calls.Requests)
	}
	schema, err := outputcheck.Compile(ResultSchemaJSON())
	if err != nil {
		t.Fatal(err)
	}
	result := res.Artifacts[len(res.Artifacts)-1]
	doc, err := outputcheck.Decode(result.Data)
	if err != nil {
		t.Fatal(err)
	}
	if findings := outputcheck.Validate(schema, result.Path, doc); len(findings) > 0 {
		t.Errorf("the result with DNS and dial rows does not match its schema: %+v", findings)
	}
}
