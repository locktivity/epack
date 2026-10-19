package componentsdk

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"sync/atomic"
)

// Dialer opens network connections the way net.Dialer does, for collectors
// that talk to hosts directly, such as one that checks TLS endpoints. It
// counts each dial in the run's call ledger with the dialed host and the
// code Classify gives a failure. A timeout or reset on the connection
// afterwards, such as during a TLS handshake, counts as that dial's error.
// Each dial is an operation named by its context (see WithOperation) or by
// default "dial". The SDK does not retry dials. Bound a dial with its
// context's deadline, and the exchange after it with the connection's.
type Dialer struct {
	run  *run
	dial func(ctx context.Context, network, address string) (net.Conn, error)
}

// NewDialer returns the dialer for the collector's own connections. It dials
// through a net.Dialer, or through InProcessOptions.Dial in a RunInProcess
// run.
func NewDialer(ctx CollectorContext) *Dialer {
	r := runOf(ctx)
	return &Dialer{run: r, dial: r.dialer()}
}

// DialContext connects to address on the named network, as
// net.Dialer.DialContext does. The connection it returns wraps the dialed
// one, so it is never a *net.TCPConn.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	op := operationOr(ctx, "dial")
	started := d.run.now()
	conn, err := d.dial(WithOperation(ctx, op), network, address)
	host, _, splitErr := net.SplitHostPort(address)
	if splitErr != nil {
		host = address
	}
	row := d.run.calls.addCall(op, "DIAL", strings.ToLower(host), "", Classify(err), d.run.now().Sub(started))
	if err != nil {
		return conn, err
	}
	return &ledgerConn{Conn: conn, calls: d.run.calls, op: op, row: row}, nil
}

// RootCAs returns the certificate authorities to verify dialed hosts'
// certificates against: pass it to x509.VerifyOptions.Roots or
// tls.Config.RootCAs. It is nil, meaning the system's roots, unless a
// RunInProcess run set InProcessOptions.RootCAs, as collectortest does for
// the test CA that signs its endpoints' certificates.
func (d *Dialer) RootCAs() *x509.CertPool {
	return d.run.rootCAs
}

// ledgerConn records the first timeout or reset on a dialed connection as
// its dial's error.
type ledgerConn struct {
	net.Conn
	calls  *ledger
	op     Operation
	row    int
	failed atomic.Bool
}

func (c *ledgerConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.note(err)
	return n, err
}

func (c *ledgerConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.note(err)
	return n, err
}

// note records err when it says the connection timed out or the far end
// dropped it. The end of the stream and a connection the collector closed
// itself are not failures.
func (c *ledgerConn) note(err error) {
	if err == nil || errors.Is(err, net.ErrClosed) {
		return
	}
	code := Classify(err)
	if code != CodeTimeout && code != CodeVendorError {
		return
	}
	if c.failed.CompareAndSwap(false, true) {
		c.calls.failCall(c.op, c.row, code)
	}
}
