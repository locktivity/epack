package collectortest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/locktivity/epack/componentsdk"
)

// Endpoint is a server the collector can dial, such as a host whose
// certificate and TLS versions it checks.
type Endpoint struct {
	// Address is the host and port the collector dials, such as
	// "example.com:443".
	Address string

	// MinVersion and MaxVersion bound the TLS versions the endpoint accepts,
	// such as tls.VersionTLS10. Zero means Go's defaults, TLS 1.2 and TLS 1.3.
	MinVersion uint16
	MaxVersion uint16

	// Cert is the certificate the endpoint presents.
	Cert Cert

	// Plaintext makes the endpoint speak no TLS: it answers whatever it is
	// sent with an HTTP 400 and hangs up.
	Plaintext bool

	// Refused makes the endpoint a closed port: a dial to it is refused, as
	// a dial to an address with no endpoint is, but the scenario check does
	// not report it.
	Refused bool
}

// Cert describes an endpoint's certificate. A test CA signs it, and the CA's
// pool is what the collector's componentsdk.Dialer.RootCAs returns.
type Cert struct {
	// DNSNames lists the names the certificate covers. Empty means the
	// endpoint's host.
	DNSNames []string

	// NotBefore and NotAfter bound the certificate's validity, as offsets
	// from the time the run sees: Suite.Clock, or the moment a recording was
	// made. Zero means 30 days before it and 60 days after it.
	NotBefore time.Duration
	NotAfter  time.Duration

	// Untrusted signs the certificate with a CA outside RootCAs.
	Untrusted bool
}

// testCA signs endpoint certificates for one Check. It makes each
// certificate once, so every run sees the same one.
type testCA struct {
	trusted   authority
	untrusted authority
	pool      *x509.CertPool

	mu    sync.Mutex
	certs map[string]*tls.Certificate
}

type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// newTestCA returns a CA whose own certificates are valid from ten years
// before the earliest of moments to ten years after the latest, so a chain
// judged at any of them, or at any moment within the validity of a
// certificate the CA signs, leads to its root.
func newTestCA(moments ...time.Time) (*testCA, error) {
	first, last := moments[0], moments[0]
	for _, c := range moments[1:] {
		if c.Before(first) {
			first = c
		}
		if c.After(last) {
			last = c
		}
	}
	trusted, err := newAuthority("collectortest CA", first, last)
	if err != nil {
		return nil, err
	}
	untrusted, err := newAuthority("collectortest untrusted CA", first, last)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(trusted.cert)
	return &testCA{trusted: trusted, untrusted: untrusted, pool: pool, certs: map[string]*tls.Certificate{}}, nil
}

func newAuthority(name string, first, last time.Time) (authority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return authority{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serialFor(name),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             first.AddDate(-10, 0, 0),
		NotAfter:              last.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return authority{}, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return authority{}, err
	}
	return authority{cert: cert, key: key}, nil
}

// certFor returns the certificate ep presents to a run that sees clock as
// the time.
func (ca *testCA) certFor(ep Endpoint, clock time.Time) (*tls.Certificate, error) {
	host, _, err := net.SplitHostPort(ep.Address)
	if err != nil {
		return nil, err
	}
	c := ep.Cert
	key := fmt.Sprintf("%s|%q|%d|%d|%t|%d", host, c.DNSNames, c.NotBefore, c.NotAfter, c.Untrusted, clock.Unix())
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if cert, ok := ca.certs[key]; ok {
		return cert, nil
	}
	notBefore, notAfter := c.validity(clock)
	tmpl := &x509.Certificate{
		SerialNumber: serialFor(key),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	switch ip := net.ParseIP(host); {
	case len(c.DNSNames) > 0:
		tmpl.DNSNames = c.DNSNames
		tmpl.Subject.CommonName = c.DNSNames[0]
	case ip != nil:
		tmpl.IPAddresses = []net.IP{ip}
	default:
		tmpl.DNSNames = []string{host}
	}
	signer := ca.trusted
	if c.Untrusted {
		signer = ca.untrusted
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer.cert, &leafKey.PublicKey, signer.key)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: leafKey}
	ca.certs[key] = cert
	return cert, nil
}

// validity returns the bounds of the certificate for a run that sees clock
// as the time.
func (c Cert) validity(clock time.Time) (time.Time, time.Time) {
	notBefore, notAfter := c.NotBefore, c.NotAfter
	if notBefore == 0 {
		notBefore = -30 * 24 * time.Hour
	}
	if notAfter == 0 {
		notAfter = 60 * 24 * time.Hour
	}
	return clock.Add(notBefore), clock.Add(notAfter)
}

// endpointMoments returns clock and the bounds of the certificate each of
// endpoints presents to a run at clock, which the test CA's own
// certificates must cover.
func endpointMoments(clock time.Time, endpoints []Endpoint) []time.Time {
	out := []time.Time{clock}
	for _, ep := range endpoints {
		notBefore, notAfter := ep.Cert.validity(clock)
		out = append(out, notBefore, notAfter)
	}
	return out
}

// serialFor derives a serial number from what a certificate covers, so the
// same endpoint keeps its serial across Checks.
func serialFor(s string) *big.Int {
	sum := sha256.Sum256([]byte(s))
	return new(big.Int).SetBytes(sum[:8])
}

// endpointSet answers dials with a scenario's endpoints. Each connection is
// an in-process server at the far end of a net.Pipe.
type endpointSet struct {
	opSet
	byAddress map[string]Endpoint
	ca        *testCA
	clock     time.Time
	injector  *injector
	answers   *answerLog

	mu        sync.Mutex
	unmatched []string
	open      []net.Conn
}

// newEndpointSet returns s's endpoints, presenting the certificates ca signs
// for a run that sees clock as the time.
func newEndpointSet(s Scenario, ca *testCA, clock time.Time) (*endpointSet, error) {
	set := &endpointSet{byAddress: map[string]Endpoint{}, ca: ca, clock: clock}
	for i, ep := range s.Endpoints {
		key, err := addressKey(ep.Address)
		if err == nil {
			err = checkVersions(ep)
		}
		if err != nil {
			return nil, fmt.Errorf("scenario %q endpoint %d: %w", s.Name, i, err)
		}
		if _, dup := set.byAddress[key]; dup {
			return nil, fmt.Errorf("scenario %q has two endpoints at %s", s.Name, ep.Address)
		}
		set.byAddress[key] = ep
	}
	return set, nil
}

func addressKey(address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" {
		return "", fmt.Errorf("address %q needs a host and a port", address)
	}
	return net.JoinHostPort(dnsKey(host), port), nil
}

func checkVersions(ep Endpoint) error {
	for _, v := range []uint16{ep.MinVersion, ep.MaxVersion} {
		if v != 0 && (v < tls.VersionTLS10 || v > tls.VersionTLS13) {
			return fmt.Errorf("version %#x is not TLS 1.0 to 1.3", v)
		}
	}
	if ep.MinVersion != 0 && ep.MaxVersion != 0 && ep.MinVersion > ep.MaxVersion {
		return fmt.Errorf("MinVersion %#x is above MaxVersion %#x", ep.MinVersion, ep.MaxVersion)
	}
	return nil
}

// dial connects to the endpoint at address. A dial with no endpoint is
// refused, and the scenario check reports it; a Refused endpoint refuses it
// without a report.
func (s *endpointSet) dial(ctx context.Context, network, address string) (conn net.Conn, err error) {
	s.add(ctx)
	defer func() { s.answers.note(ctx, componentsdk.Classify(err)) }()
	if in := s.injector; in != nil {
		if hit, call := in.strike(ctx); hit {
			in.change(call)
			return in.fault.dial(network, address)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, &net.OpError{Op: "dial", Net: network, Addr: dialAddr(address), Err: err}
	}
	key, _ := addressKey(address)
	ep, ok := s.byAddress[key]
	if ok && ep.Refused {
		return nil, connRefused(network, address)
	}
	if !ok || !strings.HasPrefix(network, "tcp") {
		op, _ := componentsdk.OperationOf(ctx)
		s.mu.Lock()
		s.unmatched = append(s.unmatched, fmt.Sprintf("%s %s (operation %s)", network, address, opName(op)))
		s.mu.Unlock()
		return nil, connRefused(network, address)
	}
	var cert *tls.Certificate
	if !ep.Plaintext {
		var err error
		if cert, err = s.ca.certFor(ep, s.clock); err != nil {
			return nil, err
		}
	}
	client, server := net.Pipe()
	s.mu.Lock()
	s.open = append(s.open, server)
	s.mu.Unlock()
	go serve(newServerConn(server), ep, cert)
	return client, nil
}

func (s *endpointSet) unmatchedDials() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.unmatched...)
}

// serverConn is an endpoint's end of a net.Pipe. Its writes go to a queue
// that a goroutine feeds into the pipe, so the endpoint never waits for the
// client to read, as a socket's send buffer lets a real server move on.
// net.Pipe's own writes wait: a client that rejects a certificate partway
// through the server's flight would block sending its alert to a server still
// writing the rest of that flight.
type serverConn struct {
	net.Conn
	queue chan []byte
	fed   chan struct{}
}

func newServerConn(c net.Conn) *serverConn {
	s := &serverConn{Conn: c, queue: make(chan []byte, 64), fed: make(chan struct{})}
	go s.feed()
	return s
}

func (s *serverConn) feed() {
	defer close(s.fed)
	for b := range s.queue {
		if _, err := s.Conn.Write(b); err != nil {
			for range s.queue {
			}
			return
		}
	}
}

func (s *serverConn) Write(b []byte) (int, error) {
	s.queue <- append([]byte(nil), b...)
	return len(b), nil
}

// Close delivers what is queued, then closes the pipe. A client that stops
// reading holds it until the client closes its end or the run's hang-up.
func (s *serverConn) Close() error {
	close(s.queue)
	<-s.fed
	return s.Conn.Close()
}

// hangUp closes the endpoints' side of every connection, which ends their
// servers once a run is over.
func (s *endpointSet) hangUp() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.open {
		_ = c.Close()
	}
	s.open = nil
}

// serve answers one connection as ep: a TLS handshake with cert, then reading
// and discarding whatever the client sends.
func serve(conn net.Conn, ep Endpoint, cert *tls.Certificate) {
	defer func() { _ = conn.Close() }()
	if ep.Plaintext {
		go func() { _, _ = io.Copy(io.Discard, conn) }()
		_, _ = io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
		return
	}
	srv := tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   ep.MinVersion,
		MaxVersion:   ep.MaxVersion,
		// net.Pipe is synchronous, and a TLS 1.3 server writes its session
		// tickets after its Finished, where a client that never reads them
		// would block it.
		SessionTicketsDisabled: true,
	})
	if srv.Handshake() != nil {
		return
	}
	_, _ = io.Copy(io.Discard, srv)
}

// dialAddr is the address a dial error names.
type dialAddr string

func (a dialAddr) Network() string { return "tcp" }
func (a dialAddr) String() string  { return string(a) }

func connRefused(network, address string) error {
	return &net.OpError{Op: "dial", Net: network, Addr: dialAddr(address), Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}}
}
