package collectortest

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk"
)

var testClock = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

const day = 24 * time.Hour

func testEndpoints(t *testing.T, endpoints ...Endpoint) (*endpointSet, *testCA) {
	t.Helper()
	ca, err := newTestCA(testClock)
	if err != nil {
		t.Fatal(err)
	}
	set, err := newEndpointSet(Scenario{Name: "test", Endpoints: endpoints}, ca, testClock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(set.hangUp)
	return set, ca
}

// handshake dials address and runs a TLS handshake with cfg.
func handshake(set *endpointSet, address string, cfg *tls.Config) (tls.ConnectionState, error) {
	conn, err := set.dial(context.Background(), "tcp", address)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(handshakeDeadline))
	client := tls.Client(conn, cfg)
	err = client.Handshake()
	return client.ConnectionState(), err
}

const handshakeDeadline = 10 * time.Second

// turnedDown reports whether err is the alert an endpoint sends for a TLS
// version it does not accept.
func turnedDown(err error) bool {
	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == "remote error"
}

func TestEndpointsServeTLS10Through13(t *testing.T) {
	set, _ := testEndpoints(t,
		Endpoint{Address: "legacy.example.com:443", MinVersion: tls.VersionTLS10},
		Endpoint{Address: "modern.example.com:443"},
		Endpoint{Address: "dated.example.com:443", MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS12},
	)
	versions := []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13}
	accepts := map[string][]bool{
		"legacy.example.com:443": {true, true, true, true},
		"modern.example.com:443": {false, false, true, true},
		"dated.example.com:443":  {true, true, true, false},
	}
	for address, want := range accepts {
		host, _, _ := net.SplitHostPort(address)
		for i, v := range versions {
			state, err := handshake(set, address, &tls.Config{ServerName: host, MinVersion: v, MaxVersion: v, InsecureSkipVerify: true})
			switch {
			case want[i] && (err != nil || state.Version != v):
				t.Errorf("%s at %s negotiated %#x with err %v", address, tls.VersionName(v), state.Version, err)
			case !want[i] && !turnedDown(err):
				t.Errorf("%s at %s: err = %v, want a protocol version alert", address, tls.VersionName(v), err)
			}
		}
	}
}

func TestEndpointCertificatesChainToRootCAs(t *testing.T) {
	set, ca := testEndpoints(t,
		Endpoint{Address: "www.example.com:443"},
		Endpoint{Address: "rogue.example.com:443", Cert: Cert{Untrusted: true}},
	)
	verifyAfter := func(address string) error {
		host, _, _ := net.SplitHostPort(address)
		state, err := handshake(set, address, &tls.Config{ServerName: host, InsecureSkipVerify: true})
		if err != nil {
			return err
		}
		_, err = state.PeerCertificates[0].Verify(x509.VerifyOptions{DNSName: host, Roots: ca.pool, CurrentTime: testClock})
		return err
	}
	if err := verifyAfter("www.example.com:443"); err != nil {
		t.Errorf("verifying the chain against RootCAs after the handshake: %v", err)
	}
	var unknown x509.UnknownAuthorityError
	if err := verifyAfter("rogue.example.com:443"); !errors.As(err, &unknown) {
		t.Errorf("an untrusted certificate verified with err %v, want an unknown authority", err)
	}

	verifyDuring := func(address string) error {
		host, _, _ := net.SplitHostPort(address)
		_, err := handshake(set, address, &tls.Config{ServerName: host, RootCAs: ca.pool, Time: func() time.Time { return testClock }})
		return err
	}
	if err := verifyDuring("www.example.com:443"); err != nil {
		t.Errorf("verifying in the handshake through tls.Config.RootCAs: %v", err)
	}
	var unverified *tls.CertificateVerificationError
	start := time.Now()
	if err := verifyDuring("rogue.example.com:443"); !errors.As(err, &unverified) {
		t.Errorf("an untrusted certificate passed the handshake with err %v", err)
	}
	if took := time.Since(start); took > handshakeDeadline/2 {
		t.Errorf("rejecting the certificate took %s: the client's alert waited on the endpoint", took)
	}
}

func TestEndpointCertificatesFollowTheClock(t *testing.T) {
	set, _ := testEndpoints(t,
		Endpoint{Address: "www.example.com:443"},
		Endpoint{Address: "expired.example.com:8443", Cert: Cert{DNSNames: []string{"other.example.com"}, NotBefore: -90 * day, NotAfter: -day}},
		Endpoint{Address: "192.0.2.7:443"},
	)
	leaf := func(address string) *x509.Certificate {
		t.Helper()
		state, err := handshake(set, address, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			t.Fatalf("%s: %v", address, err)
		}
		return state.PeerCertificates[0]
	}
	www := leaf("www.example.com:443")
	if !www.NotBefore.Equal(testClock.Add(-30*day)) || !www.NotAfter.Equal(testClock.Add(60*day)) || strings.Join(www.DNSNames, ",") != "www.example.com" {
		t.Errorf("the default certificate covers %v from %s to %s", www.DNSNames, www.NotBefore, www.NotAfter)
	}
	expired := leaf("expired.example.com:8443")
	if !expired.NotBefore.Equal(testClock.Add(-90*day)) || !expired.NotAfter.Equal(testClock.Add(-day)) || expired.VerifyHostname("expired.example.com") == nil {
		t.Errorf("the expired certificate covers %v from %s to %s", expired.DNSNames, expired.NotBefore, expired.NotAfter)
	}
	if ip := leaf("192.0.2.7:443"); len(ip.IPAddresses) != 1 || !ip.IPAddresses[0].Equal(net.ParseIP("192.0.2.7")) {
		t.Errorf("an endpoint at an IP address got a certificate for %v %v", ip.DNSNames, ip.IPAddresses)
	}
	if again := leaf("www.example.com:443"); !bytes.Equal(again.Raw, www.Raw) {
		t.Error("each dial should present the same certificate, so runs agree")
	}
}

func TestPlaintextEndpointsFailATLSHandshakeAtOnce(t *testing.T) {
	set, _ := testEndpoints(t, Endpoint{Address: "www.example.com:80", Plaintext: true})
	_, err := handshake(set, "www.example.com:80", &tls.Config{ServerName: "www.example.com", InsecureSkipVerify: true})
	var header tls.RecordHeaderError
	if !errors.As(err, &header) {
		t.Errorf("err = %v, want the record header error a TLS client gets from a plaintext server", err)
	}
}

func TestDialsWithNoEndpointAreRefused(t *testing.T) {
	set, _ := testEndpoints(t, Endpoint{Address: "www.example.com:443"})
	ctx := componentsdk.WithOperation(context.Background(), componentsdk.Operation{Name: "tls.probe"})
	for _, d := range [][2]string{{"tcp", "other.example.com:443"}, {"udp", "www.example.com:443"}, {"tcp", "www.example.com"}} {
		if _, err := set.dial(ctx, d[0], d[1]); !errors.Is(err, syscall.ECONNREFUSED) || componentsdk.Classify(err) != componentsdk.CodeVendorError {
			t.Errorf("dial %s %s: err = %v, want a refused connection", d[0], d[1], err)
		}
	}
	want := "tcp other.example.com:443 (operation tls.probe)|udp www.example.com:443 (operation tls.probe)|tcp www.example.com (operation tls.probe)"
	if got := strings.Join(set.unmatchedDials(), "|"); got != want {
		t.Errorf("unmatched dials = %s, want %s", got, want)
	}
	conn, err := set.dial(ctx, "tcp4", "WWW.Example.com.:443")
	if err != nil {
		t.Errorf("a dial differing only in case, the root dot, and tcp4: %v", err)
	} else {
		_ = conn.Close()
	}
}

func TestEndpointsAreChecked(t *testing.T) {
	for _, endpoints := range [][]Endpoint{
		{{Address: "www.example.com"}},
		{{Address: "www.example.com:443"}, {Address: "WWW.example.com:443"}},
		{{Address: "www.example.com:443", MinVersion: 0x0300}},
		{{Address: "www.example.com:443", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS12}},
	} {
		if _, err := newEndpointSet(Scenario{Name: "bad", Endpoints: endpoints}, nil, time.Time{}); err == nil {
			t.Errorf("endpoints %+v should be rejected", endpoints)
		}
	}
}

func TestDNSAndDialFaultsActLikeTheFailuresTheyStandFor(t *testing.T) {
	byKind := map[string][]string{}
	for _, f := range Faults() {
		byKind[f.kind()] = append(byKind[f.kind()], f.Name)
		start := time.Now()
		switch f.kind() {
		case kindDNS:
			err := f.lookup("example.com")
			dnsErr, ok := err.(*net.DNSError)
			if !ok || dnsErr.IsNotFound || componentsdk.Classify(err) != f.Expect {
				t.Errorf("DNS %s: err = %#v classifies as %s, want a failure classified %s", f.Name, err, componentsdk.Classify(err), f.Expect)
			}
			if f.Name == "timeout" && !dnsErr.Timeout() {
				t.Errorf("the DNS timeout's Timeout() is false")
			}
		case kindDial:
			conn, err := f.dial("tcp", "www.example.com:443")
			if f.Name == "reset" {
				if err != nil {
					t.Fatalf("the reset fault should connect, then reset: %v", err)
				}
				if _, err := conn.Write([]byte("hello")); err != nil {
					t.Errorf("a write before the reset failed: %v", err)
				}
				_, err = conn.Read(make([]byte, 1))
				if !errors.Is(err, syscall.ECONNRESET) {
					t.Errorf("the first read returned %v, want a reset", err)
				}
			}
			if code := componentsdk.Classify(err); code != f.Expect {
				t.Errorf("dial %s: err = %v classifies as %s, want %s", f.Name, err, code, f.Expect)
			}
			var netErr net.Error
			if f.Name == "timeout" && (!errors.As(err, &netErr) || !netErr.Timeout() || errors.Is(err, context.DeadlineExceeded)) {
				t.Errorf("the dial timeout should be a net.Error whose Timeout is true, not the collector's own deadline: %v", err)
			}
		}
		if took := time.Since(start); took > time.Second {
			t.Errorf("%s fault took %s, want no wall time", f.Name, took)
		}
	}
	if got := strings.Join(byKind[kindDNS], ","); got != "servfail,timeout,refused" {
		t.Errorf("DNS faults = %s", got)
	}
	if got := strings.Join(byKind[kindDial], ","); got != "refused,reset,timeout" {
		t.Errorf("dial faults = %s", got)
	}
}

// tlsDemo is a small collector that checks an endpoint's certificate and the
// TLS versions it accepts, with switches. With failureUnsupported off it
// tells an endpoint turning a version down from a probe that failed.
type tlsDemo struct {
	failureUnsupported bool // reads a failed probe as "version not supported"
	verifyInHandshake  bool // verifies the chain in the handshake, through tls.Config.RootCAs
}

const tlsDemoPath = "artifacts/tlsdemo.json"

var tlsDemoVersions = []struct {
	field   string
	version uint16
}{
	{"tls_1_0", tls.VersionTLS10},
	{"tls_1_1", tls.VersionTLS11},
	{"tls_1_2", tls.VersionTLS12},
	{"tls_1_3", tls.VersionTLS13},
}

func (d tlsDemo) run(ctx componentsdk.CollectorContext) error {
	dialer := componentsdk.NewDialer(ctx)
	rec := componentsdk.Records(ctx)
	address, _ := ctx.Config()["address"].(string)
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return componentsdk.NewConfigError("address: %v", err)
	}
	now := componentsdk.Now(ctx)
	at := func(pointer string) componentsdk.Location {
		return componentsdk.Location{Path: tlsDemoPath, Pointer: pointer}
	}
	handshake := func(op string, cfg *tls.Config) (*tls.ConnectionState, error) {
		dialCtx, cancel := context.WithTimeout(componentsdk.WithOperation(ctx.Context(), componentsdk.Operation{Name: op}), 10*time.Second)
		defer cancel()
		conn, err := dialer.DialContext(dialCtx, "tcp", address)
		if err != nil {
			return nil, err
		}
		defer func() { _ = conn.Close() }()
		// The handshake's limit is a deadline on the connection, not a context:
		// when a context ends, crypto/tls closes the connection, and the close
		// hides the timeout from the call log.
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		client := tls.Client(conn, cfg)
		if err := client.HandshakeContext(ctx.Context()); err != nil {
			return nil, err
		}
		state := client.ConnectionState()
		return &state, nil
	}

	out := map[string]any{"address": address}
	cfg := &tls.Config{ServerName: host, InsecureSkipVerify: true}
	if d.verifyInHandshake {
		cfg = &tls.Config{ServerName: host, RootCAs: dialer.RootCAs(), Time: func() time.Time { return now }}
	}
	state, err := handshake("tls.handshake", cfg)
	var leaf *x509.Certificate
	var unverified *tls.CertificateVerificationError
	switch {
	case err == nil:
		leaf = state.PeerCertificates[0]
		// The chain is judged within the certificate's validity, so an
		// expired certificate from a trusted CA reads as trusted, and its
		// expiry shows in expires_in_days.
		at := now
		if at.After(leaf.NotAfter) {
			at = leaf.NotAfter
		}
		if at.Before(leaf.NotBefore) {
			at = leaf.NotBefore
		}
		_, verifyErr := leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: dialer.RootCAs(), CurrentTime: at})
		out["trusted"] = verifyErr == nil
	case errors.As(err, &unverified):
		leaf = unverified.UnverifiedCertificates[0]
		out["trusted"] = false
	default:
		rec.NotCollected(at("/trusted"), err)
		rec.NotCollected(at("/expires_in_days"), err)
	}
	if leaf != nil {
		out["expires_in_days"] = int(leaf.NotAfter.Sub(now).Hours() / 24)
	}

	for _, v := range tlsDemoVersions {
		_, err := handshake("tls.probe", &tls.Config{ServerName: host, MinVersion: v.version, MaxVersion: v.version, InsecureSkipVerify: true})
		switch {
		case err == nil:
			out[v.field] = true
		case d.failureUnsupported || turnedDown(err):
			out[v.field] = false
		default:
			rec.NotCollected(at("/"+v.field), err)
		}
	}
	return ctx.Emit([]componentsdk.CollectedArtifact{{Data: out, Path: tlsDemoPath}})
}

func tlsDemoSuite(d tlsDemo) Suite {
	pins := func(values map[string]any) map[string]map[string]any {
		return map[string]map[string]any{tlsDemoPath: values}
	}
	return Suite{
		Spec:   componentsdk.CollectorSpec{Name: "tlsdemo", Version: "0.0.1"},
		Run:    d.run,
		Config: map[string]any{"address": "www.example.com:443", "level": "audit"},
		Scenarios: []Scenario{
			{
				Name:      "clean",
				Endpoints: []Endpoint{{Address: "www.example.com:443"}},
				Expect: pins(map[string]any{
					"/trusted": true, "/expires_in_days": 60,
					"/tls_1_0": false, "/tls_1_1": false, "/tls_1_2": true, "/tls_1_3": true,
				}),
			},
			{
				Name:      "legacy versions",
				Endpoints: []Endpoint{{Address: "www.example.com:443", MinVersion: tls.VersionTLS10}},
				Expect:    pins(map[string]any{"/tls_1_0": true, "/tls_1_1": true, "/tls_1_2": true, "/tls_1_3": true}),
			},
			{
				Name:      "no TLS 1.3",
				Endpoints: []Endpoint{{Address: "www.example.com:443", MaxVersion: tls.VersionTLS12}},
				Expect:    pins(map[string]any{"/tls_1_2": true, "/tls_1_3": false}),
			},
			{
				Name:      "expired and untrusted",
				Endpoints: []Endpoint{{Address: "www.example.com:443", Cert: Cert{Untrusted: true, NotBefore: -90 * day, NotAfter: -day}}},
				Expect:    pins(map[string]any{"/trusted": false, "/expires_in_days": -1}),
			},
		},
		Operations: []string{"tls.handshake", "tls.probe"},
	}
}

func TestATLSOnlyCollectorPasses(t *testing.T) {
	for name, d := range map[string]tlsDemo{"verify after the handshake": {}, "verify in the handshake": {verifyInHandshake: true}} {
		t.Run(name, func(t *testing.T) {
			report := checkSuite(t, tlsDemoSuite(d))
			for _, v := range report.Violations {
				t.Errorf("%s/%s: %s", v.Check, v.Case, v.Message)
			}
			// Four scenarios, two determinism runs, three levels, the three
			// dial faults on the handshake's one call, and the same at four
			// positions on the four probes. No credentials or sensitivity
			// runs, and no HTTP faults.
			if want := 4 + 2 + 3 + 3 + 3*4; report.Runs != want {
				t.Errorf("runs = %d, want %d", report.Runs, want)
			}
		})
	}
}

func TestTheKitCatchesAProbeTimeoutReadAsUnsupported(t *testing.T) {
	report := checkSuite(t, tlsDemoSuite(tlsDemo{failureUnsupported: true}))
	expectViolation(t, report, "faults", "tls.probe/timeout/all")
	expectViolation(t, report, "faults", "artifacts/tlsdemo.json /tls_1_2: value changed from true to false")
	expectViolation(t, report, "faults", "tls.probe/timeout/last")
	// The clean endpoint turns TLS 1.0 and 1.1 down, so reading their probes'
	// timeouts as unsupported changes no value; the missing gap shows it.
	for _, pos := range []string{"first", "middle"} {
		expectCase(t, report, "tls.probe/timeout/"+pos, "the fault reached tls.probe but left no new gap with code timeout")
	}
}

func TestARefusedEndpointIsAClosedPort(t *testing.T) {
	s := tlsDemoSuite(tlsDemo{})
	s.Scenarios = append(s.Scenarios, Scenario{
		Name:      "port closed",
		Endpoints: []Endpoint{{Address: "www.example.com:443", Refused: true}},
		Expect: map[string]map[string]any{
			tlsDemoPath: {"/trusted": nil, "/tls_1_2": nil},
			"artifacts/tlsdemo.collector-result.json": {"/outcome/code": "vendor_error"},
		},
	})
	for _, v := range checkSuite(t, s).Violations {
		t.Errorf("%s/%s: %s", v.Check, v.Case, v.Message)
	}
}

func TestSemanticPositionsLimitExpect(t *testing.T) {
	closed := Semantic{
		Operation: "tls.probe", Fault: "refused", Meaning: "the port closed between probes",
		Expect: map[string]map[string]any{tlsDemoPath: {"/tls_1_2": nil, "/tls_1_3": nil}},
	}
	s := tlsDemoSuite(tlsDemo{})
	s.Semantics = []Semantic{closed}
	report := checkSuite(t, s)
	expectCase(t, report, "tls.probe/refused/first", "refused (the port closed between probes): artifacts/tlsdemo.json /tls_1_2 is true, want null")

	closed.Positions = []string{PositionAll}
	s.Semantics = []Semantic{closed}
	for _, v := range checkSuite(t, s).Violations {
		t.Errorf("Expect should apply at the listed positions only: %s/%s: %s", v.Check, v.Case, v.Message)
	}

	unsupported := Semantic{
		Operation: "tls.probe", Fault: "refused", Meaning: "a refused probe means the version is off",
		Expect:    map[string]map[string]any{tlsDemoPath: {"/tls_1_2": false, "/tls_1_3": false}},
		Positions: []string{PositionAll},
	}
	s = tlsDemoSuite(tlsDemo{failureUnsupported: true})
	s.Semantics = []Semantic{unsupported}
	for _, v := range violationsOf(checkSuite(t, s), "faults") {
		if strings.HasPrefix(v.Case, "tls.probe/refused/") {
			t.Errorf("a declared meaning exempts every position from the outcome rule: %s: %s", v.Case, v.Message)
		}
	}

	s.Semantics[0].Positions = []string{"second"}
	if _, err := Check(s); err == nil || !strings.Contains(err.Error(), `position "second"`) {
		t.Errorf("an unknown position should be rejected, got %v", err)
	}
}

func TestTheScenarioCheckReportsADialWithNoEndpoint(t *testing.T) {
	s := tlsDemoSuite(tlsDemo{})
	s.Scenarios = append(s.Scenarios, Scenario{Name: "moved", Endpoints: []Endpoint{{Address: "www.example.net:443"}}})
	report := checkSuite(t, s)
	expectViolation(t, report, "scenario", "no endpoint for tcp www.example.com:443 (operation tls.handshake)")
}
