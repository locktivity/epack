package collectortest

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/safefile"
)

// RecordOptions configures Record.
type RecordOptions struct {
	// Spec and Run are what the collector passes to RunCollector.
	Spec componentsdk.CollectorSpec
	Run  componentsdk.CollectorHandler

	// Name labels the recording's scenario. It defaults to Out's file name
	// without its extension.
	Name string

	// Config is the configuration the run gets. The recording keeps it,
	// scrubbed, as its scenario's Config, so a replay sends the requests the
	// recording answers.
	Config map[string]any

	// Secrets holds the real credentials the run signs in with. Scrubbing
	// removes their values, and the scrub check fails the recording if any
	// remains.
	Secrets map[string]string

	// Env holds other environment variables the collector reads.
	Env map[string]string

	// Out is the file the recording is written to, such as
	// testdata/recordings/clean.json.
	Out string

	// Scrub adds the collector's own scrubbing rules, such as for its
	// organization's name.
	Scrub ScrubRules

	// Headers names response headers to keep beyond the built-in list, such
	// as one the collector reads a count from. A name ending in * keeps every
	// header that begins with the rest.
	Headers []string

	// Codec decodes bodies a recording could not otherwise hold, such as a
	// gRPC API's protobuf messages, into JSON the recording holds instead.
	// A run replays the recording only with the same codec as Suite.Codec.
	// See BodyCodec.
	Codec BodyCodec

	// resolver, dial, and roots stand in for the network's DNS, its
	// connections, and the system's certificate authorities in the kit's
	// own tests.
	resolver componentsdk.DNSResolver
	dial     dialFunc
	roots    *x509.CertPool
}

type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// RecordReport describes the recording Record wrote.
type RecordReport struct {
	// Responses, DNS, and Endpoints count the responses, DNS records, and
	// endpoints it holds.
	Responses int
	DNS       int
	Endpoints int

	// ExitCode and Failure say how the recorded run ended. A run that failed
	// is recorded too, for a scenario that expects the failure.
	ExitCode int
	Failure  *componentsdk.ProgressMessage

	// Replaced counts the distinct values scrubbing replaced, by rule:
	// "secret", "identifier", "literal", "pattern", "token", "email", "ip",
	// "guid", "aws_account", and "aws_key_id".
	Replaced map[string]int
}

// recordedHeaders and recordedHeaderPrefixes name the response headers a
// recording keeps: those collectors read for content, pagination, redirects,
// and rate limits.
var (
	recordedHeaders = []string{
		"Content-Type", "Link", "Location", "Retry-After", "ETag", "RateLimit",
		"X-Next-Page", "X-Page", "X-Per-Page", "X-Prev-Page", "X-Total", "X-Total-Count", "X-Total-Pages", "X-Ms-Continuation",
	}
	recordedHeaderPrefixes = []string{"X-RateLimit-", "X-Rate-Limit-", "RateLimit-", "X-Sentry-Rate-Limit-"}
)

// Record runs the collector once against its vendor, through
// componentsdk.RunInProcess with the real network and resolver, and writes
// each response its HTTP calls got, each answer its DNS lookups got, and an
// endpoint for each address its dials reached to Out as a scrubbed scenario
// that LoadScenario loads.
//
// A certificate's private key cannot be recorded, so once the run ends,
// Record probes each address the run dialed with a handshake of its own at
// each TLS version from 1.0 to 1.3. The endpoint it writes accepts the same
// versions and presents a certificate the kit's test CA signs, with the
// names and validity of the one the address presented. That certificate is
// untrusted when the chain the address presented leads to no root the
// system trusts, judged at a moment within the certificate's validity, so
// an expired certificate from a trusted CA stays trusted. An address that
// refused every dial is a closed port, and one that answered without TLS is
// a plaintext endpoint.
//
// The run's clock stands still at the moment the recording starts, moving
// only as componentsdk.Wait waits, and the recording keeps that moment as
// recorded_at. A replay runs at that moment, so it sends the same
// time-based requests.
//
// Record scrubs a response body as text, except a body whose Content-Type is
// application/cbor or ends in +cbor, such as AWS services on the Smithy RPC
// v2 CBOR protocol send: it decodes that body, scrubs each value, and
// encodes it again. A body RecordOptions.Codec takes is scrubbed as the JSON
// the codec decodes it to, and the recording keeps that JSON.
//
// Record writes nothing and returns an error when a call, lookup, or dial
// got no answer, such as one that timed out, when an endpoint does what the
// kit's endpoints cannot replay, when a response body is neither text nor
// CBOR that decodes, when the codec cannot decode a body it takes or encode
// it once scrubbed, or when the scrub check finds a secret's value or a
// token in the scrubbed result.
func Record(opts RecordOptions) (RecordReport, error) {
	switch {
	case opts.Run == nil:
		return RecordReport{}, errors.New("RecordOptions.Run is required")
	case opts.Spec.Name == "":
		return RecordReport{}, errors.New("RecordOptions.Spec.Name is required")
	case opts.Out == "":
		return RecordReport{}, errors.New("RecordOptions.Out is required")
	}
	for id, fake := range opts.Scrub.Identifiers {
		if id != "" && strings.Contains(strings.ToLower(fake), strings.ToLower(id)) {
			return RecordReport{}, fmt.Errorf("the fake %s holds the identifier it replaces, so the scrub check would fail every recording", fake)
		}
	}
	recordedAt := time.Now().UTC().Truncate(time.Second)
	httpRec := &httpRecorder{base: defaultTransport()}
	dnsRec := &dnsRecorder{base: opts.resolver}
	if dnsRec.base == nil {
		dnsRec.base = net.DefaultResolver
	}
	dialRec := &dialRecorder{base: opts.dial}
	if dialRec.base == nil {
		var d net.Dialer
		dialRec.base = d.DialContext
	}
	outputDir, err := os.MkdirTemp("", "collectortest-record-")
	if err != nil {
		return RecordReport{}, err
	}
	defer func() { _ = os.RemoveAll(outputDir) }()
	res := componentsdk.RunInProcess(opts.Spec, opts.Run, componentsdk.InProcessOptions{
		Config:    copyConfig(opts.Config),
		Secrets:   opts.Secrets,
		Env:       opts.Env,
		OutputDir: outputDir,
		RunID:     "collectortest-record",
		Transport: httpRec,
		Resolver:  dnsRec,
		Dial:      dialRec.dial,
		RootCAs:   opts.roots,
		Seed:      1,
		Sleep:     sleep,
		Clock:     func() time.Time { return recordedAt },
	})
	report := RecordReport{ExitCode: res.ExitCode, Failure: res.Failure}
	if res.Panic != "" {
		first, _, _ := strings.Cut(res.Panic, "\n")
		return report, fmt.Errorf("the collector panicked: %s", newScrubber(opts.Secrets, ScrubRules{}).text(first))
	}
	exchanges, err := httpRec.answered()
	if err != nil {
		return report, err
	}
	records, err := dnsRec.answered()
	if err != nil {
		return report, err
	}
	endpoints, err := dialRec.endpoints(opts.roots, recordedAt)
	if err != nil {
		return report, err
	}
	if len(exchanges) == 0 && len(records) == 0 && len(endpoints) == 0 {
		return report, errors.New("the run made no HTTP calls, DNS lookups, or dials through the SDK, so there is nothing to record")
	}
	name := cmp.Or(opts.Name, strings.TrimSuffix(filepath.Base(opts.Out), filepath.Ext(opts.Out)))
	scrub := newScrubber(opts.Secrets, opts.Scrub)
	sc, endpointFiles, err := scrubbedScenario(name, opts, scrub, exchanges, records, endpoints, recordedAt)
	if err != nil {
		return report, err
	}
	if leaks := scanScenario(sc, canaryList(opts.Secrets), opts.Scrub.Identifiers); len(leaks) > 0 {
		parts := make([]string, len(leaks))
		for i, l := range leaks {
			parts[i] = l.String()
		}
		return report, fmt.Errorf("the scrub check found what a recording must not hold, so nothing was written: %s. Add a ScrubRules entry for each, or take it out of Keep", strings.Join(parts, "; "))
	}
	err = writeRecording(opts.Out, recording{
		Name:             sc.Name,
		RecordedAt:       recordedAt.Format(time.RFC3339),
		Collector:        opts.Spec.Name,
		CollectorVersion: opts.Spec.Version,
		Config:           sc.Config,
		Responses:        sc.Responses,
		DNS:              sc.DNS,
		Endpoints:        endpointFiles,
	})
	if err != nil {
		return report, err
	}
	report.Responses, report.DNS, report.Endpoints, report.Replaced = len(sc.Responses), len(sc.DNS), len(sc.Endpoints), scrub.counts()
	return report, nil
}

// sleep waits for d or until ctx is done. As a run's Sleep it makes
// componentsdk.Wait move the run's stopped clock forward by what it waited.
func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func defaultTransport() http.RoundTripper {
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		return t.Clone()
	}
	return http.DefaultTransport
}

// canaryList returns secrets as canaries, sorted by key.
func canaryList(secrets map[string]string) []canary {
	out := make([]canary, 0, len(secrets))
	for _, key := range sortedKeys(secrets) {
		out = append(out, canary{key: key, value: secrets[key]})
	}
	return out
}

// scrubbedScenario builds the recording's scenario, and its endpoints as the
// file holds them, scrubbing in a fixed order: the config, then each
// response's URL, request body, headers, and body, then the DNS records,
// then the endpoints.
func scrubbedScenario(name string, opts RecordOptions, scrub *scrubber, exchanges []*exchange, records []DNSRecord, endpoints []probedEndpoint, recordedAt time.Time) (Scenario, []endpointFile, error) {
	config, err := scrub.config(opts.Config)
	if err != nil {
		return Scenario{}, nil, err
	}
	keep := headerFilter(opts.Headers)
	sc := Scenario{Name: name, Config: config}
	for _, ex := range exchanges {
		r := Response{Operation: ex.op, Method: ex.method, Status: ex.status, URL: scrub.url(ex.url)}
		reqBody, err := decodeRequest(opts.Codec, ex.op, ex.reqHeader, ex.reqBody)
		if err != nil {
			return Scenario{}, nil, fmt.Errorf("the request body of %s: %s", ex, scrub.text(err.Error()))
		}
		if reqBody == nil {
			reqBody = ex.reqBody
		}
		if r.RequestBody, err = scrub.requestBody(ex.reqHeader.Get("Content-Type"), reqBody); err != nil {
			return Scenario{}, nil, fmt.Errorf("%s: %w", ex, err)
		}
		r.Header = scrub.headers(ex.header, keep)
		decoded, err := decodeResponse(opts.Codec, ex.op, r.Header, ex.body)
		switch {
		case err != nil:
			return Scenario{}, nil, fmt.Errorf("the response to %s: %s", ex, scrub.text(err.Error()))
		case decoded != nil:
			if r.Body, err = scrub.decodedBody(decoded); err != nil {
				return Scenario{}, nil, fmt.Errorf("the response to %s: %w", ex, err)
			}
			r.decoded = true
		case isCBOR(ex.header.Get("Content-Type")):
			body, err := scrub.cborBody(ex.body)
			if err != nil {
				return Scenario{}, nil, fmt.Errorf("the CBOR response to %s: %w", ex, err)
			}
			r.Body = string(body)
		case !utf8.Valid(ex.body):
			return Scenario{}, nil, fmt.Errorf("the response to %s is neither text nor CBOR, and a recording holds only bodies it can scrub or RecordOptions.Codec decodes", ex)
		default:
			r.Body = scrub.text(string(ex.body))
		}
		sc.Responses = append(sc.Responses, r)
	}
	setTimes(sc.Responses)
	for _, rec := range records {
		sc.DNS = append(sc.DNS, scrub.dns(rec))
	}
	var files []endpointFile
	for _, p := range endpoints {
		f, err := scrub.endpoint(p)
		if err != nil {
			return Scenario{}, nil, err
		}
		ep, err := f.endpoint(recordedAt)
		if err != nil {
			return Scenario{}, nil, err
		}
		files = append(files, f)
		sc.Endpoints = append(sc.Endpoints, ep)
	}
	if _, err := newReplay(sc, opts.Codec); err != nil {
		return Scenario{}, nil, fmt.Errorf("the scrubbed recording does not replay: %w", err)
	}
	if _, err := newDNSServer(sc); err != nil {
		return Scenario{}, nil, fmt.Errorf("the scrubbed recording does not replay: %w", err)
	}
	if _, err := newEndpointSet(sc, nil, time.Time{}); err != nil {
		return Scenario{}, nil, fmt.Errorf("the scrubbed recording does not replay: %w", err)
	}
	return sc, files, nil
}

// headerFilter reports whether a recording keeps a response header: one of
// the built-in list, or one extra names.
func headerFilter(extra []string) func(string) bool {
	names := append([]string(nil), recordedHeaders...)
	prefixes := append([]string(nil), recordedHeaderPrefixes...)
	for _, h := range extra {
		if p, ok := strings.CutSuffix(h, "*"); ok {
			prefixes = append(prefixes, p)
		} else {
			names = append(names, h)
		}
	}
	return func(name string) bool {
		if containsFold(names, name) {
			return true
		}
		for _, p := range prefixes {
			if len(name) >= len(p) && strings.EqualFold(name[:len(p)], p) {
				return true
			}
		}
		return false
	}
}

// setTimes has each response answer one request when a later response
// matches the same requests, so they answer in the order recorded and the
// last of them answers every request after.
func setTimes(responses []Response) {
	keys := make([]string, len(responses))
	last := map[string]int{}
	for i, r := range responses {
		keys[i] = matchKey(r)
		last[keys[i]] = i
	}
	for i := range responses {
		if last[keys[i]] != i {
			responses[i].Times = 1
		}
	}
}

// matchKey identifies the requests a recorded response matches.
func matchKey(r Response) string {
	u, err := url.Parse(r.URL)
	if err != nil {
		return r.URL
	}
	query := "*"
	if u.RawQuery != "" || u.ForceQuery {
		var pairs []string
		for key, values := range u.Query() {
			for _, v := range values {
				pairs = append(pairs, key+"="+v)
			}
		}
		sort.Strings(pairs)
		query = strings.Join(pairs, "&")
	}
	return strings.Join([]string{r.Operation, r.Method, strings.ToLower(u.Scheme), strings.ToLower(u.Host), u.Path, query, r.RequestBody}, "\x00")
}

// exchange is one attempt of a call in a recorded run.
type exchange struct {
	op        string
	call      uint64
	attempt   int
	method    string
	url       *url.URL
	reqHeader http.Header
	reqBody   []byte
	status    int
	header    http.Header
	body      []byte
	err       error
	retried   bool
}

// String names the call by its method, its URL with query values left out,
// and its operation.
func (ex *exchange) String() string {
	return fmt.Sprintf("%s %s (operation %s)", ex.method, describeURL(ex.url), cmp.Or(ex.op, componentsdk.UnnamedOperation))
}

// httpRecorder sits beneath the SDK's transport in a recorded run and keeps
// each attempt's request and response.
type httpRecorder struct {
	base http.RoundTripper
	mu   sync.Mutex
	log  []*exchange
}

func (r *httpRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	op, _ := componentsdk.OperationOf(req.Context())
	target := *req.URL
	ex := &exchange{op: op.Name, call: componentsdk.CallOf(req.Context()), attempt: componentsdk.AttemptOf(req.Context()), method: req.Method, url: &target, reqHeader: req.Header.Clone()}
	defer r.add(ex)
	if req.Body != nil && req.Body != http.NoBody {
		body, err := readRecorded(req.Body)
		_ = req.Body.Close()
		if err != nil {
			ex.err = err
			return nil, err
		}
		ex.reqBody = body
		req = req.Clone(req.Context())
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
		req.ContentLength = int64(len(body))
	}
	resp, err := r.base.RoundTrip(req)
	if err != nil {
		ex.err = err
		return nil, err
	}
	body, err := readRecorded(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		ex.err = err
		return nil, err
	}
	ex.status, ex.header, ex.body = resp.StatusCode, resp.Header.Clone(), body
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	return resp, nil
}

func (r *httpRecorder) add(ex *exchange) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.log = append(r.log, ex)
}

// readRecorded reads a body Record keeps, up to the size of an API response.
func readRecorded(body io.Reader) ([]byte, error) {
	limit := limits.JSONResponse.Bytes()
	b, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err == nil && int64(len(b)) > limit {
		return nil, fmt.Errorf("the body is over %d bytes, too large to record", limit)
	}
	return b, err
}

// answered returns the attempts whose responses the collector got, in
// order. An attempt the SDK retried is left out, since the replay's clean
// run should not retry, and a call whose last attempt got no response fails
// the recording, since a replay could not answer it.
func (r *httpRecorder) answered() ([]*exchange, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, ex := range r.log {
		if ex.attempt <= 1 {
			continue
		}
		for j := i - 1; j >= 0; j-- {
			if p := r.log[j]; !p.retried && p.call == ex.call && p.attempt == ex.attempt-1 {
				p.retried = true
				break
			}
		}
	}
	var out []*exchange
	var failed []string
	for _, ex := range r.log {
		switch {
		case ex.retried:
		case ex.err != nil:
			failed = append(failed, fmt.Sprintf("%s: %s", ex, componentsdk.Classify(ex.err)))
		default:
			out = append(out, ex)
		}
	}
	if len(failed) > 0 {
		return nil, fmt.Errorf("some calls got no response, so a replay could not answer them; record again: %s", strings.Join(failed, "; "))
	}
	return out, nil
}

// dnsRecorder sits beneath the SDK's Resolver in a recorded run and keeps
// each lookup's answer as a DNS record, the first answer for each name and
// type.
type dnsRecorder struct {
	base componentsdk.DNSResolver

	mu      sync.Mutex
	records []DNSRecord
	seen    map[string]bool
	failed  []string
}

func (d *dnsRecorder) LookupTXT(ctx context.Context, name string) ([]string, error) {
	txt, err := d.base.LookupTXT(ctx, name)
	d.note(ctx, name, "TXT", txt, err)
	return txt, err
}

func (d *dnsRecorder) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	mx, err := d.base.LookupMX(ctx, name)
	values := make([]string, len(mx))
	for i, m := range mx {
		values[i] = fmt.Sprintf("%d %s", m.Pref, m.Host)
	}
	d.note(ctx, name, "MX", values, err)
	return mx, err
}

func (d *dnsRecorder) LookupNS(ctx context.Context, name string) ([]*net.NS, error) {
	ns, err := d.base.LookupNS(ctx, name)
	values := make([]string, len(ns))
	for i, n := range ns {
		values[i] = n.Host
	}
	d.note(ctx, name, "NS", values, err)
	return ns, err
}

func (d *dnsRecorder) LookupHost(ctx context.Context, host string) ([]string, error) {
	addrs, err := d.base.LookupHost(ctx, host)
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil {
			ips = append(ips, ip)
		}
	}
	d.noteAddresses(ctx, host, ips, err)
	return addrs, err
}

func (d *dnsRecorder) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	addrs, err := d.base.LookupIPAddr(ctx, host)
	d.noteAddresses(ctx, host, ipsOf(addrs), err)
	return addrs, err
}

func (d *dnsRecorder) LookupCNAME(ctx context.Context, host string) (string, error) {
	cname, err := d.base.LookupCNAME(ctx, host)
	if err == nil && dnsKey(cname) == dnsKey(host) {
		// A name with no CNAME is its own canonical name only when it has
		// addresses, so the replay needs them to answer the same way.
		if addrs, err := d.base.LookupIPAddr(ctx, host); err == nil {
			d.noteAddresses(ctx, host, ipsOf(addrs), nil)
		}
		return cname, nil
	}
	d.note(ctx, host, "CNAME", []string{cname}, err)
	return cname, err
}

func ipsOf(addrs []net.IPAddr) []net.IP {
	ips := make([]net.IP, len(addrs))
	for i, a := range addrs {
		ips[i] = a.IP
	}
	return ips
}

func (d *dnsRecorder) noteAddresses(ctx context.Context, host string, ips []net.IP, err error) {
	if net.ParseIP(host) != nil {
		return
	}
	if err != nil {
		d.note(ctx, host, "A", nil, err)
		return
	}
	var v4, v6 []string
	for _, ip := range ips {
		if ip.To4() != nil {
			v4 = append(v4, ip.String())
		} else {
			v6 = append(v6, ip.String())
		}
	}
	d.note(ctx, host, "A", v4, nil)
	d.note(ctx, host, "AAAA", v6, nil)
}

// note keeps a lookup's answer: its values, or NXDOMAIN or SERVFAIL. A
// failure with no response code, such as a timeout, fails the recording.
func (d *dnsRecorder) note(ctx context.Context, name, qtype string, values []string, err error) {
	rec := DNSRecord{Name: dnsKey(name), Type: qtype}
	d.mu.Lock()
	defer d.mu.Unlock()
	switch rcode := lookupRcode(err); {
	case err == nil && len(values) == 0:
		return
	case err == nil:
		rec.Values = values
	case rcode != "":
		rec.Rcode = rcode
	default:
		op, _ := componentsdk.OperationOf(ctx)
		d.failed = append(d.failed, fmt.Sprintf("%s lookup of %s (operation %s): %s", qtype, rec.Name, opName(op), componentsdk.Classify(err)))
		return
	}
	if d.seen == nil {
		d.seen = map[string]bool{}
	}
	if key := rec.Name + " " + rec.Type; !d.seen[key] {
		d.seen[key] = true
		d.records = append(d.records, rec)
	}
}

// lookupRcode returns the response code a lookup error stands for, as
// net.Resolver reports them, or "" for a failure with none.
func lookupRcode(err error) string {
	var dnsErr *net.DNSError
	switch {
	case !errors.As(err, &dnsErr):
		return ""
	case dnsErr.IsNotFound:
		return rcodeNXDomain
	case dnsErr.IsTemporary && !dnsErr.IsTimeout && dnsErr.Err == "server misbehaving":
		return rcodeServFail
	}
	return ""
}

func (d *dnsRecorder) answered() ([]DNSRecord, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.failed) > 0 {
		return nil, fmt.Errorf("some lookups got no answer, so a replay could not answer them; record again: %s", strings.Join(d.failed, "; "))
	}
	return append([]DNSRecord(nil), d.records...), nil
}

// tlsVersions are the versions Record probes an endpoint at, oldest first.
var tlsVersions = []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13}

// probeCipherSuites offers every suite Go implements, including those it
// leaves out by default, so an endpoint that accepts only legacy suites
// still completes a handshake.
var probeCipherSuites = func() []uint16 {
	var ids []uint16
	for _, suites := range [][]*tls.CipherSuite{tls.CipherSuites(), tls.InsecureCipherSuites()} {
		for _, s := range suites {
			ids = append(ids, s.ID)
		}
	}
	return ids
}()

// probeTimeout bounds each of Record's own dials and handshakes.
const probeTimeout = 10 * time.Second

// dialRecorder sits beneath the SDK's Dialer in a recorded run and keeps the
// address and outcome of each dial.
type dialRecorder struct {
	base dialFunc

	mu    sync.Mutex
	dials []dialAttempt
}

type dialAttempt struct {
	op, network, address string
	err                  error
}

func (d *dialRecorder) dial(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.base(ctx, network, address)
	op, _ := componentsdk.OperationOf(ctx)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.dials = append(d.dials, dialAttempt{op: opName(op), network: network, address: address, err: err})
	return conn, err
}

// probedEndpoint is what Record found at an address the run dialed.
type probedEndpoint struct {
	address   string
	refused   bool
	plaintext bool
	min, max  uint16
	leaf      *x509.Certificate
	trusted   bool
}

// endpoints probes each address the run dialed, in the order of its first
// dial, and judges certificates against roots at recordedAt. An address that
// refused every dial is a closed port. Any other failed dial, such as one
// that timed out or named a host that does not resolve, fails the
// recording, since no endpoint answers that way.
func (d *dialRecorder) endpoints(roots *x509.CertPool, recordedAt time.Time) ([]probedEndpoint, error) {
	d.mu.Lock()
	dials := append([]dialAttempt(nil), d.dials...)
	d.mu.Unlock()
	var order []string
	byKey := map[string]*probedEndpoint{}
	connected := map[string]bool{}
	var failed []string
	for _, a := range dials {
		key, err := addressKey(a.address)
		switch {
		case err != nil || !strings.HasPrefix(a.network, "tcp"):
			failed = append(failed, fmt.Sprintf("%s %s (operation %s): not a TCP host and port", a.network, a.address, a.op))
			continue
		case a.err == nil:
			connected[key] = true
		case !errors.Is(a.err, syscall.ECONNREFUSED):
			failed = append(failed, fmt.Sprintf("%s %s (operation %s): %s", a.network, a.address, a.op, componentsdk.Classify(a.err)))
			continue
		}
		if byKey[key] == nil {
			byKey[key] = &probedEndpoint{address: a.address}
			order = append(order, key)
		}
	}
	if len(failed) > 0 {
		return nil, fmt.Errorf("some dials failed in a way no endpoint can replay, such as a timeout or a name that does not resolve; record again once each connects or is refused: %s", strings.Join(failed, "; "))
	}
	out := make([]probedEndpoint, 0, len(order))
	for _, key := range order {
		ep := byKey[key]
		if !connected[key] {
			ep.refused = true
		} else if err := ep.probe(d.base, roots, recordedAt); err != nil {
			return nil, err
		}
		out = append(out, *ep)
	}
	return out, nil
}

// probe finds the TLS versions the endpoint accepts, with a handshake at
// each, and reads its certificate chain from the handshake at the newest. A
// version is turned down when the endpoint answers its handshake with an
// alert or closes the connection.
func (ep *probedEndpoint) probe(dial dialFunc, roots *x509.CertPool, recordedAt time.Time) error {
	host, _, err := net.SplitHostPort(ep.address)
	if err != nil {
		return err
	}
	var accepted []uint16
	var chain []*x509.Certificate
	plaintext := 0
	for _, v := range tlsVersions {
		state, err := probeHandshake(dial, ep.address, host, v)
		var header tls.RecordHeaderError
		var netErr net.Error
		switch {
		case err == nil:
			accepted = append(accepted, v)
			chain = state.PeerCertificates
		case errors.As(err, &header):
			plaintext++
		case errors.Is(err, errProbeDial):
			return fmt.Errorf("probing %s at %s: %w; record again once it connects", ep.address, tls.VersionName(v), err)
		case errors.As(err, &netErr) && netErr.Timeout():
			return fmt.Errorf("probing %s at %s: the handshake timed out; record again once it answers", ep.address, tls.VersionName(v))
		}
	}
	switch {
	case plaintext == len(tlsVersions):
		ep.plaintext = true
		return nil
	case plaintext > 0:
		return fmt.Errorf("%s answered some TLS handshakes without TLS, which no endpoint replays", ep.address)
	case len(accepted) == 0 || len(chain) == 0:
		return fmt.Errorf("%s completed no TLS handshake from TLS 1.0 to TLS 1.3, which no endpoint replays", ep.address)
	}
	for i := 1; i < len(accepted); i++ {
		if accepted[i] != accepted[i-1]+1 {
			return fmt.Errorf("%s accepts TLS versions with a gap between them, which no endpoint replays", ep.address)
		}
	}
	ep.min, ep.max = accepted[0], accepted[len(accepted)-1]
	ep.leaf = chain[0]
	ep.trusted = trustedChain(chain, roots, recordedAt)
	return nil
}

var errProbeDial = errors.New("the dial failed")

// probeHandshake dials address and runs a handshake at version alone. It
// checks no certificate, since Record judges the chain itself.
func probeHandshake(dial dialFunc, address, host string, version uint16) (*tls.ConnectionState, error) {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	conn, err := dial(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", errProbeDial, componentsdk.Classify(err))
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(probeTimeout))
	// #nosec G402 -- the handshake reads the chain, which Record verifies on its own.
	client := tls.Client(conn, &tls.Config{
		ServerName:         host,
		MinVersion:         version,
		MaxVersion:         version,
		CipherSuites:       probeCipherSuites,
		InsecureSkipVerify: true,
	})
	if err := client.Handshake(); err != nil {
		return nil, err
	}
	state := client.ConnectionState()
	return &state, nil
}

// trustedChain reports whether chain leads from its leaf to one of roots,
// or to the system's roots when roots is nil, at the moment within the
// leaf's validity nearest to at.
func trustedChain(chain []*x509.Certificate, roots *x509.CertPool, at time.Time) bool {
	leaf := chain[0]
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	if at.After(leaf.NotAfter) {
		at = leaf.NotAfter
	}
	if at.Before(leaf.NotBefore) {
		at = leaf.NotBefore
	}
	_, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: at})
	return err == nil
}

// endpointFile is an Endpoint as a recording holds it: TLS versions by name,
// such as "TLS 1.2", and certificate validity as moments rather than offsets
// from the clock, so a recording made again changes only where the endpoint
// did.
type endpointFile struct {
	Address    string    `json:"address"`
	MinVersion string    `json:"min_version,omitempty"`
	MaxVersion string    `json:"max_version,omitempty"`
	Cert       *certFile `json:"cert,omitempty"`
	Plaintext  bool      `json:"plaintext,omitempty"`
	Refused    bool      `json:"refused,omitempty"`
}

type certFile struct {
	DNSNames  []string `json:"dns_names,omitempty"`
	NotBefore string   `json:"not_before,omitempty"`
	NotAfter  string   `json:"not_after,omitempty"`
	Untrusted bool     `json:"untrusted,omitempty"`
}

// endpoint scrubs what Record found at an address into the endpoint a
// recording holds. It fails when the replay's certificate would answer the
// hostname check another way, as for a certificate with no DNS names, which
// the kit's CA would sign for the host.
func (s *scrubber) endpoint(p probedEndpoint) (endpointFile, error) {
	host, port, err := net.SplitHostPort(p.address)
	if err != nil {
		return endpointFile{}, err
	}
	scrubbedHost := s.text(strings.ToLower(host))
	f := endpointFile{Address: net.JoinHostPort(scrubbedHost, port), Plaintext: p.plaintext, Refused: p.refused}
	if p.leaf == nil {
		return f, nil
	}
	f.MinVersion, f.MaxVersion = tls.VersionName(p.min), tls.VersionName(p.max)
	f.Cert = &certFile{
		NotBefore: p.leaf.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:  p.leaf.NotAfter.UTC().Format(time.RFC3339),
		Untrusted: !p.trusted,
	}
	for _, name := range p.leaf.DNSNames {
		f.Cert.DNSNames = append(f.Cert.DNSNames, s.text(name))
	}
	if (p.leaf.VerifyHostname(host) == nil) != namesHost(f.Cert.DNSNames, scrubbedHost) {
		return endpointFile{}, fmt.Errorf("the certificate %s presented and its replay would answer the hostname check differently: "+
			"a certificate with no DNS names, or ScrubRules that rewrite the host and the certificate's names apart, cannot be replayed", p.address)
	}
	return f, nil
}

// namesHost reports whether the certificate the kit's CA signs for an
// endpoint at host with these names covers host.
func namesHost(names []string, host string) bool {
	c := &x509.Certificate{DNSNames: names}
	if len(names) == 0 {
		if ip := net.ParseIP(host); ip != nil {
			c.IPAddresses = []net.IP{ip}
		} else {
			c.DNSNames = []string{host}
		}
	}
	return c.VerifyHostname(host) == nil
}

// endpoint returns f as the Endpoint of a recording made at recordedAt.
func (f endpointFile) endpoint(recordedAt time.Time) (Endpoint, error) {
	ep := Endpoint{Address: f.Address, Plaintext: f.Plaintext, Refused: f.Refused}
	var err error
	if ep.MinVersion, err = parseTLSVersion(f.MinVersion); err != nil {
		return Endpoint{}, fmt.Errorf("endpoint %s: %w", f.Address, err)
	}
	if ep.MaxVersion, err = parseTLSVersion(f.MaxVersion); err != nil {
		return Endpoint{}, fmt.Errorf("endpoint %s: %w", f.Address, err)
	}
	if f.Cert == nil {
		return ep, nil
	}
	ep.Cert = Cert{DNSNames: f.Cert.DNSNames, Untrusted: f.Cert.Untrusted}
	for _, bound := range []struct {
		value  string
		offset *time.Duration
	}{{f.Cert.NotBefore, &ep.Cert.NotBefore}, {f.Cert.NotAfter, &ep.Cert.NotAfter}} {
		if bound.value == "" {
			continue
		}
		if recordedAt.IsZero() {
			return Endpoint{}, fmt.Errorf("endpoint %s: certificate times need the recording's recorded_at", f.Address)
		}
		t, err := time.Parse(time.RFC3339, bound.value)
		if err != nil {
			return Endpoint{}, fmt.Errorf("endpoint %s: %q is not an RFC 3339 time", f.Address, bound.value)
		}
		*bound.offset = t.Sub(recordedAt)
	}
	return ep, nil
}

func parseTLSVersion(name string) (uint16, error) {
	if name == "" {
		return 0, nil
	}
	for _, v := range tlsVersions {
		if tls.VersionName(v) == name {
			return v, nil
		}
	}
	return 0, fmt.Errorf("version %q is not TLS 1.0, TLS 1.1, TLS 1.2, or TLS 1.3", name)
}

// recording is a scenario as a file holds it.
type recording struct {
	Name             string         `json:"name"`
	RecordedAt       string         `json:"recorded_at,omitempty"`
	Collector        string         `json:"collector,omitempty"`
	CollectorVersion string         `json:"collector_version,omitempty"`
	Config           map[string]any `json:"config,omitempty"`
	Responses        []Response     `json:"responses,omitempty"`
	DNS              []DNSRecord    `json:"dns,omitempty"`
	Endpoints        []endpointFile `json:"endpoints,omitempty"`
}

func writeRecording(path string, r recording) error {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(abs)
	if err := safefile.EnsureBaseDir(dir); err != nil {
		return err
	}
	return safefile.WriteFile(dir, filepath.Base(abs), b.Bytes())
}

// LoadScenario loads a recording Record wrote, or one written by hand in
// the same format. Its runs see the moment it was recorded as the time, and
// its config, when it has one, as their whole configuration. Check runs the
// scrub check on each scenario LoadScenario loaded, and when Suite.Clock is
// zero and the first scenario is a recording, the other scenarios run at
// the moment it was recorded too. A recording made with RecordOptions.Codec
// replays only in runs with the same codec as Suite.Codec.
func LoadScenario(path string) (Scenario, error) {
	data, err := safefile.ReadFile(path, limits.Artifact)
	if err != nil {
		return Scenario{}, err
	}
	var r recording
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return Scenario{}, fmt.Errorf("%s: %w", path, err)
	}
	s := Scenario{
		Name:      cmp.Or(r.Name, strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))),
		Responses: r.Responses,
		DNS:       r.DNS,
		Config:    r.Config,
		source:    path,
	}
	if r.RecordedAt != "" {
		if s.recordedAt, err = time.Parse(time.RFC3339, r.RecordedAt); err != nil {
			return Scenario{}, fmt.Errorf("%s: recorded_at %q is not an RFC 3339 time", path, r.RecordedAt)
		}
	}
	for _, f := range r.Endpoints {
		ep, err := f.endpoint(s.recordedAt)
		if err != nil {
			return Scenario{}, fmt.Errorf("%s: %w", path, err)
		}
		s.Endpoints = append(s.Endpoints, ep)
	}
	for i := range s.Responses {
		if _, err := newReplayEntry(s, i); err != nil {
			return Scenario{}, fmt.Errorf("%s: %w", path, err)
		}
	}
	if _, err := newDNSServer(s); err != nil {
		return Scenario{}, fmt.Errorf("%s: %w", path, err)
	}
	if _, err := newEndpointSet(s, nil, time.Time{}); err != nil {
		return Scenario{}, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// responseFile is a Response as a recording holds it. A body that is a JSON
// object or array is written as JSON, so it reads and diffs as JSON. A body
// that is not UTF-8, such as CBOR, is written as base64, with body_encoding
// set to base64, so it replays byte for byte. A body a BodyCodec decoded is
// written as the codec's JSON, with body_encoding set to codec. Any other
// body is a string.
type responseFile struct {
	Operation    string          `json:"operation,omitempty"`
	Method       string          `json:"method,omitempty"`
	URL          string          `json:"url,omitempty"`
	RequestBody  json.RawMessage `json:"request_body,omitempty"`
	Times        int             `json:"times,omitempty"`
	Status       int             `json:"status,omitempty"`
	Header       http.Header     `json:"header,omitempty"`
	BodyEncoding string          `json:"body_encoding,omitempty"`
	Body         json.RawMessage `json:"body,omitempty"`
}

// base64Body is the body_encoding of a body written as base64.
const base64Body = "base64"

// MarshalJSON writes r as a recording holds it.
func (r Response) MarshalJSON() ([]byte, error) {
	requestBody, err := embedJSON(r.RequestBody)
	if err != nil {
		return nil, err
	}
	var body json.RawMessage
	encoding := ""
	switch {
	case r.decoded:
		encoding, body = codecBody, json.RawMessage(r.Body)
	case utf8.ValidString(r.Body):
		body, err = embedJSON(r.Body)
	default:
		encoding = base64Body
		body, err = marshalJSON(base64.StdEncoding.EncodeToString([]byte(r.Body)))
	}
	if err != nil {
		return nil, err
	}
	return marshalJSON(responseFile{
		Operation: r.Operation, Method: r.Method, URL: r.URL, RequestBody: requestBody,
		Times: r.Times, Status: r.Status, Header: r.Header, BodyEncoding: encoding, Body: body,
	})
}

// UnmarshalJSON reads r as a recording holds it.
func (r *Response) UnmarshalJSON(data []byte) error {
	var f responseFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return err
	}
	requestBody, err := unembedJSON(f.RequestBody)
	if err != nil {
		return err
	}
	var body string
	switch f.BodyEncoding {
	case "":
		body, err = unembedJSON(f.Body)
	case base64Body:
		body, err = unbase64(f.Body)
	case codecBody:
		body, err = codecJSON(f.Body)
	default:
		err = fmt.Errorf("body_encoding %q is not %s or %s", f.BodyEncoding, base64Body, codecBody)
	}
	if err != nil {
		return err
	}
	*r = Response{
		Operation: f.Operation, Method: f.Method, URL: f.URL, Status: f.Status,
		Header: f.Header, Body: body, Times: f.Times, RequestBody: requestBody,
		decoded: f.BodyEncoding == codecBody,
	}
	return nil
}

func embedJSON(s string) (json.RawMessage, error) {
	if s == "" {
		return nil, nil
	}
	if t := strings.TrimSpace(s); t != "" && (t[0] == '{' || t[0] == '[') && json.Valid([]byte(t)) {
		var b bytes.Buffer
		if err := json.Compact(&b, []byte(t)); err != nil {
			return nil, err
		}
		return b.Bytes(), nil
	}
	return marshalJSON(s)
}

func unembedJSON(raw json.RawMessage) (string, error) {
	t := bytes.TrimSpace(raw)
	switch {
	case len(t) == 0 || string(t) == "null":
		return "", nil
	case t[0] == '"':
		var s string
		err := json.Unmarshal(t, &s)
		return s, err
	}
	var b bytes.Buffer
	if err := json.Compact(&b, t); err != nil {
		return "", err
	}
	return b.String(), nil
}

// unbase64 reads a body written as a base64 string.
func unbase64(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("a base64 body must be a string: %w", err)
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("the body is not base64: %w", err)
	}
	return string(b), nil
}

// codecJSON reads a body written as a codec's JSON, which may be any JSON
// value, compacted.
func codecJSON(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", errors.New("a codec body must be the codec's JSON")
	}
	var b bytes.Buffer
	if err := json.Compact(&b, raw); err != nil {
		return "", err
	}
	return b.String(), nil
}
