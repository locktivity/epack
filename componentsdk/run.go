package componentsdk

import (
	"context"
	"crypto/x509"
	"math/rand/v2"
	"net"
	"net/http"
	"slices"
	"sync"
	"time"
)

// run is what one collector run shares between its context, the HTTP layer,
// the resolver and dialer, and the recorder.
type run struct {
	name     string
	version  string
	commit   string
	runID    string
	started  time.Time
	base     http.RoundTripper
	resolver DNSResolver
	dial     func(ctx context.Context, network, address string) (net.Conn, error)
	rootCAs  *x509.CertPool
	calls    *ledger
	records  *Recorder
	secrets  *secretSet
	sleep    func(context.Context, time.Duration) error
	clock    func() time.Time
	schemas  map[string]*artifactSchema

	mu        sync.Mutex
	rng       *rand.Rand
	hostLists [][]string
	waited    time.Duration
	unlisted  []string
}

func newRun(spec CollectorSpec, name, runID string, base http.RoundTripper, seed uint64) *run {
	if name == "" {
		name = spec.Name
	}
	return &run{
		name:    name,
		version: spec.Version,
		commit:  spec.Commit,
		runID:   runID,
		started: time.Now(),
		base:    base,
		calls:   newLedger(),
		records: &Recorder{},
		secrets: &secretSet{},
		clock:   time.Now,
		rng:     rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)),
	}
}

// runCarrier is implemented by the contexts RunCollector and RunInProcess
// create.
type runCarrier interface {
	sdkRun() *run
}

// runOf returns ctx's run. A context the SDK did not create gets a fresh run
// whose records and calls nothing reads.
func runOf(ctx CollectorContext) *run {
	if c, ok := ctx.(runCarrier); ok {
		if r := c.sdkRun(); r != nil {
			return r
		}
	}
	return newRun(CollectorSpec{}, ctx.Name(), "", nil, uint64(time.Now().UnixNano()))
}

// baseTransport returns the transport beneath the SDK's HTTP layer: the one
// RunInProcess was given, then the collector's own (HTTPOptions.Base), then
// a clone of http.DefaultTransport.
func (r *run) baseTransport(own http.RoundTripper) http.RoundTripper {
	if r.base != nil {
		return r.base
	}
	if own != nil {
		return own
	}
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		return t.Clone()
	}
	return http.DefaultTransport
}

// dnsResolver returns the resolver beneath Resolver: the one RunInProcess was
// given, or net.DefaultResolver.
func (r *run) dnsResolver() DNSResolver {
	if r.resolver != nil {
		return r.resolver
	}
	return net.DefaultResolver
}

// dialer returns the dial function beneath Dialer: the one RunInProcess was
// given, or a net.Dialer's.
func (r *run) dialer() func(ctx context.Context, network, address string) (net.Conn, error) {
	if r.dial != nil {
		return r.dial
	}
	var d net.Dialer
	return d.DialContext
}

func (r *run) userAgent() string {
	if r.name == "" {
		return ""
	}
	ua := "epack-collector-" + r.name
	if r.version != "" {
		ua += "/" + r.version
	}
	if r.runID != "" {
		ua += " (run " + r.runID + ")"
	}
	return ua
}

func (r *run) now() time.Time {
	t := time.Now()
	if r.clock != nil {
		t = r.clock()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return t.Add(r.waited)
}

// Now returns the current time for ctx's run. Collectors stamp artifacts and
// compute ages from it, so a test can pin it; outside tests it is the wall
// clock.
func Now(ctx CollectorContext) time.Time {
	return runOf(ctx).now()
}

// Wait pauses the collector for d, or until ctx is done, as when polling for
// a report the vendor builds in the background. In a test kit run it returns
// at once and moves the run's clock forward by d instead, so a loop that
// polls until a deadline read from Now still ends.
func Wait(ctx CollectorContext, d time.Duration) error {
	r := runOf(ctx)
	if err := r.wait(ctx.Context(), d); err != nil {
		return err
	}
	if r.sleep != nil {
		r.mu.Lock()
		r.waited += d
		r.mu.Unlock()
	}
	return nil
}

// wait sleeps for d or until ctx is done.
func (r *run) wait(ctx context.Context, d time.Duration) error {
	if r.sleep != nil {
		return r.sleep(ctx, d)
	}
	return sleepContext(ctx, d)
}

// jitter returns a random duration in [0, d).
func (r *run) jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return time.Duration(r.rng.Int64N(int64(d)))
}

// noteCredentialHosts keeps the CredentialHosts a client was built with, each
// distinct list once, so a test can judge them.
func (r *run) noteCredentialHosts(hosts []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, have := range r.hostLists {
		if slices.Equal(have, hosts) {
			return
		}
	}
	r.hostLists = append(r.hostLists, append([]string{}, hosts...))
}

// noteUnlistedCredentials records an operation that sent a credential header
// through a client built without CredentialHosts, which no host check guards.
func (r *run) noteUnlistedCredentials(op string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !slices.Contains(r.unlisted, op) {
		r.unlisted = append(r.unlisted, op)
	}
}

func (r *run) unlistedCredentialOps() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.unlisted...)
}

// credentialHostLists returns a copy of the lists noteCredentialHosts kept,
// in the order the run first built a client with each.
func (r *run) credentialHostLists() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][]string, len(r.hostLists))
	for i, hosts := range r.hostLists {
		out[i] = append([]string{}, hosts...)
	}
	return out
}

// secretSet holds every value the collector read through Secret, so detail
// text can be redacted by value.
type secretSet struct {
	mu     sync.Mutex
	values []string
}

func (s *secretSet) add(v string) {
	if v == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values = append(s.values, v)
}

func (s *secretSet) list() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.values...)
}
