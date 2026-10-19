package collectortest

import (
	"context"
	"net/http"
	"sync"

	"github.com/locktivity/epack/componentsdk"
)

// Kinds of operation, by the SDK seam the collector makes its calls through.
const (
	kindHTTP = "http"
	kindDNS  = "dns"
	kindDial = "dial"
)

// network stands in for the internet in one run: the scenario's canned
// responses, DNS records, and endpoints.
type network struct {
	replay    *Replay
	transport http.RoundTripper
	dns       *dnsServer
	endpoints *endpointSet
	answers   *answerLog
}

func (k *kit) newNetwork(s Scenario) (*network, error) {
	rp, err := NewReplay(s)
	if err != nil {
		return nil, err
	}
	dns, err := newDNSServer(s)
	if err != nil {
		return nil, err
	}
	endpoints, err := newEndpointSet(s, k.ca, k.clockFor(s))
	if err != nil {
		return nil, err
	}
	answers := &answerLog{}
	rp.answers, dns.answers, endpoints.answers = answers, answers, answers
	return &network{replay: rp, transport: rp, dns: dns, endpoints: endpoints, answers: answers}, nil
}

// answerLog keeps the code of each call's answer, by operation and call: ""
// for an answer, such as a record that does not exist, or the code of a
// failure. A fault that turns a call that failed in the clean run into
// another failure with the same code leaves the output as it was.
type answerLog struct {
	mu    sync.Mutex
	codes map[string][]componentsdk.Code
	// callOf maps the ID the SDK's transport gives a call to its index in
	// its operation's codes.
	callOf map[uint64]int
}

// note records the answer to an attempt of a call. A first attempt starts a
// new call, and a retry's answer replaces the one before it for the same
// call, even when another call started since.
func (l *answerLog) note(ctx context.Context, code componentsdk.Code) {
	if l == nil {
		return
	}
	op, _ := componentsdk.OperationOf(ctx)
	name := opName(op)
	id := componentsdk.CallOf(ctx)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.codes == nil {
		l.codes, l.callOf = map[string][]componentsdk.Code{}, map[uint64]int{}
	}
	if i, known := l.callOf[id]; known && componentsdk.AttemptOf(ctx) > 1 {
		l.codes[name][i] = code
		return
	}
	if id != 0 {
		l.callOf[id] = len(l.codes[name])
	}
	l.codes[name] = append(l.codes[name], code)
}

// failedWith reports whether each of op's calls, numbered from 1, failed
// with code.
func (l *answerLog) failedWith(op string, calls []int, code componentsdk.Code) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if code == "" || len(calls) == 0 {
		return false
	}
	for _, call := range calls {
		if call < 1 || call > len(l.codes[op]) || l.codes[op][call-1] != code {
			return false
		}
	}
	return true
}

// unmatched lists the requests and dials the scenario had no answer for.
func (n *network) unmatched() []string {
	if n == nil {
		return nil
	}
	var out []string
	for _, req := range n.replay.Unmatched() {
		out = append(out, "no canned response for "+req)
	}
	for _, dial := range n.endpoints.unmatchedDials() {
		out = append(out, "no endpoint for "+dial)
	}
	return out
}

// close hangs up the endpoints' side of the connections the run left open.
func (n *network) close() {
	n.endpoints.hangUp()
}

// kindOf says which seam the run made op's calls through. An operation
// neither the DNS server nor the endpoints saw is HTTP.
func (n *network) kindOf(op string) string {
	switch {
	case n.dns.has(op):
		return kindDNS
	case n.endpoints.has(op):
		return kindDial
	default:
		return kindHTTP
	}
}

// opSet records the operations that reached part of the network.
type opSet struct {
	mu  sync.Mutex
	ops map[string]bool
}

func (s *opSet) add(ctx context.Context) {
	op, _ := componentsdk.OperationOf(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ops == nil {
		s.ops = map[string]bool{}
	}
	s.ops[opName(op)] = true
}

func (s *opSet) has(op string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ops[op]
}
