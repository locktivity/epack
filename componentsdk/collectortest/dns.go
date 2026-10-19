package collectortest

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/locktivity/epack/componentsdk"
)

// DNSRecord is one canned DNS answer.
type DNSRecord struct {
	// Name is the queried name, such as "_dmarc.example.com". Case and a
	// trailing dot do not matter.
	Name string `json:"name"`

	// Type is TXT, MX, A, AAAA, CNAME, or NS. Lookups of other types at a
	// name with a CNAME follow it.
	Type string `json:"type"`

	// Values are the records: TXT text, MX as "10 mx.example.com.",
	// addresses, or names.
	Values []string `json:"values,omitempty"`

	// Rcode, when set, answers lookups of Name and Type with NXDOMAIN or
	// SERVFAIL in place of Values.
	Rcode string `json:"rcode,omitempty"`
}

// kitDNSServer is the server the kit's DNS errors name.
const kitDNSServer = "192.0.2.53:53"

// maxCNAMEHops bounds a chain of CNAMEs, as resolvers do to stop a loop.
const maxCNAMEHops = 8

// dnsServer answers lookups from a scenario's DNS records, with the errors
// net.Resolver returns for the same answers.
type dnsServer struct {
	opSet
	records  map[string][]DNSRecord
	injector *injector
	answers  *answerLog
}

func newDNSServer(s Scenario) (*dnsServer, error) {
	srv := &dnsServer{records: map[string][]DNSRecord{}}
	for i, rec := range s.DNS {
		rec.Type = strings.ToUpper(rec.Type)
		rec.Rcode = strings.ToUpper(rec.Rcode)
		if err := checkRecord(rec); err != nil {
			return nil, fmt.Errorf("scenario %q DNS record %d (%s %s): %w", s.Name, i, rec.Name, rec.Type, err)
		}
		key := dnsKey(rec.Name)
		srv.records[key] = append(srv.records[key], rec)
	}
	return srv, nil
}

func checkRecord(rec DNSRecord) error {
	if dnsKey(rec.Name) == "" {
		return fmt.Errorf("needs a name")
	}
	switch rec.Rcode {
	case "", rcodeNXDomain, rcodeServFail:
	default:
		return fmt.Errorf("the rcode %q is not NXDOMAIN or SERVFAIL", rec.Rcode)
	}
	switch rec.Type {
	case "TXT", "MX", "A", "AAAA", "CNAME", "NS":
	default:
		return fmt.Errorf("type %q is not TXT, MX, A, AAAA, CNAME, or NS", rec.Type)
	}
	if rec.Rcode != "" {
		return nil
	}
	if len(rec.Values) == 0 {
		return fmt.Errorf("needs Values or an Rcode")
	}
	if rec.Type == "CNAME" && len(rec.Values) != 1 {
		return fmt.Errorf("a CNAME has one value")
	}
	for _, v := range rec.Values {
		var ok bool
		switch rec.Type {
		case "A":
			ip := net.ParseIP(v)
			ok = ip != nil && ip.To4() != nil
		case "AAAA":
			ip := net.ParseIP(v)
			ok = ip != nil && ip.To4() == nil
		case "MX":
			_, _, ok = parseMX(v)
		default:
			ok = v != ""
		}
		if !ok {
			return fmt.Errorf("value %q is not a valid %s record", v, rec.Type)
		}
	}
	return nil
}

const (
	rcodeNXDomain = "NXDOMAIN"
	rcodeServFail = "SERVFAIL"
)

func dnsKey(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

func fqdn(name string) string {
	return dnsKey(name) + "."
}

func parseMX(v string) (uint16, string, bool) {
	fields := strings.Fields(v)
	if len(fields) != 2 {
		return 0, "", false
	}
	pref, err := strconv.ParseUint(fields[0], 10, 16)
	if err != nil {
		return 0, "", false
	}
	return uint16(pref), fqdn(fields[1]), true
}

func notFound(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, Server: kitDNSServer, IsNotFound: true}
}

func servfail(name string) error {
	return &net.DNSError{Err: "server misbehaving", Name: name, Server: kitDNSServer, IsTemporary: true}
}

func isNotFound(err error) bool {
	dnsErr, ok := err.(*net.DNSError)
	return ok && dnsErr.IsNotFound
}

// begin starts a lookup: it notes the operation and applies the run's fault,
// if it hits this lookup.
func (s *dnsServer) begin(ctx context.Context, name string) error {
	s.add(ctx)
	if in := s.injector; in != nil {
		if hit, call := in.strike(ctx); hit {
			in.change(call)
			return in.fault.lookup(name)
		}
	}
	return nil
}

// end notes a lookup's answer: a record that does not exist is an answer,
// not a failure.
func (s *dnsServer) end(ctx context.Context, err error) {
	var code componentsdk.Code
	if err != nil && !isNotFound(err) {
		code = componentsdk.Classify(err)
	}
	s.answers.note(ctx, code)
}

// answer returns the values of name's records of type qtype, following
// CNAMEs for other types.
func (s *dnsServer) answer(name, qtype string) ([]string, error) {
	key := dnsKey(name)
	for hops := 0; hops <= maxCNAMEHops; hops++ {
		var values []string
		cname := ""
		for _, rec := range s.records[key] {
			switch {
			case rec.Type == qtype && rec.Rcode == rcodeServFail:
				return nil, servfail(name)
			case rec.Type == qtype && rec.Rcode == rcodeNXDomain:
				return nil, notFound(name)
			case rec.Type == qtype:
				values = append(values, rec.Values...)
			case rec.Type == "CNAME" && rec.Rcode == "" && qtype != "CNAME":
				cname = rec.Values[0]
			}
		}
		if len(values) > 0 {
			return values, nil
		}
		if cname == "" {
			return nil, notFound(name)
		}
		key = dnsKey(cname)
	}
	return nil, servfail(name)
}

func (s *dnsServer) LookupTXT(ctx context.Context, name string) (_ []string, err error) {
	defer func() { s.end(ctx, err) }()
	if err := s.begin(ctx, name); err != nil {
		return nil, err
	}
	return s.answer(name, "TXT")
}

func (s *dnsServer) LookupMX(ctx context.Context, name string) (_ []*net.MX, err error) {
	defer func() { s.end(ctx, err) }()
	if err := s.begin(ctx, name); err != nil {
		return nil, err
	}
	values, err := s.answer(name, "MX")
	if err != nil {
		return nil, err
	}
	out := make([]*net.MX, 0, len(values))
	for _, v := range values {
		pref, host, _ := parseMX(v)
		out = append(out, &net.MX{Host: host, Pref: pref})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Pref < out[j].Pref })
	return out, nil
}

func (s *dnsServer) LookupNS(ctx context.Context, name string) (_ []*net.NS, err error) {
	defer func() { s.end(ctx, err) }()
	if err := s.begin(ctx, name); err != nil {
		return nil, err
	}
	values, err := s.answer(name, "NS")
	if err != nil {
		return nil, err
	}
	out := make([]*net.NS, 0, len(values))
	for _, v := range values {
		out = append(out, &net.NS{Host: fqdn(v)})
	}
	return out, nil
}

// LookupCNAME follows host's CNAMEs to the canonical name. A host with no
// CNAME but an address is its own canonical name, as net.Resolver has it.
func (s *dnsServer) LookupCNAME(ctx context.Context, host string) (_ string, err error) {
	defer func() { s.end(ctx, err) }()
	if err := s.begin(ctx, host); err != nil {
		return "", err
	}
	name := host
	for hops := 0; hops <= maxCNAMEHops; hops++ {
		targets, err := s.answer(name, "CNAME")
		switch {
		case err == nil:
			name = targets[0]
			continue
		case !isNotFound(err):
			return "", err
		case hops > 0:
			return fqdn(name), nil
		}
		if _, err := s.addresses(name); err != nil {
			return "", err
		}
		return fqdn(name), nil
	}
	return "", servfail(host)
}

func (s *dnsServer) LookupHost(ctx context.Context, host string) (_ []string, err error) {
	defer func() { s.end(ctx, err) }()
	if err := s.begin(ctx, host); err != nil {
		return nil, err
	}
	ips, err := s.addresses(host)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out, nil
}

func (s *dnsServer) LookupIPAddr(ctx context.Context, host string) (_ []net.IPAddr, err error) {
	defer func() { s.end(ctx, err) }()
	if err := s.begin(ctx, host); err != nil {
		return nil, err
	}
	ips, err := s.addresses(host)
	if err != nil {
		return nil, err
	}
	out := make([]net.IPAddr, 0, len(ips))
	for _, ip := range ips {
		out = append(out, net.IPAddr{IP: ip})
	}
	return out, nil
}

// addresses returns host's A and AAAA records. As with net.Resolver, one type
// failing does not hide the other's addresses.
func (s *dnsServer) addresses(host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	var ips []net.IP
	var failed error
	for _, qtype := range []string{"A", "AAAA"} {
		values, err := s.answer(host, qtype)
		if err != nil {
			if !isNotFound(err) {
				failed = err
			}
			continue
		}
		for _, v := range values {
			ips = append(ips, net.ParseIP(v))
		}
	}
	switch {
	case len(ips) > 0:
		return ips, nil
	case failed != nil:
		return nil, failed
	default:
		return nil, notFound(host)
	}
}
