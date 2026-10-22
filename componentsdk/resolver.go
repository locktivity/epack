package componentsdk

import (
	"context"
	"errors"
	"net"
	"strings"
)

// DNSResolver makes the lookups Resolver offers. *net.Resolver implements
// it, and RunInProcess takes one in place of the network.
type DNSResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
}

// Response codes the call ledger keys DNS lookups by.
const (
	rcodeNoError  = "NOERROR"
	rcodeNXDomain = "NXDOMAIN"
	rcodeServFail = "SERVFAIL"
)

// Resolver looks up DNS records with the signatures of net.Resolver, and
// counts each lookup in the run's call ledger. A name or record that does not
// exist is an answer, not a failure: the lookup returns net.Resolver's
// *net.DNSError unchanged, with IsNotFound true, and the ledger counts it
// under NXDOMAIN with no error code. A failure, such as SERVFAIL or a timeout,
// counts under the code Classify gives it. The error a failed lookup returns
// names the lookup's call, so a gap recorded from it names it too. Use
// errors.As to get the *net.DNSError from that error.
//
// Each lookup is an operation named by its context (see WithOperation), such
// as "dns.spf.lookup", or by default "dns." and the lookup's kind: "dns.txt",
// "dns.mx", "dns.host", "dns.ipaddr", "dns.cname", or "dns.ns". The SDK does
// not retry lookups.
type Resolver struct {
	run      *run
	resolver DNSResolver
}

// NewResolver returns the resolver for the collector's DNS lookups. It
// resolves through net.DefaultResolver, or through InProcessOptions.Resolver
// in a RunInProcess run.
func NewResolver(ctx CollectorContext) *Resolver {
	r := runOf(ctx)
	return &Resolver{run: r, resolver: r.dnsResolver()}
}

// LookupTXT returns the TXT records for name.
func (r *Resolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return lookup(ctx, r, "dns.txt", "TXT", name, r.resolver.LookupTXT)
}

// LookupMX returns the MX records for name, sorted by preference.
func (r *Resolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return lookup(ctx, r, "dns.mx", "MX", name, r.resolver.LookupMX)
}

// LookupHost returns the addresses of host.
func (r *Resolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return lookup(ctx, r, "dns.host", "A/AAAA", host, r.resolver.LookupHost)
}

// LookupIPAddr returns the IP addresses of host.
func (r *Resolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return lookup(ctx, r, "dns.ipaddr", "A/AAAA", host, r.resolver.LookupIPAddr)
}

// LookupCNAME returns the canonical name of host, following CNAME records.
func (r *Resolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	return lookup(ctx, r, "dns.cname", "CNAME", host, r.resolver.LookupCNAME)
}

// LookupNS returns the NS records for name.
func (r *Resolver) LookupNS(ctx context.Context, name string) ([]*net.NS, error) {
	return lookup(ctx, r, "dns.ns", "NS", name, r.resolver.LookupNS)
}

// lookup makes one lookup under its operation and records it. The operation
// rides on the context the resolver gets, so a test resolver sees the name the
// ledger counts.
func lookup[T any](ctx context.Context, r *Resolver, defaultOp, qtype, name string, fn func(context.Context, string) (T, error)) (T, error) {
	op := operationOr(ctx, defaultOp)
	call := r.run.beginCall(ctx, op)
	answer, err := fn(WithOperation(ctx, op), name)
	rcode := rcodeOf(err)
	var code Code
	if rcode != rcodeNXDomain {
		code = Classify(err)
	}
	host := strings.TrimSuffix(strings.ToLower(name), ".")
	r.run.calls.addCall(call, "DNS "+qtype, host, rcode, code, r.run.now().Sub(call.started))
	if err != nil && rcode != rcodeNXDomain {
		return answer, &callError{err: err, operation: op.Name, call: call.number}
	}
	return answer, err
}

// rcodeOf returns the response code a lookup's result stands for: NOERROR for
// an answer, NXDOMAIN for a name or record that does not exist, and SERVFAIL.
// A failure with no response, such as a timeout, has none.
func rcodeOf(err error) string {
	if err == nil {
		return rcodeNoError
	}
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		return ""
	}
	switch {
	case dnsErr.IsNotFound:
		return rcodeNXDomain
	// net.Resolver marks socket errors temporary as well, so only its
	// "server misbehaving" error, which it returns for SERVFAIL, counts.
	case dnsErr.IsTemporary && !dnsErr.IsTimeout && dnsErr.Err == "server misbehaving":
		return rcodeServFail
	default:
		return ""
	}
}

// operationOr returns the operation ctx names, or one named name.
func operationOr(ctx context.Context, name string) Operation {
	if op, ok := OperationOf(ctx); ok {
		return op
	}
	return Operation{Name: name}
}
