package componentsdk

import (
	"slices"
	"sort"
	"strings"
	"sync"
	"unicode"
)

// Location names a value in an emitted artifact.
type Location struct {
	// Schema is the artifact's schema. Use Path instead when several
	// artifacts share a schema or the artifact has none.
	Schema string
	// Path is the artifact's path in the pack.
	Path string
	// Pointer is a JSON pointer (RFC 6901) into the artifact's data. Address
	// items by array index, never by name.
	Pointer string
}

// Gap statuses.
const (
	// GapNotCollected marks a value the collector could not read.
	GapNotCollected = "not_collected"
	// GapPartial marks a rollup left out because some of the items it covers
	// could not be read, or a list or object that holds only the items that
	// could be.
	GapPartial = "partial"
)

// Gap is a value a collector left out of its artifact, and why.
type Gap struct {
	Schema     string `json:"schema,omitempty"`
	Path       string `json:"path,omitempty"`
	Pointer    string `json:"pointer"`
	Status     string `json:"status"`
	Code       Code   `json:"code"`
	Owner      Owner  `json:"owner"`
	VendorCode string `json:"vendor_code,omitempty"`
	Unmeasured int    `json:"unmeasured,omitempty"`
	// Operation and Call name the failed call that left the value out, when
	// the gap was recorded from an error the SDK's client returned or one
	// built with ResponseError. Call matches the call on its rows.
	Operation string `json:"operation,omitempty"`
	Call      int    `json:"call,omitempty"`
	// Source is the line of the collector's own code that recorded the gap,
	// relative to its module's root, such as
	// internal/collector/system_log.go:155. See Recorder.Helper.
	Source string `json:"source,omitempty"`
	// MissingPermission is the permission to grant for a permission_denied
	// gap, in the vendor's own terms. See MissingPermission.
	MissingPermission string `json:"missing_permission,omitempty"`
	// Warning is the collector's message to the operator about the gap, and
	// Detail redacted text from the error. Both are redacted and shown at
	// the audit and internal levels only.
	Warning string `json:"warning,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// GapOption adds a detail to a gap the Recorder records.
type GapOption struct {
	apply func(*Gap)
}

// MissingPermission names the permission a permission_denied gap's
// credential lacks, in the vendor's own terms, such as okta.logs.read, so
// the customer knows what to grant. It applies only to a gap whose code is
// permission_denied, and is dropped from any other. A permission holding
// whitespace or more than 256 bytes is dropped too, since it appears at
// every level.
func MissingPermission(permission string) GapOption {
	return GapOption{apply: func(g *Gap) {
		if g.Code == CodePermissionDenied && len(permission) <= 256 && !strings.ContainsFunc(permission, unicode.IsSpace) && !strings.ContainsFunc(permission, unicode.IsControl) {
			g.MissingPermission = permission
		}
	}}
}

// Warning gives a gap the collector's message to the operator about it,
// such as the role to grant. Like the error text, it is redacted and appears
// at the audit and internal levels only.
func Warning(message string) GapOption {
	return GapOption{apply: func(g *Gap) { g.Warning = message }}
}

// Principal is the identity a collector signed in as.
type Principal struct {
	// Provider names the identity system, such as "microsoft-entra".
	Provider string `json:"provider"`
	// Kind is the kind of principal, such as "service_principal" or "user".
	Kind string `json:"kind"`
	// TenantID is the tenant, account, or organization signed in to.
	TenantID string `json:"tenant_id,omitempty"`
	// AuthMethod is how the collector proved its identity, such as
	// AuthPrivateKeyJWT or AuthAPIToken.
	AuthMethod string `json:"auth_method,omitempty"`
	// RequestedScopes lists the scopes the collector asked for. A scope in
	// it and missing from Scopes was not granted.
	RequestedScopes []string `json:"requested_scopes,omitempty"`
	// Scopes lists the permissions the sign-in carried.
	Scopes []string `json:"scopes,omitempty"`
	// ReadOnly is true when the collector can show that its credential could
	// only read, such as a token that carries only the read scopes it asked
	// for. Leave it false otherwise.
	ReadOnly bool `json:"read_only,omitempty"`
	// ID identifies the principal. It appears at the audit and internal
	// levels only.
	ID string `json:"id,omitempty"`
}

// clone returns a copy of p that shares none of its lists.
func (p Principal) clone() Principal {
	p.Scopes = slices.Clone(p.Scopes)
	p.RequestedScopes = slices.Clone(p.RequestedScopes)
	return p
}

// Sign-in methods for Principal.AuthMethod. A collector whose sign-in fits
// none of them names its own in the same form.
const (
	// AuthAPIToken is a static token or key the vendor issued.
	AuthAPIToken = "api_token"
	// AuthClientSecret is OAuth 2.0 client credentials with a shared secret.
	AuthClientSecret = "client_secret"
	// AuthPrivateKeyJWT is OAuth 2.0 client credentials with a key
	// assertion the collector signs, as RFC 7523 describes.
	AuthPrivateKeyJWT = "private_key_jwt"
	// AuthWorkloadIdentity is a token from the runner's own identity
	// provider, such as a CI job's OIDC token, exchanged for the vendor's.
	AuthWorkloadIdentity = "workload_identity"
	// AuthAccessKey is a cloud provider's access key pair, such as AWS's.
	AuthAccessKey = "access_key"
)

// Mirrored is one Recorder.Mirror call, which copies a value's gap from one
// location to another, such as from a detailed value to the normalized value
// copied from it.
type Mirrored struct {
	From, To Location
}

// Recorder collects a run's gaps and sign-in identity. The SDK writes them
// into the run's result artifact at Emit.
type Recorder struct {
	mu        sync.Mutex
	gaps      []Gap
	principal *Principal
	mirrors   []Mirrored
}

// Records returns ctx's recorder. Contexts that RunCollector or RunInProcess
// did not create get a recorder nothing reads.
func Records(ctx CollectorContext) *Recorder {
	return runOf(ctx).records
}

// NotCollected records that the value at at was left out because of err,
// classified with Classify. The value itself must be absent or null in the
// emitted artifact; Emit fails otherwise. When err came from a call the
// SDK's client made, or from ResponseError, the gap names that call.
func (r *Recorder) NotCollected(at Location, err error, opts ...GapOption) {
	r.add(at, GapNotCollected, 0, classifyOrInternal(err), err, errorText(err), opts)
}

// NotCollectedCode records a left-out value with a code the collector chose,
// such as CodeNotLicensed for a feature the plan lacks.
func (r *Recorder) NotCollectedCode(at Location, code Code, detail string, opts ...GapOption) {
	r.add(at, GapNotCollected, 0, code, nil, detail, opts)
}

// Partial records that the rollup at at was left out because unmeasured of
// the items it covers could not be read, err being the first of the
// failures, whose call the gap names. A rollup over the items that were
// read could still show 100%, so it is not written. At a list or object,
// such as a list read in part, Partial instead says the value holds only
// the items that were read, and the value may be emitted.
func (r *Recorder) Partial(at Location, unmeasured int, err error, opts ...GapOption) {
	r.add(at, GapPartial, unmeasured, classifyOrInternal(err), err, errorText(err), opts)
}

// Mirror records at to the gap that covers from, with all its details, such
// as for a normalized value copied from a detailed one. The gap that covers
// from names its artifact the way from does, by the same Schema and Path,
// and sits at from's pointer or, failing that, at the nearest value that
// contains it. Mirror records nothing when no gap covers from, or when to
// has a gap already. Call it for every value copied, gap or not: the test
// kit reads the calls to map each copy to the value it copies.
func (r *Recorder) Mirror(from, to Location) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if pair := (Mirrored{From: from, To: to}); !slices.Contains(r.mirrors, pair) {
		r.mirrors = append(r.mirrors, pair)
	}
	source := -1
	for i, g := range r.gaps {
		if g.Schema != from.Schema || g.Path != from.Path || !covers(g.Pointer, from.Pointer) {
			continue
		}
		if source < 0 || len(g.Pointer) > len(r.gaps[source].Pointer) {
			source = i
		}
	}
	if source < 0 {
		return
	}
	g := r.gaps[source]
	g.Schema, g.Path, g.Pointer = to.Schema, to.Path, to.Pointer
	r.keep(g)
}

// covers reports whether the value at pointer is the one at gap or inside it.
func covers(gap, pointer string) bool {
	return gap == "" || pointer == gap || strings.HasPrefix(pointer, gap+"/")
}

// SignedInAs records the identity the collector signed in as.
func (r *Recorder) SignedInAs(p Principal) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := p.clone()
	sort.Strings(cp.Scopes)
	sort.Strings(cp.RequestedScopes)
	r.principal = &cp
}

// Gaps returns a copy of the gaps recorded so far.
func (r *Recorder) Gaps() []Gap {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Gap(nil), r.gaps...)
}

// mirrored returns a copy of the Mirror calls made so far.
func (r *Recorder) mirrored() []Mirrored {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Mirrored(nil), r.mirrors...)
}

func (r *Recorder) signedIn() *Principal {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.principal == nil {
		return nil
	}
	cp := r.principal.clone()
	return &cp
}

// add keeps the first gap recorded for a location.
func (r *Recorder) add(at Location, status string, unmeasured int, code Code, err error, detail string, opts []GapOption) {
	if !code.Valid() {
		code = CodeInternal
	}
	g := Gap{
		Schema:     at.Schema,
		Path:       at.Path,
		Pointer:    at.Pointer,
		Status:     status,
		Code:       code,
		Owner:      code.Owner(),
		VendorCode: VendorCodeOf(err),
		Unmeasured: unmeasured,
		Source:     gapSource(),
		Detail:     detail,
	}
	if c, ok := callOf(err); ok {
		g.Operation, g.Call = c.operation, c.call
	}
	for _, o := range opts {
		if o.apply != nil {
			o.apply(&g)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keep(g)
}

// keep adds g unless a gap is already recorded at its location. The caller
// holds r.mu.
func (r *Recorder) keep(g Gap) {
	for _, existing := range r.gaps {
		if existing.Schema == g.Schema && existing.Path == g.Path && existing.Pointer == g.Pointer {
			return
		}
	}
	r.gaps = append(r.gaps, g)
}

func classifyOrInternal(err error) Code {
	if code := Classify(err); code != "" {
		return code
	}
	return CodeInternal
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
