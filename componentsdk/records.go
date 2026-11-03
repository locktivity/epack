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
	Schema string `json:"schema,omitempty"`
	// Path is the artifact's path in the pack.
	Path string `json:"path,omitempty"`
	// Pointer is a JSON pointer (RFC 6901) into the artifact's data. Address
	// items by array index, never by name.
	Pointer string `json:"pointer"`
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

// Gap is a value that a collector left out of its artifact, with the reason.
// Location holds the value's path and pointer.
type Gap struct {
	Location
	Status     string `json:"status"`
	Code       Code   `json:"code"`
	Owner      Owner  `json:"owner"`
	VendorCode string `json:"vendor_code,omitempty"`
	// Unmeasured counts the items a partial gap could not read. It appears at
	// the audit and internal levels only.
	Unmeasured int `json:"unmeasured,omitempty"`
	// Operation and Call name the failed call that left the value out, when
	// the gap was recorded from an error the SDK's client returned or one
	// built with ResponseError. Call matches the call on its rows, and like
	// them appears at the audit and internal levels only.
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
	// Guidance holds the advice on what to do about the gap. See Fix,
	// NoAction, Decide, and Scope.
	Guidance

	// guidanceConflict is true when the gap was given more than one of Fix,
	// NoAction, and Decide. It is also true for a Decide with fewer than two
	// options.
	guidanceConflict bool
}

// AdviceOption adds a detail to a gap or a run warning that the Recorder
// records, such as Fix or MissingPermission. A run warning takes every
// option except Warning.
type AdviceOption struct {
	apply func(*advice)
}

// GapOption is the name AdviceOption had before run warnings took options.
//
// Deprecated: Use AdviceOption.
type GapOption = AdviceOption

// advice holds what the options set on a gap or a run warning.
type advice struct {
	warning           string
	missingPermission string
	guidance          Guidance
	// conflict is true when more than one of Fix, NoAction, and Decide was
	// given. It is also true for a Decide with fewer than two options.
	conflict bool
}

// adviceOf applies opts.
func adviceOf(opts []AdviceOption) advice {
	var a advice
	for _, o := range opts {
		if o.apply != nil {
			o.apply(&a)
		}
	}
	return a
}

// MissingPermission names the permission a permission_denied gap's
// credential lacks, in the vendor's own terms, such as okta.logs.read, so
// the customer knows what to grant. It applies only to a gap whose code is
// permission_denied, and is dropped from any other. A permission holding
// whitespace or more than 256 bytes is dropped too, since it appears at
// every level.
func MissingPermission(permission string) AdviceOption {
	return AdviceOption{apply: func(a *advice) {
		if permissionName(permission) {
			a.missingPermission = permission
		}
	}}
}

// permissionName reports whether permission can appear at every level. It
// must be at most 256 bytes and have no whitespace or control characters.
func permissionName(permission string) bool {
	return permission != "" && len(permission) <= 256 && !strings.ContainsFunc(permission, unicode.IsSpace) && !strings.ContainsFunc(permission, unicode.IsControl)
}

// Warning gives a gap the collector's message to the operator about it,
// such as the role to grant. Like the error text, it is redacted and appears
// at the audit and internal levels only.
func Warning(message string) AdviceOption {
	return AdviceOption{apply: func(a *advice) { a.warning = message }}
}

// Principal is the identity a collector signed in as.
type Principal struct {
	// Provider names the identity system, such as "microsoft-entra".
	Provider string `json:"provider"`
	// Kind is the kind of principal, such as "service_principal" or "user".
	Kind string `json:"kind"`
	// TenantID is the tenant, account, or organization signed in to. It
	// appears at the audit and internal levels only.
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
	warnings  []RunWarning
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
func (r *Recorder) NotCollected(at Location, err error, opts ...AdviceOption) {
	r.add(Gap{Location: at, Status: GapNotCollected, Code: classifyOrInternal(err), Detail: errorText(err)}, err, opts)
}

// NotCollectedCode records a left-out value with a code the collector chose,
// such as CodeNotLicensed for a feature the plan lacks.
func (r *Recorder) NotCollectedCode(at Location, code Code, detail string, opts ...AdviceOption) {
	r.add(Gap{Location: at, Status: GapNotCollected, Code: code, Detail: detail}, nil, opts)
}

// Partial records that the rollup at at was left out because unmeasured of
// the items it covers could not be read, err being the first of the
// failures, whose call the gap names. A rollup over the items that were
// read could still show 100%, so it is not written. At a list or object,
// such as a list read in part, Partial instead says the value holds only
// the items that were read, and the value may be emitted.
func (r *Recorder) Partial(at Location, unmeasured int, err error, opts ...AdviceOption) {
	r.add(Gap{Location: at, Status: GapPartial, Code: classifyOrInternal(err), Unmeasured: unmeasured, Detail: errorText(err)}, err, opts)
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
	g.Location = to
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

// add fills in the rest of g from err and opts. g already holds its
// location, status, code, unmeasured count, and detail. add keeps g only if
// it is the first gap recorded for its location.
func (r *Recorder) add(g Gap, err error, opts []AdviceOption) {
	// Only the SDK records not_shared, for what the collect config key
	// leaves out.
	if !g.Code.Valid() || g.Code == CodeNotShared {
		g.Code = CodeInternal
	}
	a := adviceOf(opts)
	g.Owner = g.Code.Owner()
	g.VendorCode = VendorCodeOf(err)
	g.Source = gapSource()
	g.MissingPermission, g.Warning = a.missingPermission, a.warning
	g.Guidance, g.guidanceConflict = a.guidance, a.conflict
	if c, ok := callOf(err); ok {
		g.Operation, g.Call = c.operation, c.call
		if g.MissingPermission == "" && permissionName(c.permission) {
			g.MissingPermission = c.permission
		}
	}
	if g.Code != CodePermissionDenied {
		g.MissingPermission = ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keep(g)
}

// leaveOut records a not_shared gap on the whole artifact with schema ID
// schemaID at path, which the collect config key left out. The gap names
// the artifact by its schema when it has one, and otherwise by its path, so
// leaving one artifact out twice records one gap.
func (r *Recorder) leaveOut(schemaID, path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	at := Location{Path: path}
	if schemaID != "" {
		at = Location{Schema: schemaID}
	}
	r.keep(notSharedGap(at))
}

// notShared records that the value at at was left out because it was copied
// from an artifact the collect config key left out. It replaces any gap
// already recorded there, such as one Mirror copied from that artifact.
func (r *Recorder) notShared(at Location) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gaps = slices.DeleteFunc(r.gaps, func(g Gap) bool { return g.Location == at })
	r.keep(notSharedGap(at))
}

func notSharedGap(at Location) Gap {
	return Gap{Location: at, Status: GapNotCollected, Code: CodeNotShared, Owner: CodeNotShared.Owner(),
		Detail: "left out by the collect config key"}
}

// dropInside removes the gaps that inside reports as being in an artifact
// the run does not write.
func (r *Recorder) dropInside(inside func(Gap) bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gaps = slices.DeleteFunc(r.gaps, inside)
}

// keep adds g unless a gap is already recorded at its location. The caller
// holds r.mu.
func (r *Recorder) keep(g Gap) {
	for _, existing := range r.gaps {
		if existing.Location == g.Location {
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
