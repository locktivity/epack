package componentsdk

import (
	"sort"
	"strings"
	"sync"
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
	// Detail is redacted text from the error, shown at the audit and
	// internal levels only.
	Detail string `json:"detail,omitempty"`
}

// Principal is the identity a collector signed in as.
type Principal struct {
	// Provider names the identity system, such as "microsoft-entra".
	Provider string `json:"provider"`
	// Kind is the kind of principal, such as "service_principal" or "user".
	Kind string `json:"kind"`
	// TenantID is the tenant, account, or organization signed in to.
	TenantID string `json:"tenant_id,omitempty"`
	// Scopes lists the permissions the sign-in carried.
	Scopes []string `json:"scopes,omitempty"`
	// ID identifies the principal. It appears at the audit and internal
	// levels only.
	ID string `json:"id,omitempty"`
}

// Recorder collects a run's gaps and sign-in identity. The SDK writes them
// into the run's result artifact at Emit.
type Recorder struct {
	mu        sync.Mutex
	gaps      []Gap
	principal *Principal
}

// Records returns ctx's recorder. Contexts that RunCollector or RunInProcess
// did not create get a recorder nothing reads.
func Records(ctx CollectorContext) *Recorder {
	return runOf(ctx).records
}

// NotCollected records that the value at at was left out because of err,
// classified with Classify. The value itself must be absent or null in the
// emitted artifact; Emit fails otherwise.
func (r *Recorder) NotCollected(at Location, err error) {
	r.add(at, GapNotCollected, 0, classifyOrInternal(err), VendorCodeOf(err), errorText(err))
}

// NotCollectedCode records a left-out value with a code the collector chose,
// such as CodeNotLicensed for a feature the plan lacks.
func (r *Recorder) NotCollectedCode(at Location, code Code, detail string) {
	r.add(at, GapNotCollected, 0, code, "", detail)
}

// Partial records that the rollup at at was left out because unmeasured of
// the items it covers could not be read, err being one of the failures. A
// rollup over the items that were read could still show 100%, so it is not
// written. At a list or object, such as a list read in part, Partial instead
// says the value holds only the items that were read, and the value may be
// emitted.
func (r *Recorder) Partial(at Location, unmeasured int, err error) {
	r.add(at, GapPartial, unmeasured, classifyOrInternal(err), VendorCodeOf(err), errorText(err))
}

// Mirror records at to the gap that covers from, with the same status, code,
// owner, vendor code, detail, and unmeasured count, such as for a normalized
// value copied from a detailed one. The gap that covers from names its
// artifact the way from does, by the same Schema and Path, and sits at
// from's pointer or, failing that, at the nearest value that contains it.
// Mirror records nothing when no gap covers from, or when to has a gap
// already.
func (r *Recorder) Mirror(from, to Location) {
	r.mu.Lock()
	defer r.mu.Unlock()
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
	cp := p
	cp.Scopes = append([]string(nil), p.Scopes...)
	sort.Strings(cp.Scopes)
	r.principal = &cp
}

// Gaps returns a copy of the gaps recorded so far.
func (r *Recorder) Gaps() []Gap {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Gap(nil), r.gaps...)
}

func (r *Recorder) signedIn() *Principal {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.principal == nil {
		return nil
	}
	cp := *r.principal
	cp.Scopes = append([]string(nil), r.principal.Scopes...)
	return &cp
}

// add keeps the first gap recorded for a location.
func (r *Recorder) add(at Location, status string, unmeasured int, code Code, vendorCode, detail string) {
	if !code.Valid() {
		code = CodeInternal
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keep(Gap{
		Schema:     at.Schema,
		Path:       at.Path,
		Pointer:    at.Pointer,
		Status:     status,
		Code:       code,
		Owner:      code.Owner(),
		VendorCode: vendorCode,
		Unmeasured: unmeasured,
		Detail:     detail,
	})
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
