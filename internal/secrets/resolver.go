package secrets

import (
	"fmt"
	"os"
	"sort"

	"github.com/locktivity/epack/internal/component/config"
)

// Status says whether a variable will reach its readers in this run.
type Status string

const (
	StatusPresent        Status = "present"
	StatusMissing        Status = "missing"
	StatusApprovalNeeded Status = "approval_needed"
	StatusLocked         Status = "locked"
	StatusUnavailable    Status = "unavailable"
)

// Source says where a present value came from.
type Source string

const (
	SourceEnv      Source = "env"
	SourceKeychain Source = "keychain"
	SourceHelper   Source = "helper"
)

// Row is what the check reports for one variable. Nothing in it is derived
// from a value.
type Row struct {
	Name             string   `json:"name"`
	Status           Status   `json:"status"`
	Source           Source   `json:"source,omitempty"`
	UsedBy           []string `json:"used_by"`
	Optional         bool     `json:"optional,omitempty"`
	StoredAt         string   `json:"stored_at,omitempty"`
	ApprovedRevision int      `json:"approved_revision,omitempty"`
	Reason           string   `json:"reason,omitempty"`
	Fix              string   `json:"fix,omitempty"`
}

// Ready reports whether a value will reach the readers.
func (r Row) Ready() bool { return r.Status == StatusPresent }

// Finding is the check's line for a variable that is not ready.
func (r Row) Finding() string {
	switch r.Status {
	case StatusPresent:
		return ""
	case StatusMissing:
		if r.Fix == "" {
			return "not set: " + r.Name
		}
		return fmt.Sprintf("not set: %s; run %s", r.Name, r.Fix)
	default:
		if r.Fix == "" {
			return fmt.Sprintf("%s: %s", r.Name, r.Reason)
		}
		return fmt.Sprintf("%s: %s; run %s", r.Name, r.Reason, r.Fix)
	}
}

// StoreStatus is what the check says about the store it consulted.
type StoreStatus struct {
	Kind    string `json:"kind"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// Store states.
const (
	StoreReady       = "ready"
	StoreLocked      = "locked"
	StoreUnavailable = "unavailable"
	StoreSkipped     = "skipped"
)

// Resolution is the outcome for every variable a configuration lists.
type Resolution struct {
	Scope  Scope
	Rows   []Row
	Store  StoreStatus
	values map[string]string
	env    func(string) string
}

// Getenv returns the value a component receives for a name: the
// environment's when set, else the approved stored value, else nothing.
func (r *Resolution) Getenv(name string) string {
	if r == nil {
		return os.Getenv(name)
	}
	if value := r.env(name); value != "" {
		return value
	}
	return r.values[name]
}

// Values are the stored values this run holds, for redaction.
func (r *Resolution) Values() []string {
	if r == nil {
		return nil
	}
	values := make([]string, 0, len(r.values))
	for _, value := range r.values {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

// Blocking lists the required variables that are not ready.
func (r *Resolution) Blocking() []Row {
	if r == nil {
		return nil
	}
	var rows []Row
	for _, row := range r.Rows {
		if !row.Ready() && !row.Optional {
			rows = append(rows, row)
		}
	}
	return rows
}

// Resolver finds values for a configuration's variables.
type Resolver struct {
	Paths Paths
	Store Store
	// Env reads the process environment; nil means os.Getenv.
	Env func(string) string
	// Skip leaves the store alone, as in CI; SkipReason says why.
	Skip       bool
	SkipReason string
	// Interactive lets the store prompt, as the secret commands may; a run,
	// a check, and a fetch summary leave it false.
	Interactive bool
}

// Resolve answers for every listed variable, in name order. Covered names,
// which a signed-in session already provides, are left out. The store is
// read under a shared lock, interactively only when the resolver says so;
// after its first locked or unavailable answer it is not asked again.
func (r Resolver) Resolve(cfg *config.JobConfig, scope Scope, covered map[string]bool) (*Resolution, error) {
	env := r.Env
	if env == nil {
		env = os.Getenv
	}
	res := &Resolution{Scope: scope, values: map[string]string{}, env: env}
	listed := listedSecrets(cfg)
	var pending []listedSecret
	for _, secret := range listed {
		if covered[secret.name] {
			continue
		}
		row := Row{Name: secret.name, UsedBy: readerNames(secret.readers), Optional: secret.optional}
		if env(secret.name) != "" {
			row.Status, row.Source = StatusPresent, SourceEnv
			res.Rows = append(res.Rows, row)
			continue
		}
		pending = append(pending, secret)
	}
	switch {
	case r.Skip:
		res.Store = StoreStatus{Kind: r.storeKind(), Status: StoreSkipped, Message: r.SkipReason}
	case scope.Zero():
		res.Store = StoreStatus{Kind: r.storeKind(), Status: StoreSkipped, Message: "this folder has no pull record, so it has no scope"}
	case r.Store == nil:
		res.Store = StoreStatus{Kind: "", Status: StoreSkipped, Message: "no secret store"}
	default:
		res.Store = StoreStatus{Kind: r.Store.Kind(), Status: StoreReady}
	}
	if res.Store.Status == StoreSkipped {
		for _, secret := range pending {
			res.Rows = append(res.Rows, Row{Name: secret.name, Status: StatusMissing, UsedBy: readerNames(secret.readers), Optional: secret.optional})
		}
		sortRows(res.Rows)
		return res, nil
	}
	if len(pending) > 0 {
		if err := r.readStore(res, scope, pending); err != nil {
			return nil, err
		}
	}
	sortRows(res.Rows)
	return res, nil
}

func (r Resolver) storeKind() string {
	if r.Store == nil {
		return ""
	}
	return r.Store.Kind()
}

func (r Resolver) readStore(res *Resolution, scope Scope, pending []listedSecret) error {
	unlock, err := r.Paths.lockScope(scope, false)
	if err != nil {
		if CodeOf(err) != CodeBusy {
			return err
		}
		res.Store.Status = StoreLocked
		res.Store.Message = err.Error()
		for _, secret := range pending {
			res.Rows = append(res.Rows, Row{Name: secret.name, Status: StatusLocked, UsedBy: readerNames(secret.readers), Optional: secret.optional, Reason: err.Error()})
		}
		return nil
	}
	defer unlock()
	meta, err := r.Paths.loadMetadata()
	if err != nil {
		return err
	}
	var stopped *Row
	for _, secret := range pending {
		row := Row{Name: secret.name, UsedBy: readerNames(secret.readers), Optional: secret.optional}
		if stopped != nil {
			row.Status, row.Reason = stopped.Status, stopped.Reason
			res.Rows = append(res.Rows, row)
			continue
		}
		value, err := r.Store.Get(scope, secret.name, r.Interactive)
		switch CodeOf(err) {
		case "":
			if err != nil {
				return err
			}
			r.fill(&row, meta.record(scope, secret.name), secret.readers, scope)
			if row.Status == StatusPresent {
				res.values[secret.name] = value
			}
		case CodeNotFound:
			row.Status = StatusMissing
			row.Fix = "epack secret set " + secret.name
		case CodeLocked:
			row.Status, row.Reason = StatusLocked, err.Error()
			res.Store.Status, res.Store.Message = StoreLocked, err.Error()
			stopped = &row
		default:
			row.Status, row.Reason = StatusUnavailable, err.Error()
			res.Store.Status, res.Store.Message = StoreUnavailable, err.Error()
			stopped = &row
		}
		res.Rows = append(res.Rows, row)
	}
	return nil
}

// fill decides whether a stored value may be used: only when it is approved
// for the readers as they are now.
func (r Resolver) fill(row *Row, record *SecretRecord, readers []Reader, scope Scope) {
	row.Source = Source(r.Store.Kind())
	if record != nil {
		row.StoredAt = record.StoredAt
		if record.Approved != nil {
			row.ApprovedRevision = record.Approved.Revision
		}
	}
	var approved *Approval
	if record != nil {
		approved = record.Approved
	}
	needed, reason := needsApproval(approved, readers)
	if !needed {
		row.Status = StatusPresent
		return
	}
	row.Status = StatusApprovalNeeded
	row.Reason = reason
	if approved != nil && approved.Revision > 0 && scope.Revision > approved.Revision {
		row.Reason = fmt.Sprintf("%s (revision %d to %d)", reason, approved.Revision, scope.Revision)
	}
	row.Fix = "epack secret approve " + row.Name
}

func sortRows(rows []Row) {
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
}
