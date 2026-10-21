// Package collector is a small collector the trace map tests build a map
// for. Its code has the shapes the analysis follows: a percentage from two
// counts, a loop with checks that skip items, a helper, rows built in a
// loop, an embedded struct, a record a MarshalJSON encodes alone, one whose
// generic type is instantiated in two packages, and a normalized copy.
package collector

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"example.com/epack-collector-fixture/internal/billing"
	"github.com/locktivity/epack/componentsdk"
)

const (
	artifactPath = "artifacts/fixture.json"
	apiURL       = "https://api.fixture.test"

	opOrg    = "fixture.org.get"
	opPeople = "fixture.people.list"
)

// Output is the detailed artifact.
type Output struct {
	Meta
	Org     string          `json:"org"`
	Users   *Users          `json:"users,omitempty"`
	Raw     Opaque          `json:"raw"`
	Plan    Lookup[Plan]    `json:"plan"`
	Billing billing.Account `json:"billing"`
	Hidden  string          `json:"-"`
}

// Meta is embedded, so its fields encode at the top level.
type Meta struct {
	CollectedAt string `json:"collected_at"`
}

// Users rolls up the people.
type Users struct {
	Total       int    `json:"total_count"`
	Enrolled    int    `json:"mfa_enrolled_count"`
	Suspended   int    `json:"suspended_count"`
	CoveragePct *int   `json:"mfa_coverage"`
	Inventory   []User `json:"inventory"`
}

// User is one row.
type User struct {
	Login string `json:"login"`
	MFA   *bool  `json:"has_active_mfa"`
}

// Opaque encodes itself as other than one of its fields, so the analysis
// cannot follow them.
type Opaque struct {
	V string `json:"v"`
}

// MarshalJSON writes a label in place of the fields.
func (o Opaque) MarshalJSON() ([]byte, error) { return json.Marshal("opaque " + o.V) }

// Lookup encodes as its record alone, so the analysis follows the record's
// fields.
type Lookup[T any] struct{ Record *T }

// MarshalJSON writes the record, or null.
func (l Lookup[T]) MarshalJSON() ([]byte, error) { return json.Marshal(l.Record) }

// Plan is the org's plan.
type Plan struct {
	Name string `json:"name"`
}

// Normalized is the normalized artifact, whose path is not a constant.
type Normalized struct {
	CoveragePct *float64 `json:"mfa_coverage_pct"`
}

type metrics struct {
	total     int
	enrolled  int
	suspended int
}

type person struct {
	Login   string   `json:"login"`
	Status  string   `json:"status"`
	Factors []factor `json:"factors"`
}

type factor struct {
	Status string `json:"status"`
}

func count(people []person) metrics {
	var m metrics
	for _, p := range people {
		if p.Status == "DEPROVISIONED" {
			continue
		}
		m.total++
		switch p.Status {
		case "SUSPENDED":
			m.suspended++
		}
		active := false
		for _, f := range p.Factors {
			if f.Status != "ACTIVE" {
				continue
			}
			active = true
		}
		if active {
			m.enrolled++
		}
	}
	return m
}

func percent(n, total int) *int {
	if total == 0 {
		return nil
	}
	p := n * 100 / total
	return &p
}

func users(people []person) *Users {
	m := count(people)
	out := &Users{Total: m.total, Suspended: m.suspended}
	out.Enrolled = m.enrolled
	out.CoveragePct = percent(m.enrolled, m.total)
	for _, p := range people {
		on := len(p.Factors) > 0
		out.Inventory = append(out.Inventory, User{Login: p.Login, MFA: &on})
	}
	return out
}

func normalize(o *Output) *Normalized {
	n := &Normalized{}
	if o.Users != nil && o.Users.CoveragePct != nil {
		v := float64(*o.Users.CoveragePct)
		n.CoveragePct = &v
	}
	return n
}

// Spec describes the collector.
func Spec() componentsdk.CollectorSpec {
	return componentsdk.CollectorSpec{Name: "fixture", Version: "0.0.1"}
}

// Run reads the org and its people and emits both artifacts.
func Run(ctx componentsdk.CollectorContext) error {
	client := componentsdk.NewHTTPClient(ctx, componentsdk.HTTPOptions{CredentialHosts: []string{"api.fixture.test"}})
	token := ctx.Secret("FIXTURE_TOKEN")
	get := func(op, path string, out any) error {
		req, err := http.NewRequestWithContext(componentsdk.WithOperation(ctx.Context(), componentsdk.Operation{Name: op}), http.MethodGet, apiURL+path, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return componentsdk.ResponseError(resp, &apiError{status: resp.StatusCode})
		}
		return componentsdk.ResponseError(resp, json.NewDecoder(resp.Body).Decode(out))
	}
	var org struct {
		Name string `json:"name"`
	}
	if err := get(opOrg, "/org", &org); err != nil {
		return fmt.Errorf("signing in: %w", err)
	}
	if org.Name == "" {
		return componentsdk.CodeError(componentsdk.CodeInvalidResponse, errors.New("signing in: the org has no name"))
	}
	gaps := gapLog{rec: componentsdk.Records(ctx)}
	out := &Output{Meta: Meta{CollectedAt: componentsdk.Now(ctx).UTC().Format("2006-01-02")}, Org: org.Name}
	out.Raw.V = org.Name
	out.Plan.Record = &Plan{Name: org.Name}
	var owner billing.Optional[billing.Owner]
	owner.Value = &billing.Owner{Name: org.Name}
	out.Billing.Owner = owner
	var people []person
	if err := get(opPeople, "/people", &people); err != nil {
		gaps.notCollected(err, "/users")
	} else {
		out.Users = users(people)
	}
	normalized := normalize(out)
	gaps.rec.Mirror(componentsdk.Location{Path: artifactPath, Pointer: "/users/mfa_coverage"},
		componentsdk.Location{Path: ctx.Name() + ".normalized.json", Pointer: "/mfa_coverage_pct"})
	return ctx.Emit([]componentsdk.CollectedArtifact{
		componentsdk.JSONArtifact(artifactPath, out, componentsdk.ArtifactMeta{}),
		{Data: normalized, Path: ctx.Name() + ".normalized.json", Schema: "evidencepack/fixture@v1"},
	})
}

// apiError is a response whose status is not 200.
type apiError struct{ status int }

func (e *apiError) Error() string   { return fmt.Sprintf("the API answered %d", e.status) }
func (e *apiError) HTTPStatus() int { return e.status }
