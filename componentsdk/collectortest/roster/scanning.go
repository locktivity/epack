package roster

import (
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
)

// Normalized scanning terms.
const (
	VulnAccount      = "account"
	VulnSubscription = "subscription"

	VulnHosts        = "hosts"
	VulnContainers   = "containers"
	VulnFunctions    = "functions"
	VulnDependencies = "dependencies"
	VulnCode         = "code"
	VulnSecrets      = "secrets"

	VulnOn  = "on"
	VulnOff = "off"

	VulnScanned    = "scanned"
	VulnNotScanned = "not_scanned"

	VulnCritical = "critical"
	VulnHigh     = "high"
	VulnMedium   = "medium"
	VulnLow      = "low"
	// VulnUnrated is a severity that is none of the others, such as
	// informational or untriaged.
	VulnUnrated = "none"

	VulnOpen   = "open"
	VulnClosed = "closed"
)

// The days a critical and a high finding may stay open before they are
// overdue.
const (
	vulnOverdueCriticalDays = 30
	vulnOverdueHighDays     = 90
)

// vulnCategories are the vuln-scanning categories, in the schema's order.
var vulnCategories = []string{VulnHosts, VulnContainers, VulnFunctions, VulnDependencies, VulnCode, VulnSecrets}

var vulnScannerName = regexp.MustCompile(`^[a-z0-9_]+$`)

// Scanning is the vulnerability scanners a system runs and what they found.
// In a roster file:
//
//	"scanning": {
//	  "scopes": {"<id>": {"kind": "...", "scanners": {...}, "resources": {...}}},
//	  "scanners": {"<scanner>": {"states": {"<resource type>": "..."}}},
//	  "resources": {"<key>": {"type": "...", "scans": {"<scanner>": "..."},
//	    "findings": {"<key>": {"scanner": "...", "severity": "...",
//	      "state": "...", "open_days": 45}}}}
//	}
//
// and in the terms block:
//
//	"vuln_scanners": {"<scanner>": {"name": "inspector",
//	  "categories": {"<resource type>": "hosts"}}},
//	"vuln_scope_kinds": {...}, "vuln_scanner_states": {...},
//	"vuln_scan_statuses": {...}, "vuln_severities": {...},
//	"vuln_finding_states": {...}
//
// A system with accounts or subscriptions, such as AWS, lists each in
// scopes, keyed by its ID, with the scope's kind, scanners and resources. A
// system without them, such as a GitHub organization, has its scanners and
// resources in the block itself and no scopes. A resource is in one scope
// only.
//
// vuln_scanners lists the system's scanners. Each has the fixed name the
// schema gives it, and the category it scans each type of resource as. A
// scanner has an entry in every scope for each category it scans, and the
// resources it could cover there are the scope's resources of a type it
// scans as that category.
//
// A scope's scanners are those turned on or off for the scope as a whole,
// such as Amazon Inspector in an AWS account, with the vendor's state for
// each type of resource. A scanner, or a type of resource, the scope's
// scanners give no state for is turned on per resource, such as Dependabot
// per repository. A resource's scans give the vendor's scan status, such as
// ACTIVE, for each scanner that lists the resource. A scanner that doesn't
// list a resource doesn't scan it.
//
// A finding is one scanner's finding on the resource that holds it. One the
// vendor rates no severity, such as a leaked secret, leaves severity out.
// An open finding gives open_days, the whole days it has been open at the
// time of the run.
type Scanning struct {
	// Scopes are the system's accounts or subscriptions, in ID order. A
	// system without them has none, and its scanners and resources are in
	// the embedded ScanScope.
	Scopes []ScanScope
	ScanScope
}

// ScanScope is one account or subscription's scanners and resources, or a
// whole system's when it has no scopes.
type ScanScope struct {
	ID   string
	Kind string
	// Switches are the scanners turned on or off for the scope as a whole.
	Switches  []ScannerSwitch
	Resources []ScanResource
	Extra     Extra
}

// ScannerSwitch is a scanner turned on or off for a scope as a whole.
type ScannerSwitch struct {
	Scanner string
	// States gives the vendor's state, such as ENABLED, by resource type.
	States map[string]string
	Extra  Extra
}

// ScanResource is a resource a scanner could cover, such as a host or a
// repository.
type ScanResource struct {
	Key  string
	Type string
	// Scans gives the vendor's scan status by scanner, for each scanner that
	// lists the resource.
	Scans    map[string]string
	Findings []VulnFinding
	Extra    Extra
}

// VulnFinding is a scanner's finding on a resource.
type VulnFinding struct {
	Key     string
	Scanner string
	// Severity is the vendor's rating, or empty when it gives none.
	Severity string
	State    string
	// OpenDays is the whole days an open finding has been open at the time
	// of the run.
	OpenDays *int
	Extra    Extra
}

// ScanningTerms maps the vendor terms a roster's scanning block uses to
// normalized ones.
type ScanningTerms struct {
	// VulnScanners gives, for each vendor scanner, its fixed name and the
	// category it scans each type of resource as.
	VulnScanners      map[string]ScannerTerms `json:"vuln_scanners"`
	VulnScopeKinds    map[string]string       `json:"vuln_scope_kinds"`
	VulnScannerStates map[string]string       `json:"vuln_scanner_states"`
	VulnScanStatuses  map[string]string       `json:"vuln_scan_statuses"`
	VulnSeverities    map[string]string       `json:"vuln_severities"`
	VulnFindingStates map[string]string       `json:"vuln_finding_states"`
}

// ScannerTerms is a vendor scanner's fixed name in the vuln-scanning schema,
// such as inspector, and the category it scans each vendor resource type
// as.
type ScannerTerms struct {
	Name       string            `json:"name"`
	Categories map[string]string `json:"categories"`
}

var scanningDomain = domain{
	key: "scanning",
	parse: func(r *Roster, raw json.RawMessage) error {
		s, err := parseScanning(raw)
		if err != nil {
			return err
		}
		r.Scanning = s
		return nil
	},
	validate: validateScanning,
	clone: func(c, r *Roster) {
		if r.Scanning != nil {
			c.Scanning = r.Scanning.clone()
		}
	},
	derive:     deriveScanning,
	notDerived: map[string]map[string]string{VulnScanning: {}},
}

func parseScanning(raw json.RawMessage) (*Scanning, error) {
	var b struct {
		Scopes map[string]json.RawMessage `json:"scopes"`
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, err
	}
	own, err := parseScanScope("", raw, "scopes")
	if err != nil {
		return nil, err
	}
	s := &Scanning{ScanScope: own}
	for _, id := range sortedKeys(b.Scopes) {
		var sc struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(b.Scopes[id], &sc); err != nil {
			return nil, fmt.Errorf("scope %s: %w", id, err)
		}
		scope, err := parseScanScope(id, b.Scopes[id], "kind")
		if err != nil {
			return nil, fmt.Errorf("scope %s: %w", id, err)
		}
		scope.Kind = sc.Kind
		s.Scopes = append(s.Scopes, scope)
	}
	return s, nil
}

// parseScanScope reads a scope's scanners and resources, leaving the fields
// named in known out of its extras.
func parseScanScope(id string, raw json.RawMessage, known ...string) (ScanScope, error) {
	var sc struct {
		Scanners  map[string]json.RawMessage `json:"scanners"`
		Resources map[string]json.RawMessage `json:"resources"`
	}
	if err := json.Unmarshal(raw, &sc); err != nil {
		return ScanScope{}, err
	}
	out := ScanScope{ID: id}
	var err error
	if out.Extra, err = extra(raw, append(known, "scanners", "resources")...); err != nil {
		return ScanScope{}, err
	}
	for _, name := range sortedKeys(sc.Scanners) {
		var sw struct {
			States map[string]string `json:"states"`
		}
		if err := json.Unmarshal(sc.Scanners[name], &sw); err != nil {
			return ScanScope{}, fmt.Errorf("scanner %s: %w", name, err)
		}
		e, err := extra(sc.Scanners[name], "states")
		if err != nil {
			return ScanScope{}, fmt.Errorf("scanner %s: %w", name, err)
		}
		out.Switches = append(out.Switches, ScannerSwitch{Scanner: name, States: sw.States, Extra: e})
	}
	for _, key := range sortedKeys(sc.Resources) {
		res, err := parseScanResource(key, sc.Resources[key])
		if err != nil {
			return ScanScope{}, err
		}
		out.Resources = append(out.Resources, res)
	}
	return out, nil
}

func parseScanResource(key string, raw json.RawMessage) (ScanResource, error) {
	var res struct {
		Type     string                     `json:"type"`
		Scans    map[string]string          `json:"scans"`
		Findings map[string]json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return ScanResource{}, fmt.Errorf("resource %s: %w", key, err)
	}
	out := ScanResource{Key: key, Type: res.Type, Scans: res.Scans}
	var err error
	if out.Extra, err = extra(raw, "type", "scans", "findings"); err != nil {
		return ScanResource{}, fmt.Errorf("resource %s: %w", key, err)
	}
	for _, fk := range sortedKeys(res.Findings) {
		var f struct {
			Scanner  string `json:"scanner"`
			Severity string `json:"severity"`
			State    string `json:"state"`
			OpenDays *int   `json:"open_days"`
		}
		if err := json.Unmarshal(res.Findings[fk], &f); err != nil {
			return ScanResource{}, fmt.Errorf("resource %s finding %s: %w", key, fk, err)
		}
		fe, err := extra(res.Findings[fk], "scanner", "severity", "state", "open_days")
		if err != nil {
			return ScanResource{}, fmt.Errorf("resource %s finding %s: %w", key, fk, err)
		}
		out.Findings = append(out.Findings, VulnFinding{Key: fk, Scanner: f.Scanner, Severity: f.Severity, State: f.State, OpenDays: f.OpenDays, Extra: fe})
	}
	return out, nil
}

func validateScanning(r *Roster) error {
	t := r.Terms
	for name, m := range map[string]struct {
		terms map[string]string
		allow []string
	}{
		"vuln_scope_kinds":    {t.VulnScopeKinds, []string{VulnAccount, VulnSubscription}},
		"vuln_scanner_states": {t.VulnScannerStates, []string{VulnOn, VulnOff}},
		"vuln_scan_statuses":  {t.VulnScanStatuses, []string{VulnScanned, VulnNotScanned}},
		"vuln_severities":     {t.VulnSeverities, []string{VulnCritical, VulnHigh, VulnMedium, VulnLow, VulnUnrated}},
		"vuln_finding_states": {t.VulnFindingStates, []string{VulnOpen, VulnClosed}},
	} {
		for _, vendor := range sortedKeys(m.terms) {
			if !slices.Contains(m.allow, m.terms[vendor]) {
				return fmt.Errorf("terms.%s maps %q to %q, which is none of %v", name, vendor, m.terms[vendor], m.allow)
			}
		}
	}
	entries := map[[2]string]string{}
	for _, vendor := range sortedKeys(t.VulnScanners) {
		st := t.VulnScanners[vendor]
		if !vulnScannerName.MatchString(st.Name) {
			return fmt.Errorf("terms.vuln_scanners names %q %q, which is not lowercase letters, digits and underscores", vendor, st.Name)
		}
		if len(st.Categories) == 0 {
			return fmt.Errorf("terms.vuln_scanners gives %q no resource type to scan", vendor)
		}
		for _, typ := range sortedKeys(st.Categories) {
			category := st.Categories[typ]
			if !slices.Contains(vulnCategories, category) {
				return fmt.Errorf("terms.vuln_scanners has %q scan %q as %q, which is none of %v", vendor, typ, category, vulnCategories)
			}
			key := [2]string{st.Name, category}
			if other, ok := entries[key]; ok && other != vendor {
				return fmt.Errorf("terms.vuln_scanners names %q and %q both %s for %s", other, vendor, st.Name, category)
			}
			entries[key] = vendor
		}
	}

	s := r.Scanning
	if s == nil {
		return nil
	}
	if len(s.Scopes) > 0 && (len(s.Switches) > 0 || len(s.Resources) > 0) {
		return fmt.Errorf("the block has scopes and scanners or resources of its own; a system with scopes keeps them in its scopes")
	}
	scopeOf := map[string]string{}
	for _, scope := range s.scopes() {
		where := ""
		if len(s.Scopes) > 0 {
			if scope.ID == "" {
				return fmt.Errorf("a scope has an empty ID")
			}
			where = "scope " + scope.ID + " "
			if err := mapped(t.VulnScopeKinds, "vuln_scope_kinds", where+"kind", scope.Kind); err != nil {
				return err
			}
		}
		for _, sw := range scope.Switches {
			for _, typ := range sortedKeys(sw.States) {
				if err := r.scansType(where+"scanner", sw.Scanner, typ); err != nil {
					return err
				}
				if err := mapped(t.VulnScannerStates, "vuln_scanner_states", where+"scanner "+sw.Scanner+" state", sw.States[typ]); err != nil {
					return err
				}
			}
		}
		for _, res := range scope.Resources {
			what := where + "resource " + res.Key
			if prev, ok := scopeOf[res.Key]; ok {
				return fmt.Errorf("%s is also in scope %s; a resource is in one scope only", what, prev)
			}
			scopeOf[res.Key] = scope.ID
			if !r.scannedType(res.Type) {
				return fmt.Errorf("%s type %q has no entry in terms.vuln_scanners categories", what, res.Type)
			}
			for _, scanner := range sortedKeys(res.Scans) {
				if err := r.scansType(what+" scanner", scanner, res.Type); err != nil {
					return err
				}
				if err := mapped(t.VulnScanStatuses, "vuln_scan_statuses", what+" scan status", res.Scans[scanner]); err != nil {
					return err
				}
			}
			for _, f := range res.Findings {
				fwhat := what + " finding " + f.Key
				if err := r.scansType(fwhat+" scanner", f.Scanner, res.Type); err != nil {
					return err
				}
				if f.Severity != "" {
					if err := mapped(t.VulnSeverities, "vuln_severities", fwhat+" severity", f.Severity); err != nil {
						return err
					}
				}
				if err := mapped(t.VulnFindingStates, "vuln_finding_states", fwhat+" state", f.State); err != nil {
					return err
				}
				if f.OpenDays != nil && *f.OpenDays < 0 {
					return fmt.Errorf("%s opened %d days from now", fwhat, -*f.OpenDays)
				}
				if t.VulnFindingStates[f.State] == VulnOpen && f.OpenDays == nil {
					return fmt.Errorf("%s is open and gives no open_days", fwhat)
				}
			}
		}
	}
	return nil
}

// scansType checks that terms.vuln_scanners has scanner, and that it scans
// resources of type typ.
func (r *Roster) scansType(what, scanner, typ string) error {
	st, ok := r.Terms.VulnScanners[scanner]
	if !ok {
		return fmt.Errorf("%s %q has no entry in terms.vuln_scanners", what, scanner)
	}
	if _, ok := st.Categories[typ]; !ok {
		return fmt.Errorf("%s %q scans no resource of type %q in terms.vuln_scanners", what, scanner, typ)
	}
	return nil
}

// scannedType reports whether a scanner in terms.vuln_scanners scans
// resources of type typ.
func (r *Roster) scannedType(typ string) bool {
	for _, st := range r.Terms.VulnScanners {
		if _, ok := st.Categories[typ]; ok {
			return true
		}
	}
	return false
}

// scopes lists the scopes a scanner has an entry in: each of s's scopes, or
// the system itself when it has none.
func (s *Scanning) scopes() []ScanScope {
	if len(s.Scopes) > 0 {
		return s.Scopes
	}
	return []ScanScope{s.ScanScope}
}

func (s *Scanning) clone() *Scanning {
	c := &Scanning{Scopes: slices.Clone(s.Scopes), ScanScope: s.ScanScope.clone()}
	for i := range c.Scopes {
		c.Scopes[i] = c.Scopes[i].clone()
	}
	return c
}

func (sc ScanScope) clone() ScanScope {
	sc.Switches = slices.Clone(sc.Switches)
	for i := range sc.Switches {
		sc.Switches[i].States = maps.Clone(sc.Switches[i].States)
	}
	sc.Resources = slices.Clone(sc.Resources)
	for i := range sc.Resources {
		res := &sc.Resources[i]
		res.Scans = maps.Clone(res.Scans)
		res.Findings = slices.Clone(res.Findings)
		for j := range res.Findings {
			if f := &res.Findings[j]; f.OpenDays != nil {
				days := *f.OpenDays
				f.OpenDays = &days
			}
		}
	}
	return sc
}

// scanEntry is one scanner and category, an entry in a scope's scanners.
type scanEntry struct {
	vendor, name, category string
}

// scanEntries lists the system's scanners and the categories each scans, by
// vendor scanner and then in the schema's order of categories.
func (r *Roster) scanEntries() []scanEntry {
	var out []scanEntry
	for _, vendor := range sortedKeys(r.Terms.VulnScanners) {
		st := r.Terms.VulnScanners[vendor]
		for _, category := range vulnCategories {
			if slices.Contains(slices.Collect(maps.Values(st.Categories)), category) {
				out = append(out, scanEntry{vendor: vendor, name: st.Name, category: category})
			}
		}
	}
	return out
}

// scanTally is one scanner entry's coverage and open findings.
type scanTally struct {
	enabled                      bool
	resources, scanned           int
	critical, high, medium, low  int
	overdueCritical, overdueHigh int
}

// tallyScanner gives e's tally in one scope. A scanner the scope switches
// on or off for a type of resource in e's category is enabled when it is on
// for one of them. Otherwise it is turned on per resource, and enabled when
// it scans at least one. A finding is overdue when it is critical and open
// more than 30 days, or high and open more than 90.
func (r *Roster) tallyScanner(e scanEntry, scope ScanScope) scanTally {
	inCategory := func(typ string) bool {
		category, ok := r.Terms.VulnScanners[e.vendor].Categories[typ]
		return ok && category == e.category
	}
	var t scanTally
	for _, res := range scope.Resources {
		if !inCategory(res.Type) {
			continue
		}
		t.resources++
		if status, ok := res.Scans[e.vendor]; ok && r.Terms.VulnScanStatuses[status] == VulnScanned {
			t.scanned++
		}
		for _, f := range res.Findings {
			if f.Scanner != e.vendor || r.Terms.VulnFindingStates[f.State] != VulnOpen {
				continue
			}
			switch r.Terms.VulnSeverities[f.Severity] {
			case VulnCritical:
				t.critical++
				if *f.OpenDays > vulnOverdueCriticalDays {
					t.overdueCritical++
				}
			case VulnHigh:
				t.high++
				if *f.OpenDays > vulnOverdueHighDays {
					t.overdueHigh++
				}
			case VulnMedium:
				t.medium++
			case VulnLow:
				t.low++
			}
		}
	}
	switched, on := false, false
	for _, sw := range scope.Switches {
		if sw.Scanner != e.vendor {
			continue
		}
		for typ, state := range sw.States {
			if inCategory(typ) {
				switched = true
				on = on || r.Terms.VulnScannerStates[state] == VulnOn
			}
		}
	}
	t.enabled = on || (!switched && t.scanned > 0)
	return t
}

// add totals t with a scope's tally: enabled when enabled in every scope,
// with counts that add up.
func (t *scanTally) add(o scanTally) {
	t.enabled = t.enabled && o.enabled
	t.resources += o.resources
	t.scanned += o.scanned
	t.critical += o.critical
	t.high += o.high
	t.medium += o.medium
	t.low += o.low
	t.overdueCritical += o.overdueCritical
	t.overdueHigh += o.overdueHigh
}

// totalScanner gives e's tally across the system's scopes, and each scope's
// in order.
func (r *Roster) totalScanner(e scanEntry) (scanTally, []scanTally) {
	total := scanTally{enabled: true}
	var each []scanTally
	for _, scope := range r.Scanning.scopes() {
		t := r.tallyScanner(e, scope)
		total.add(t)
		each = append(each, t)
	}
	return total, each
}

// put adds t's values to v as the scanner entry at.
func (t scanTally) put(v map[string]any, at string, e scanEntry) {
	v[at+"/scanner"] = e.name
	v[at+"/category"] = e.category
	v[at+"/enabled"] = t.enabled
	v[at+"/resource_count"] = t.resources
	v[at+"/scanned_resource_count"] = t.scanned
	v[at+"/open_critical_count"] = t.critical
	v[at+"/open_high_count"] = t.high
	v[at+"/open_medium_count"] = t.medium
	v[at+"/open_low_count"] = t.low
	v[at+"/overdue_critical_count"] = t.overdueCritical
	v[at+"/overdue_high_count"] = t.overdueHigh
	v[at+"/open_critical_present"] = t.critical > 0
	v[at+"/open_high_present"] = t.high > 0
	v[at+"/overdue_present"] = t.overdueCritical+t.overdueHigh > 0
}

// deriveScanning gives vuln-scanning's scanners, one entry for each scanner
// and category, and, for a system with scopes, each scope's. With scopes,
// the system's entries total its scopes': a scanner is enabled when it is
// enabled in every scope, its counts add up, and each *_present flag is true
// when it is true in any scope. Each resource is in one scope, so a sum
// counts it once.
func deriveScanning(r *Roster, out Values) error {
	s := r.Scanning
	if s == nil {
		return nil
	}
	v := out[VulnScanning]
	if v == nil {
		v = map[string]any{}
		out[VulnScanning] = v
	}
	for j, scope := range s.Scopes {
		at := "/scopes/" + strconv.Itoa(j)
		v[at+"/id"] = scope.ID
		v[at+"/kind"] = r.Terms.VulnScopeKinds[scope.Kind]
	}
	for i, e := range r.scanEntries() {
		total, each := r.totalScanner(e)
		total.put(v, "/scanners/"+strconv.Itoa(i), e)
		if len(s.Scopes) == 0 {
			continue
		}
		for j, t := range each {
			t.put(v, fmt.Sprintf("/scopes/%d/scanners/%d", j, i), e)
		}
	}
	return nil
}

// scanCoverage gives the scanned and total resources, across the system's
// scopes, of the one scanner that scans category, and reports whether
// exactly one does.
func (r *Roster) scanCoverage(category string) (scanned, resources int, ok bool) {
	if r.Scanning == nil {
		return 0, 0, false
	}
	var found []scanTally
	for _, e := range r.scanEntries() {
		if e.category == category {
			total, _ := r.totalScanner(e)
			found = append(found, total)
		}
	}
	if len(found) != 1 {
		return 0, 0, false
	}
	return found[0].scanned, found[0].resources, true
}
