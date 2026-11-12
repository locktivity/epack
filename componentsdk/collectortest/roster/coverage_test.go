package roster

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/outputcheck"
)

func TestAlignMatchesListEntriesByIdentity(t *testing.T) {
	doc, err := outputcheck.Decode([]byte(`{"domains": [
	  {"domain": "a.example", "dkim": [{"selector": "s2"}, {"selector": "s1"}]},
	  {"domain": "b.example", "dkim": []}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]any{
		"/summary/total_domains":     3,
		"/domains/0/domain":          "b.example",
		"/domains/1/domain":          "c.example",
		"/domains/1/dkim/0/valid":    true,
		"/domains/2/domain":          "a.example",
		"/domains/2/dkim/0/selector": "s1",
		"/domains/2/dkim/1/selector": "s2",
		"/domains/2/dkim/1/valid":    false,
	}
	want := map[string]any{
		"/summary/total_domains":     3,
		"/domains/1/domain":          "b.example",
		"/domains/2/domain":          "c.example",
		"/domains/2/dkim/0/valid":    true,
		"/domains/0/domain":          "a.example",
		"/domains/0/dkim/1/selector": "s1",
		"/domains/0/dkim/0/selector": "s2",
		"/domains/0/dkim/0/valid":    false,
	}
	got := Align(EmailDNS, doc, values)
	for _, pointer := range slices.Sorted(func(yield func(string) bool) {
		for k := range want {
			if !yield(k) {
				return
			}
		}
	}) {
		if !sameValue(got[pointer], want[pointer]) {
			t.Errorf("%s = %v, want %v", pointer, got[pointer], want[pointer])
		}
	}
	if len(got) != len(want) {
		t.Errorf("Align gave %d values, want %d: %v", len(got), len(want), got)
	}
}

// Settle's Expect values align by their exact identity values. An entry
// whose identity is only a range keeps its index.
func TestAlignReadsSettledValues(t *testing.T) {
	doc, err := outputcheck.Decode([]byte(`{"scanners": [{"scanner": "dependabot", "category": "dependencies"}, {"scanner": "code_scanning", "category": "code"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	got := Align(VulnScanning, doc, map[string]any{
		"/scanners/0/scanner":  Expect{Exact: "code_scanning"},
		"/scanners/0/category": Expect{Exact: "code"},
		"/scanners/0/enabled":  Expect{Exact: true},
		"/scanners/1/scanner":  Expect{Exact: "dependabot"},
		"/scanners/1/category": Expect{Exact: "dependencies"},
	})
	if e, ok := got["/scanners/1/enabled"].(Expect); !ok || e.Exact != true {
		t.Errorf("/scanners/1/enabled = %v, want code_scanning's true", got["/scanners/1/enabled"])
	}
	if e, ok := got["/scanners/0/scanner"].(Expect); !ok || e.Exact != "dependabot" {
		t.Errorf("/scanners/0/scanner = %v, want dependabot", got["/scanners/0/scanner"])
	}
}

// Counts are audit-level in vuln-scanning, so a trust run leaves them out,
// and the present flags and percentages stay.
func TestAboveLevelFollowsTheSchema(t *testing.T) {
	for pointer, want := range map[string]bool{
		"/scanners/0/resource_count":  true,
		"/scanners/0/coverage_pct":    false,
		"/scanners/0/overdue_present": false,
		"/scopes/0/id":                true,
	} {
		got, err := AboveLevel(VulnScanning, pointer, "trust")
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("AboveLevel(%s, trust) = %t, want %t", pointer, got, want)
		}
		if got, _ := AboveLevel(VulnScanning, pointer, "audit"); got {
			t.Errorf("AboveLevel(%s, audit) = true, want false", pointer)
		}
	}
}

func TestAlignKeepsTheIndexOfAnEntryWithNoIdentity(t *testing.T) {
	doc, err := outputcheck.Decode([]byte(`{"accounts": [{"account_id": "sub-1"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	got := Align(CloudPosture, doc, map[string]any{"/accounts/0/network/security_group_count": 2})
	if got["/accounts/0/network/security_group_count"] != 2 {
		t.Errorf("Align moved an entry with no identity: %v", got)
	}
}

func TestUncoveredListsWhatDeriveGivesNoValueFor(t *testing.T) {
	artifact := []byte(`{"schema_version": "1.0.0", "collected_at": "2026-11-11T00:00:00Z",
	  "endpoints": [{"host": "a.example", "port": 443, "reachable": true, "tls": {"protocol_support": {"tls_1_3": true}}}],
	  "summary": {"total_endpoints": 1, "reachable_count": 1}}`)
	values := map[string]any{
		"/schema_version":          "1.0.0",
		"/endpoints/0/host":        "a.example",
		"/endpoints/0/port":        443,
		"/endpoints/0/reachable":   true,
		"/summary/total_endpoints": 1,
	}
	got, err := Uncovered(TLS, artifact, values)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/endpoints/0/tls/protocol_support/tls_1_3", "/summary/reachable_count"}
	if !slices.Equal(got, want) {
		t.Errorf("Uncovered = %v, want %v", got, want)
	}
}

func TestEveryListHasAnIdentity(t *testing.T) {
	for short, id := range schemaIDs {
		s, err := compileSchema(id)
		if err != nil {
			t.Fatal(err)
		}
		for _, list := range outputcheck.Lists(s) {
			if _, ok := identities[id][list]; !ok {
				t.Errorf("%s: list %s has no entry in identities", short, list)
			}
		}
	}
}

// TestDeriveAnswersEveryField derives values from every roster in testdata,
// each way its unsettled attributes could turn out, and checks that between
// them they answer every field of every normalized schema that NotDerived
// doesn't list.
func TestDeriveAnswersEveryField(t *testing.T) {
	paths, err := filepath.Glob("testdata/*.roster.json")
	if err != nil {
		t.Fatal(err)
	}
	derived := map[string][]map[string]any{}
	for _, path := range paths {
		r, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		realizations, err := r.Realizations()
		if err != nil {
			t.Fatal(err)
		}
		for _, real := range realizations {
			values, err := Derive(real.Roster)
			if err != nil {
				t.Fatalf("%s %s: %v", path, real.Name, err)
			}
			for id, v := range values {
				derived[id] = append(derived[id], v)
			}
		}
	}
	for _, short := range sortedKeys(schemaIDs) {
		t.Run(short, func(t *testing.T) {
			missing, err := Unanswered(schemaIDs[short], derived[schemaIDs[short]])
			if err != nil {
				t.Fatal(err)
			}
			if len(missing) > 0 {
				t.Errorf("no roster in testdata gives a value for %d fields:\n  %s", len(missing), strings.Join(missing, "\n  "))
			}
		})
	}
}
