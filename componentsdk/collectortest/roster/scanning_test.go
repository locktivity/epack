package roster

import (
	"strings"
	"testing"
)

// inspectorAccounts has two AWS accounts. Inspector is on for hosts in both
// and for containers in prod only. Prod has a host Inspector doesn't scan
// and an overdue critical finding, and stage a high finding that isn't
// overdue.
const inspectorAccounts = `{
  "version": 1,
  "vendor": "test",
  "scanning": {"scopes": {
    "prod": {
      "kind": "AWS_ACCOUNT",
      "scanners": {"Inspector": {"states": {"EC2": "ENABLED", "ECR": "ENABLED"}}},
      "resources": {
        "i-1": {"type": "EC2", "scans": {"Inspector": "ACTIVE"}, "findings": {
          "a": {"scanner": "Inspector", "severity": "CRITICAL", "state": "ACTIVE", "open_days": 31}
        }},
        "i-2": {"type": "EC2", "scans": {"Inspector": "INACTIVE"}},
        "img-1": {"type": "ECR", "scans": {"Inspector": "ACTIVE"}}
      }
    },
    "stage": {
      "kind": "AWS_ACCOUNT",
      "scanners": {"Inspector": {"states": {"EC2": "ENABLED", "ECR": "DISABLED"}}},
      "resources": {
        "i-3": {"type": "EC2", "scans": {"Inspector": "ACTIVE"}, "findings": {
          "b": {"scanner": "Inspector", "severity": "HIGH", "state": "ACTIVE", "open_days": 5}
        }}
      }
    }
  }},
  "terms": {
    "vuln_scanners": {"Inspector": {"name": "inspector", "categories": {"EC2": "hosts", "ECR": "containers"}}},
    "vuln_scope_kinds": {"AWS_ACCOUNT": "account"},
    "vuln_scanner_states": {"ENABLED": "on", "DISABLED": "off"},
    "vuln_scan_statuses": {"ACTIVE": "scanned", "INACTIVE": "not_scanned"},
    "vuln_severities": {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INFORMATIONAL": "none"},
    "vuln_finding_states": {"ACTIVE": "open", "SUPPRESSED": "closed", "CLOSED": "closed"}
  }
}`

func deriveScanned(t *testing.T, r *Roster) map[string]any {
	t.Helper()
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	values, err := Derive(r)
	if err != nil {
		t.Fatal(err)
	}
	return values[VulnScanning]
}

func checkScanningValues(t *testing.T, got map[string]any, want map[string]any) {
	t.Helper()
	for _, pointer := range sortedKeys(want) {
		if v, ok := got[pointer]; !ok || !sameValue(v, want[pointer]) {
			t.Errorf("%s = %v (set %t), want %v", pointer, v, ok, want[pointer])
		}
	}
}

// With several accounts, the system's entries total the scopes': a scanner
// is enabled only when it is enabled in every scope, counts add up, and a
// present flag is true when it is true in any scope.
func TestDeriveScanningTotalsScopes(t *testing.T) {
	r, err := Parse([]byte(inspectorAccounts))
	if err != nil {
		t.Fatal(err)
	}
	checkScanningValues(t, deriveScanned(t, r), map[string]any{
		"/scopes/0/id":                                "prod",
		"/scopes/0/kind":                              "account",
		"/scopes/0/scanners/0/scanner":                "inspector",
		"/scopes/0/scanners/0/category":               "hosts",
		"/scopes/0/scanners/0/resource_count":         2,
		"/scopes/0/scanners/0/scanned_resource_count": 1,
		"/scopes/0/scanners/0/coverage_pct":           50,
		"/scopes/0/scanners/0/overdue_critical_count": 1,
		"/scopes/0/scanners/0/open_high_present":      false,
		"/scopes/0/scanners/1/category":               "containers",
		"/scopes/0/scanners/1/enabled":                true,
		"/scopes/1/id":                                "stage",
		"/scopes/1/scanners/0/open_high_count":        1,
		"/scopes/1/scanners/0/overdue_present":        false,
		"/scopes/1/scanners/1/enabled":                false,
		"/scopes/1/scanners/1/resource_count":         0,
		"/scopes/1/scanners/1/resources_present":      false,
		"/scopes/1/scanners/1/coverage_pct":           nil,

		"/scanners/0/scanner":                "inspector",
		"/scanners/0/category":               "hosts",
		"/scanners/0/enabled":                true,
		"/scanners/0/resource_count":         3,
		"/scanners/0/scanned_resource_count": 2,
		"/scanners/0/coverage_pct":           66,
		"/scanners/0/resources_present":      true,
		"/scanners/0/open_critical_count":    1,
		"/scanners/0/open_high_count":        1,
		"/scanners/0/open_critical_present":  true,
		"/scanners/0/open_high_present":      true,
		"/scanners/0/overdue_critical_count": 1,
		"/scanners/0/overdue_high_count":     0,
		"/scanners/0/overdue_present":        true,
		"/scanners/1/category":               "containers",
		"/scanners/1/enabled":                false,
		"/scanners/1/resource_count":         1,
		"/scanners/1/coverage_pct":           100,
	})
}

// A finding counts by its severity while it is open. A critical one is
// overdue after 30 days and a high one after 90. No other is ever overdue,
// and one rated none or not rated counts nowhere.
func TestDeriveScanningCountsOpenAndOverdueFindings(t *testing.T) {
	r, err := Parse([]byte(inspectorAccounts))
	if err != nil {
		t.Fatal(err)
	}
	days := func(n int) *int { return &n }
	cases := []struct {
		name    string
		finding VulnFinding
		want    map[string]any
	}{
		{"critical for 30 days", VulnFinding{Severity: "CRITICAL", State: "ACTIVE", OpenDays: days(30)},
			map[string]any{"open_critical_count": 1, "overdue_critical_count": 0, "overdue_present": false}},
		{"critical for 31 days", VulnFinding{Severity: "CRITICAL", State: "ACTIVE", OpenDays: days(31)},
			map[string]any{"open_critical_count": 1, "overdue_critical_count": 1, "overdue_present": true}},
		{"high for 90 days", VulnFinding{Severity: "HIGH", State: "ACTIVE", OpenDays: days(90)},
			map[string]any{"open_high_count": 1, "overdue_high_count": 0, "overdue_present": false}},
		{"high for 91 days", VulnFinding{Severity: "HIGH", State: "ACTIVE", OpenDays: days(91)},
			map[string]any{"open_high_count": 1, "overdue_high_count": 1, "overdue_present": true}},
		{"medium for 1000 days", VulnFinding{Severity: "MEDIUM", State: "ACTIVE", OpenDays: days(1000)},
			map[string]any{"open_medium_count": 1, "overdue_present": false}},
		{"low", VulnFinding{Severity: "LOW", State: "ACTIVE", OpenDays: days(1)},
			map[string]any{"open_low_count": 1, "open_critical_present": false, "open_high_present": false}},
		{"informational", VulnFinding{Severity: "INFORMATIONAL", State: "ACTIVE", OpenDays: days(500)},
			map[string]any{"open_critical_count": 0, "open_high_count": 0, "open_medium_count": 0, "open_low_count": 0}},
		{"not rated", VulnFinding{State: "ACTIVE", OpenDays: days(500)},
			map[string]any{"open_critical_count": 0, "open_high_count": 0, "open_medium_count": 0, "open_low_count": 0}},
		{"closed critical", VulnFinding{Severity: "CRITICAL", State: "CLOSED", OpenDays: days(100)},
			map[string]any{"open_critical_count": 0, "overdue_critical_count": 0, "open_critical_present": false}},
		{"suppressed critical", VulnFinding{Severity: "CRITICAL", State: "SUPPRESSED"},
			map[string]any{"open_critical_count": 0, "overdue_present": false}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := r.Clone()
			tc.finding.Key, tc.finding.Scanner = "f", "Inspector"
			c.Scanning.Scopes[1].Resources[0].Findings = []VulnFinding{tc.finding}
			got := deriveScanned(t, c)
			want := map[string]any{}
			for field, v := range tc.want {
				want["/scopes/1/scanners/0/"+field] = v
			}
			checkScanningValues(t, got, want)
		})
	}
	if len(r.Scanning.Scopes[1].Resources[0].Findings) != 1 {
		t.Error("changing the clone changed the roster")
	}
}

// A scanner switched on or off for a scope as a whole is enabled when its
// switch is on, whatever it scans. One turned on per resource is enabled
// when it scans at least one resource.
func TestDeriveScanningEnabled(t *testing.T) {
	r, err := Parse([]byte(inspectorAccounts))
	if err != nil {
		t.Fatal(err)
	}
	prod := func(change func(*ScanScope)) func(*Roster) {
		return func(c *Roster) { change(&c.Scanning.Scopes[0]) }
	}
	cases := []struct {
		name               string
		change             func(*Roster)
		hosts, containers  bool
		stageContainersOn  bool
		stageContainersPct any
	}{
		{"switched", func(*Roster) {}, true, true, false, nil},
		{"switched on with nothing to scan", func(c *Roster) { c.Scanning.Scopes[1].Switches[0].States["ECR"] = "ENABLED" }, true, true, true, nil},
		{"switched off with a resource it scans", prod(func(s *ScanScope) { s.Switches[0].States["ECR"] = "DISABLED" }), true, false, false, nil},
		{"per resource, one scanned", prod(func(s *ScanScope) { s.Switches = nil }), true, true, false, nil},
		{"per resource, none scanned", prod(func(s *ScanScope) {
			s.Switches = nil
			for i := range s.Resources {
				s.Resources[i].Scans = map[string]string{"Inspector": "INACTIVE"}
			}
		}), false, false, false, nil},
		{"switched for hosts only", prod(func(s *ScanScope) { s.Switches[0].States = map[string]string{"EC2": "DISABLED"} }), false, true, false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := r.Clone()
			tc.change(c)
			checkScanningValues(t, deriveScanned(t, c), map[string]any{
				"/scopes/0/scanners/0/enabled":      tc.hosts,
				"/scopes/0/scanners/1/enabled":      tc.containers,
				"/scopes/1/scanners/1/enabled":      tc.stageContainersOn,
				"/scopes/1/scanners/1/coverage_pct": tc.stageContainersPct,
				"/scanners/1/enabled":               tc.containers && tc.stageContainersOn,
			})
		})
	}
}

// dependabotRepos is a GitHub organization: no scopes, and Dependabot
// turned on per repository.
const dependabotRepos = `{
  "version": 1,
  "vendor": "test",
  "scanning": {"resources": {
    "api": {"type": "repository", "scans": {"Dependabot": "enabled"}, "findings": {
      "1": {"scanner": "Dependabot", "severity": "critical", "state": "open", "open_days": 2}
    }},
    "web": {"type": "repository", "scans": {"Dependabot": "disabled"}},
    "docs": {"type": "repository"}
  }},
  "terms": {
    "vuln_scanners": {"Dependabot": {"name": "dependabot", "categories": {"repository": "dependencies"}}},
    "vuln_scan_statuses": {"enabled": "scanned", "disabled": "not_scanned"},
    "vuln_severities": {"critical": "critical"},
    "vuln_finding_states": {"open": "open"}
  }
}`

func TestDeriveScanningWithoutScopes(t *testing.T) {
	r, err := Parse([]byte(dependabotRepos))
	if err != nil {
		t.Fatal(err)
	}
	got := deriveScanned(t, r)
	checkScanningValues(t, got, map[string]any{
		"/scanners/0/scanner":               "dependabot",
		"/scanners/0/category":              "dependencies",
		"/scanners/0/enabled":               true,
		"/scanners/0/resource_count":        3,
		"/scanners/0/coverage_pct":          33,
		"/scanners/0/open_critical_present": true,
		"/scanners/0/overdue_present":       false,
	})
	for pointer := range got {
		if strings.HasPrefix(pointer, "/scopes") {
			t.Errorf("%s is set, but the system has no scopes", pointer)
		}
	}

	none := r.Clone()
	none.Scanning.Resources = nil
	checkScanningValues(t, deriveScanned(t, none), map[string]any{
		"/scanners/0/enabled":           false,
		"/scanners/0/resource_count":    0,
		"/scanners/0/resources_present": false,
		"/scanners/0/coverage_pct":      nil,
	})
}

func TestParseRefusesBadScanning(t *testing.T) {
	cases := map[string]struct{ from, to, want string }{
		"severity":       {`"severity": "HIGH"`, `"severity": "SEVERE"`, `severity "SEVERE" has no entry in terms.vuln_severities`},
		"finding state":  {`"state": "ACTIVE", "open_days": 5`, `"state": "OPEN", "open_days": 5`, `state "OPEN" has no entry in terms.vuln_finding_states`},
		"scan status":    {`"scans": {"Inspector": "INACTIVE"}`, `"scans": {"Inspector": "PENDING"}`, `scan status "PENDING" has no entry in terms.vuln_scan_statuses`},
		"scope kind":     {`"kind": "AWS_ACCOUNT"`, `"kind": "AZURE_SUBSCRIPTION"`, `kind "AZURE_SUBSCRIPTION" has no entry in terms.vuln_scope_kinds`},
		"switch state":   {`"ECR": "DISABLED"`, `"ECR": "PAUSED"`, `state "PAUSED" has no entry in terms.vuln_scanner_states`},
		"scanner":        {`{"scanner": "Inspector", "severity": "HIGH"`, `{"scanner": "Snyk", "severity": "HIGH"`, `scanner "Snyk" has no entry in terms.vuln_scanners`},
		"resource type":  {`"i-2": {"type": "EC2"`, `"i-2": {"type": "RDS"`, `type "RDS" has no entry in terms.vuln_scanners`},
		"switched type":  {`"states": {"EC2": "ENABLED", "ECR": "DISABLED"}`, `"states": {"EC2": "ENABLED", "LAMBDA": "DISABLED"}`, `scans no resource of type "LAMBDA"`},
		"two scopes":     {`"i-3": {`, `"i-1": {`, `resource i-1 is also in scope prod`},
		"open days":      {`, "open_days": 5`, ``, `finding b is open and gives no open_days`},
		"future":         {`"open_days": 5`, `"open_days": -5`, `opened 5 days from now`},
		"scanner name":   {`"name": "inspector"`, `"name": "Amazon Inspector"`, `not lowercase letters, digits and underscores`},
		"category":       {`"ECR": "containers"`, `"ECR": "images"`, `scan "ECR" as "images"`},
		"term":           {`"INFORMATIONAL": "none"`, `"INFORMATIONAL": "info"`, `terms.vuln_severities maps "INFORMATIONAL" to "info"`},
		"scopes and own": {`"scanning": {"scopes": {`, `"scanning": {"resources": {"x": {"type": "EC2"}}, "scopes": {`, `has scopes and scanners or resources of its own`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			changed := strings.Replace(inspectorAccounts, tc.from, tc.to, 1)
			if changed == inspectorAccounts {
				t.Fatalf("%q is not in the roster", tc.from)
			}
			_, err := Parse([]byte(changed))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Parse() error = %v, want one containing %q", err, tc.want)
			}
		})
	}
	dup := strings.Replace(inspectorAccounts, `"vuln_scope_kinds"`, `"Inspector2": {"name": "inspector", "categories": {"EC2": "hosts"}}}, "vuln_scope_kinds"`, 1)
	dup = strings.Replace(dup, `"ECR": "containers"}}},`, `"ECR": "containers"}},`, 1)
	if _, err := Parse([]byte(dup)); err == nil || !strings.Contains(err.Error(), `both inspector for hosts`) {
		t.Errorf("Parse() error = %v, want one about two scanners with one name and category", err)
	}
}

func TestScanningExtrasStayWithTheirEntries(t *testing.T) {
	r, err := Parse([]byte(strings.Replace(inspectorAccounts, `"i-2": {"type": "EC2",`, `"i-2": {"type": "EC2", "platform": "WINDOWS",`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	var platform string
	if ok, err := r.Scanning.Scopes[0].Resources[1].Extra.Get("platform", &platform); !ok || err != nil || platform != "WINDOWS" {
		t.Fatalf("platform = %q, %t, %v", platform, ok, err)
	}
}
