package roster

import (
	"strings"
	"testing"
)

// githubOrg has four repositories, one archived and one a fork, and its scan
// leaves out the sandbox ones. Only api protects its default branch.
const githubOrg = `{
  "version": 1,
  "vendor": "test",
  "vcs": {
    "organization": "acme",
    "two_factor_requirement": true,
    "exclude_patterns": ["sandbox-*"],
    "repositories": {
      "api": {"protections": {"classic": {"enforcement": "active", "rules": {
        "pull_request": {"approvals": 1},
        "status_checks": {"checks": ["ci"]},
        "signatures": {}
      }}}},
      "web": {"archived": true},
      "web.fork": {"fork": true},
      "sandbox-1": {}
    }
  },
  "terms": {
    "vcs_enforcements": {"active": "enforced", "evaluate": "report_only", "disabled": "off"},
    "vcs_rules": {"pull_request": "pull_request", "approval_rule": "approvals", "status_checks": "status_checks", "signatures": "signed_commits", "linear_history": "other"}
  }
}`

func deriveVCSValues(t *testing.T, r *Roster) map[string]any {
	t.Helper()
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	values, err := Derive(r)
	if err != nil {
		t.Fatal(err)
	}
	return values[VCSPosture]
}

// The organization's repositories are all of them, archived and forked ones
// included, and the scan covers those whose name matches an include pattern
// and no exclude pattern.
func TestDeriveVCSScanFollowsThePatterns(t *testing.T) {
	r, err := Parse([]byte(githubOrg))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name             string
		include, exclude []string
		scanned          int
		coverage         int
	}{
		{"every repository", nil, nil, 4, 100},
		{"excluding sandboxes", nil, []string{"sandbox-*"}, 3, 75},
		{"a prefix", []string{"web*"}, nil, 2, 50},
		{"a whole name only", []string{"we"}, nil, 0, 0},
		{"one character", []string{"web?fork"}, nil, 1, 25},
		{"a dot is a dot", []string{"web.*"}, nil, 1, 25},
		{"several includes", []string{"api", "web"}, nil, 2, 50},
		{"exclude wins", []string{"*"}, []string{"*"}, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := r.Clone()
			c.VCS.IncludePatterns, c.VCS.ExcludePatterns = tc.include, tc.exclude
			checkScanningValues(t, deriveVCSValues(t, c), map[string]any{
				"/repository_count":         4,
				"/scanned_repository_count": tc.scanned,
				"/repo_coverage_pct":        tc.coverage,
				"/repositories_present":     tc.scanned > 0,
			})
		})
	}
	checkScanningValues(t, deriveVCSValues(t, r), map[string]any{
		"/organization":                                   "acme",
		"/org_security/two_factor_required":               true,
		"/branch_protection/pr_required_repository_count": 1,
		"/branch_protection/pr_required_pct":              33,
	})
}

// A repository the collector can't read, such as one its App isn't
// installed on, is one of the organization's repositories and out of the
// scan, whatever the patterns say.
func TestDeriveVCSScanLeavesOutWhatTheCollectorCantRead(t *testing.T) {
	r, err := Parse([]byte(strings.Replace(githubOrg, `"web": {"archived": true}`, `"web": {"archived": true, "collector_access": false}`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	checkScanningValues(t, deriveVCSValues(t, r), map[string]any{
		"/repository_count":         4,
		"/scanned_repository_count": 2,
		"/repo_coverage_pct":        50,
	})
}

// A scanned repository's default branch requires what an enforced
// protection on it requires: pull requests, at least one approving review,
// at least one named status check, or signed commits. Protections combine,
// and one that is only evaluated or turned off requires nothing.
func TestDeriveVCSBranchProtection(t *testing.T) {
	r, err := Parse([]byte(githubOrg))
	if err != nil {
		t.Fatal(err)
	}
	protection := func(enforcement string, rules ...BranchRule) BranchProtection {
		return BranchProtection{Key: enforcement + "-" + rules[0].Type, Enforcement: enforcement, Rules: rules}
	}
	cases := []struct {
		name                            string
		protections                     []BranchProtection
		pr, reviews, checks, signatures int
	}{
		{"pull requests, no reviews", []BranchProtection{protection("active", BranchRule{Type: "pull_request"})}, 1, 0, 0, 0},
		{"pull requests and two reviews", []BranchProtection{protection("active", BranchRule{Type: "pull_request", Approvals: 2})}, 1, 1, 0, 0},
		{"reviews without pull requests", []BranchProtection{protection("active", BranchRule{Type: "approval_rule", Approvals: 1})}, 0, 1, 0, 0},
		{"a named check", []BranchProtection{protection("active", BranchRule{Type: "status_checks", Checks: []string{"ci"}})}, 0, 0, 1, 0},
		{"no named check", []BranchProtection{protection("active", BranchRule{Type: "status_checks"})}, 0, 0, 0, 0},
		{"signed commits", []BranchProtection{protection("active", BranchRule{Type: "signatures"})}, 0, 0, 0, 1},
		{"another rule", []BranchProtection{protection("active", BranchRule{Type: "linear_history"})}, 0, 0, 0, 0},
		{"evaluated only", []BranchProtection{protection("evaluate", BranchRule{Type: "pull_request", Approvals: 1})}, 0, 0, 0, 0},
		{"turned off", []BranchProtection{protection("disabled", BranchRule{Type: "signatures"})}, 0, 0, 0, 0},
		{"two protections combine", []BranchProtection{
			protection("active", BranchRule{Type: "pull_request"}),
			protection("active", BranchRule{Type: "approval_rule", Approvals: 1}),
			protection("evaluate", BranchRule{Type: "signatures"}),
		}, 1, 1, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := r.Clone()
			c.VCS.Repositories = []Repository{{Key: "api", Protections: tc.protections}}
			checkScanningValues(t, deriveVCSValues(t, c), map[string]any{
				"/scanned_repository_count":                             1,
				"/branch_protection/pr_required_repository_count":       tc.pr,
				"/branch_protection/approving_reviews_repository_count": tc.reviews,
				"/branch_protection/status_checks_repository_count":     tc.checks,
				"/branch_protection/signed_commits_repository_count":    tc.signatures,
				"/branch_protection/pr_required_pct":                    tc.pr * 100,
				"/branch_protection/signed_commits_pct":                 tc.signatures * 100,
			})
		})
	}

	none := r.Clone()
	none.VCS.Repositories = nil
	checkScanningValues(t, deriveVCSValues(t, none), map[string]any{
		"/repository_count":                        0,
		"/scanned_repository_count":                0,
		"/repo_coverage_pct":                       nil,
		"/repositories_present":                    false,
		"/branch_protection/approving_reviews_pct": nil,
	})
}

// The deprecated security feature percentages are the coverage of the
// scanning block's one scanner of each category, the same values as
// vuln-scanning's.
func TestDeriveVCSSecurityFeaturesFollowScanning(t *testing.T) {
	withScanning := strings.Replace(githubOrg, `"terms": {`, `"scanning": {"resources": {
	    "api": {"type": "repository", "scans": {"Dependabot": "enabled", "Secrets": "enabled"}},
	    "web": {"type": "repository", "scans": {"Dependabot": "enabled"}},
	    "docs": {"type": "repository"}
	  }},
	  "terms": {
	    "vuln_scanners": {
	      "Dependabot": {"name": "dependabot", "categories": {"repository": "dependencies"}},
	      "Secrets": {"name": "secret_scanning", "categories": {"repository": "secrets"}}
	    },
	    "vuln_scan_statuses": {"enabled": "scanned"},`, 1)
	r, err := Parse([]byte(withScanning))
	if err != nil {
		t.Fatal(err)
	}
	values, err := Derive(r)
	if err != nil {
		t.Fatal(err)
	}
	checkScanningValues(t, values[VCSPosture], map[string]any{
		"/security_features/vuln_alerts_pct":     values[VulnScanning]["/scanners/0/coverage_pct"],
		"/security_features/secret_scanning_pct": values[VulnScanning]["/scanners/1/coverage_pct"],
	})
	checkScanningValues(t, values[VCSPosture], map[string]any{
		"/security_features/vuln_alerts_pct":     66,
		"/security_features/secret_scanning_pct": 33,
	})
	if _, ok := values[VCSPosture]["/security_features/code_scanning_pct"]; ok {
		t.Error("code_scanning_pct is set, but no scanner scans code")
	}

	empty := r.Clone()
	empty.Scanning.Resources = nil
	checkScanningValues(t, deriveVCSValues(t, empty), map[string]any{"/security_features/vuln_alerts_pct": nil})

	two := r.Clone()
	two.Terms.VulnScanners = map[string]ScannerTerms{
		"Dependabot": {Name: "dependabot", Categories: map[string]string{"repository": VulnDependencies}},
		"Snyk":       {Name: "snyk", Categories: map[string]string{"repository": VulnDependencies}},
	}
	two.Scanning.Resources[0].Scans = map[string]string{"Dependabot": "enabled"}
	if _, ok := deriveVCSValues(t, two)["/security_features/vuln_alerts_pct"]; ok {
		t.Error("vuln_alerts_pct is set, but two scanners scan dependencies")
	}

	alone, err := Parse([]byte(githubOrg))
	if err != nil {
		t.Fatal(err)
	}
	for pointer := range deriveVCSValues(t, alone) {
		if strings.HasPrefix(pointer, "/security_features/") {
			t.Errorf("%s is set, but the roster has no scanning block", pointer)
		}
	}
}

func TestParseRefusesBadVCS(t *testing.T) {
	cases := map[string]struct{ from, to, want string }{
		"enforcement":    {`"enforcement": "active"`, `"enforcement": "on"`, `enforcement "on" has no entry in terms.vcs_enforcements`},
		"rule":           {`"signatures": {}`, `"commit_signing": {}`, `rule "commit_signing" has no entry in terms.vcs_rules`},
		"approvals":      {`"status_checks": {"checks": ["ci"]}`, `"status_checks": {"checks": ["ci"], "approvals": 1}`, `only a pull_request or approvals rule has them`},
		"no approvals":   {`"approvals": 1`, `"approvals": -1`, `approvals are 0 or more`},
		"checks":         {`"pull_request": {"approvals": 1}`, `"pull_request": {"approvals": 1, "checks": ["ci"]}`, `only a status_checks rule has checks`},
		"organization":   {`"organization": "acme",`, ``, `names no organization`},
		"term":           {`"linear_history": "other"`, `"linear_history": "history"`, `terms.vcs_rules maps "linear_history" to "history"`},
		"enforced terms": {`"evaluate": "report_only"`, `"evaluate": "audit"`, `terms.vcs_enforcements maps "evaluate" to "audit"`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			changed := strings.Replace(githubOrg, tc.from, tc.to, 1)
			if changed == githubOrg {
				t.Fatalf("%q is not in the roster", tc.from)
			}
			_, err := Parse([]byte(changed))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Parse() error = %v, want one containing %q", err, tc.want)
			}
		})
	}
}

func TestVCSExtrasAndClone(t *testing.T) {
	r, err := Parse([]byte(githubOrg))
	if err != nil {
		t.Fatal(err)
	}
	var archived bool
	if ok, err := r.VCS.Repositories[2].Extra.Get("archived", &archived); !ok || err != nil || !archived {
		t.Fatalf("archived = %t, %t, %v", archived, ok, err)
	}
	c := r.Clone()
	c.VCS.Repositories[0].Protections[0].Rules[0].Approvals = 5
	c.VCS.ExcludePatterns[0] = "*"
	if r.VCS.Repositories[0].Protections[0].Rules[0].Approvals != 1 || r.VCS.ExcludePatterns[0] != "sandbox-*" {
		t.Error("changing the clone changed the roster")
	}
}
