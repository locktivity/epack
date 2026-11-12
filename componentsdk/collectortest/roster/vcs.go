package roster

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/locktivity/epack/componentsdk"
)

// Normalized branch rule kinds.
const (
	// BranchRulePullRequest makes every change reach the branch through a
	// pull request.
	BranchRulePullRequest = "pull_request"
	// BranchRuleApprovals asks for approving reviews on pull requests to the
	// branch, without stopping changes that reach it another way.
	BranchRuleApprovals     = "approvals"
	BranchRuleStatusChecks  = "status_checks"
	BranchRuleSignedCommits = "signed_commits"
	// BranchRuleOther is a rule that is none of the others, such as one
	// requiring a linear history.
	BranchRuleOther = "other"
)

// VCS is a version control organization's repositories and settings. In a
// roster file:
//
//	"vcs": {
//	  "organization": "...",
//	  "two_factor_requirement": true,
//	  "single_sign_on": true, "provisioning": [...],
//	  "allowed_sources": [...],
//	  "include_patterns": ["*"], "exclude_patterns": [...],
//	  "repositories": {"<name>": {"collector_access": true,
//	    "protections": {"<key>": {"enforcement": "...",
//	    "rules": {"<rule type>": {"approvals": 1, "checks": [...]}}}}}},
//	  "credentials": {"<key>": {"repositories": [...], "owner": "...",
//	    "app": "...", "active": true, "created_days_ago": 30,
//	    "expires_in_days": 60, "last_used_days_ago": 2,
//	    "allowed_sources": [...], "permissions": "..."}}
//	}
//
// and in the terms block, "vcs_enforcements" maps each enforcement to
// enforced, report_only or off, "vcs_rules" each rule type to
// pull_request, approvals, status_checks, signed_commits or other, and
// "vcs_credential_permissions" each credential's permissions to full,
// write or read.
//
// organization is the organization, group or workspace name.
// two_factor_requirement is whether the organization's setting, its own or
// one it takes from an enterprise or a parent group, makes every member use
// two-factor authentication. single_sign_on is whether sign-in through an
// identity provider, its own or one it takes the same way, is set up for
// it, and its provisioning features, mapped in
// terms.provisioning_features, are those of its SCIM provisioning.
// allowed_sources are the networks its IP allow list lets every credential
// in from, mapped in terms.network_sources, and left out when it has no
// allow list.
//
// A roster with a vcs block describes the one organization. Its accounts
// are the organization's members and outside collaborators, and the bot
// and service accounts it has, each of kind member, guest or service. An
// account's roles are its organization roles, such as owner, mapped in
// terms.roles, its logins the ways it can reach the organization, and
// signed_in_days_ago the age of its last sign-in or other recorded
// activity. The roster's apps are the apps installed on the organization,
// and enabled false marks a suspended one.
//
// Each credential is one machine credential, such as a token or a deploy
// key, read as the cloud block's are. Its repositories are those it
// belongs to, such as a deploy key's, and are left out for one that belongs
// to the organization, such as an organization access token or an
// approved personal access token.
//
// The repositories are every repository in the organization, archived and
// forked ones included, keyed by the name the patterns match.
// include_patterns and exclude_patterns are the scan's patterns. The scan
// covers each repository whose name matches an include pattern and no
// exclude pattern, where * matches any run of characters, ? any one
// character, and every other character itself. With no include patterns,
// it includes every repository. collector_access false marks a repository
// the collector's identity can't read, such as one a GitHub App isn't
// installed on, which the scan leaves out whatever the patterns say.
//
// A repository's protections are the branch protections and rulesets that
// apply to its default branch. A pull_request or approvals rule's approvals
// are the approving reviews a pull request needs. A status_checks rule's
// checks are the checks that must pass, such as a CI job or, for a vendor
// that runs one pipeline, the pipeline.
type VCS struct {
	Organization         string
	TwoFactorRequirement bool
	SingleSignOn         bool
	Provisioning         []string
	AllowedSources       []string
	IncludePatterns      []string
	ExcludePatterns      []string
	Repositories         []Repository
	Credentials          []MachineCredential
	Extra                Extra
}

// Repository is a repository and the protections on its default branch.
type Repository struct {
	Key string
	// Unreadable marks a repository the collector's identity can't read,
	// collector_access false in the file.
	Unreadable  bool
	Protections []BranchProtection
	Extra       Extra
}

// BranchProtection is a branch protection or ruleset that applies to a
// repository's default branch.
type BranchProtection struct {
	Key         string
	Enforcement string
	Rules       []BranchRule
	Extra       Extra
}

// BranchRule is one rule of a branch protection.
type BranchRule struct {
	// Type is the vendor's rule type, the rule's key in the file.
	Type      string
	Approvals int
	Checks    []string
	Extra     Extra
}

// VCSTerms maps the vendor terms a roster's vcs block uses to normalized
// ones.
type VCSTerms struct {
	// VCSEnforcements maps a protection's enforcement to enforced,
	// report_only or off.
	VCSEnforcements map[string]string `json:"vcs_enforcements"`
	// VCSRules maps a rule type to a BranchRule kind.
	VCSRules map[string]string `json:"vcs_rules"`
	// VCSCredentialPermissions maps a credential's permissions to full,
	// write or read.
	VCSCredentialPermissions map[string]string `json:"vcs_credential_permissions"`
}

var vcsDomain = domain{
	key: "vcs",
	parse: func(r *Roster, raw json.RawMessage) error {
		g, err := parseVCS(raw)
		if err != nil {
			return err
		}
		r.VCS = g
		return nil
	},
	validate: validateVCS,
	clone: func(c, r *Roster) {
		if r.VCS != nil {
			c.VCS = r.VCS.clone()
		}
	},
	derive:     deriveVCS,
	notDerived: map[string]map[string]string{VCSPosture: {}},
}

func parseVCS(raw json.RawMessage) (*VCS, error) {
	var b struct {
		Organization   string                     `json:"organization"`
		TwoFactor      bool                       `json:"two_factor_requirement"`
		SingleSignOn   bool                       `json:"single_sign_on"`
		Provisioning   oneOrMore                  `json:"provisioning"`
		AllowedSources []string                   `json:"allowed_sources"`
		Include        []string                   `json:"include_patterns"`
		Exclude        []string                   `json:"exclude_patterns"`
		Repositories   map[string]json.RawMessage `json:"repositories"`
		Credentials    map[string]json.RawMessage `json:"credentials"`
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, err
	}
	g := &VCS{
		Organization: b.Organization, TwoFactorRequirement: b.TwoFactor, SingleSignOn: b.SingleSignOn, Provisioning: b.Provisioning,
		AllowedSources: b.AllowedSources, IncludePatterns: b.Include, ExcludePatterns: b.Exclude,
	}
	var err error
	if g.Extra, err = extra(raw, "organization", "two_factor_requirement", "single_sign_on", "provisioning", "allowed_sources",
		"include_patterns", "exclude_patterns", "repositories", "credentials"); err != nil {
		return nil, err
	}
	if g.Credentials, err = parseCredentials(b.Credentials, "repositories"); err != nil {
		return nil, err
	}
	for _, name := range sortedKeys(b.Repositories) {
		repo, err := parseRepository(name, b.Repositories[name])
		if err != nil {
			return nil, err
		}
		g.Repositories = append(g.Repositories, repo)
	}
	return g, nil
}

func parseRepository(name string, raw json.RawMessage) (Repository, error) {
	var repo struct {
		CollectorAccess *bool                      `json:"collector_access"`
		Protections     map[string]json.RawMessage `json:"protections"`
	}
	if err := json.Unmarshal(raw, &repo); err != nil {
		return Repository{}, fmt.Errorf("repository %s: %w", name, err)
	}
	out := Repository{Key: name, Unreadable: repo.CollectorAccess != nil && !*repo.CollectorAccess}
	var err error
	if out.Extra, err = extra(raw, "collector_access", "protections"); err != nil {
		return Repository{}, fmt.Errorf("repository %s: %w", name, err)
	}
	for _, pk := range sortedKeys(repo.Protections) {
		what := "repository " + name + " protection " + pk
		var p struct {
			Enforcement string                     `json:"enforcement"`
			Rules       map[string]json.RawMessage `json:"rules"`
		}
		if err := json.Unmarshal(repo.Protections[pk], &p); err != nil {
			return Repository{}, fmt.Errorf("%s: %w", what, err)
		}
		pe, err := extra(repo.Protections[pk], "enforcement", "rules")
		if err != nil {
			return Repository{}, fmt.Errorf("%s: %w", what, err)
		}
		protection := BranchProtection{Key: pk, Enforcement: p.Enforcement, Extra: pe}
		for _, typ := range sortedKeys(p.Rules) {
			var rule struct {
				Approvals int      `json:"approvals"`
				Checks    []string `json:"checks"`
			}
			if err := json.Unmarshal(p.Rules[typ], &rule); err != nil {
				return Repository{}, fmt.Errorf("%s rule %s: %w", what, typ, err)
			}
			re, err := extra(p.Rules[typ], "approvals", "checks")
			if err != nil {
				return Repository{}, fmt.Errorf("%s rule %s: %w", what, typ, err)
			}
			protection.Rules = append(protection.Rules, BranchRule{Type: typ, Approvals: rule.Approvals, Checks: rule.Checks, Extra: re})
		}
		out.Protections = append(out.Protections, protection)
	}
	return out, nil
}

func validateVCS(r *Roster) error {
	t := r.Terms
	for name, m := range map[string]struct {
		terms map[string]string
		allow []string
	}{
		"vcs_enforcements":           {t.VCSEnforcements, []string{StateEnforced, StateReportOnly, StateOff}},
		"vcs_rules":                  {t.VCSRules, []string{BranchRulePullRequest, BranchRuleApprovals, BranchRuleStatusChecks, BranchRuleSignedCommits, BranchRuleOther}},
		"vcs_credential_permissions": {t.VCSCredentialPermissions, []string{PermissionsFull, PermissionsWrite, PermissionsRead}},
	} {
		for _, vendor := range sortedKeys(m.terms) {
			if !slices.Contains(m.allow, m.terms[vendor]) {
				return fmt.Errorf("terms.%s maps %q to %q, which is none of %v", name, vendor, m.terms[vendor], m.allow)
			}
		}
	}
	g := r.VCS
	if g == nil {
		return nil
	}
	if g.Organization == "" {
		return fmt.Errorf("the block names no organization")
	}
	if err := mapped(t.ProvisioningFeatures, "provisioning_features", "provisioning", g.Provisioning...); err != nil {
		return err
	}
	if err := mapped(t.NetworkSources, "network_sources", "allowed source", g.AllowedSources...); err != nil {
		return err
	}
	accounts, apps, repositories := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, a := range r.Accounts {
		accounts[a.Key] = true
	}
	for _, a := range r.Apps {
		apps[a.Key] = true
	}
	for _, repo := range g.Repositories {
		repositories[repo.Key] = true
	}
	for _, m := range g.Credentials {
		if err := known(repositories, "credential "+m.Key+" repository", m.Repositories...); err != nil {
			return err
		}
		if err := r.validateCredential(m, accounts, apps, t.VCSCredentialPermissions, "vcs_credential_permissions"); err != nil {
			return err
		}
	}
	for _, repo := range g.Repositories {
		for _, p := range repo.Protections {
			what := "repository " + repo.Key + " protection " + p.Key
			if err := mapped(t.VCSEnforcements, "vcs_enforcements", what+" enforcement", p.Enforcement); err != nil {
				return err
			}
			for _, rule := range p.Rules {
				if err := mapped(t.VCSRules, "vcs_rules", what+" rule", rule.Type); err != nil {
					return err
				}
				kind := t.VCSRules[rule.Type]
				if rule.Approvals < 0 || (rule.Approvals > 0 && kind != BranchRulePullRequest && kind != BranchRuleApprovals) {
					return fmt.Errorf("%s rule %s: approvals are 0 or more, and only a %s or %s rule has them", what, rule.Type, BranchRulePullRequest, BranchRuleApprovals)
				}
				if len(rule.Checks) > 0 && kind != BranchRuleStatusChecks {
					return fmt.Errorf("%s rule %s: only a %s rule has checks", what, rule.Type, BranchRuleStatusChecks)
				}
			}
		}
	}
	return nil
}

func (g *VCS) clone() *VCS {
	c := *g
	c.Provisioning, c.AllowedSources = slices.Clone(g.Provisioning), slices.Clone(g.AllowedSources)
	c.IncludePatterns, c.ExcludePatterns = slices.Clone(g.IncludePatterns), slices.Clone(g.ExcludePatterns)
	c.Credentials = cloneCredentials(g.Credentials)
	c.Repositories = slices.Clone(g.Repositories)
	for i := range c.Repositories {
		repo := &c.Repositories[i]
		repo.Protections = slices.Clone(repo.Protections)
		for j := range repo.Protections {
			p := &repo.Protections[j]
			p.Rules = slices.Clone(p.Rules)
			for k := range p.Rules {
				p.Rules[k].Checks = slices.Clone(p.Rules[k].Checks)
			}
		}
	}
	return &c
}

// scans reports whether the scan covers the repository called name: the
// collector can read it, and it matches an include pattern, or there are
// none, and no exclude pattern.
func (g *VCS) scans(name string) bool {
	if slices.ContainsFunc(g.Repositories, func(repo Repository) bool { return repo.Key == name && repo.Unreadable }) {
		return false
	}
	matches := func(patterns []string) bool {
		return slices.ContainsFunc(patterns, func(p string) bool { return repoPattern(p).MatchString(name) })
	}
	return (len(g.IncludePatterns) == 0 || matches(g.IncludePatterns)) && !matches(g.ExcludePatterns)
}

// repoPattern compiles a scan pattern, where * matches any run of
// characters, ? any one character, and every other character itself.
func repoPattern(pattern string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString(`^(?s:`)
	for _, c := range pattern {
		switch c {
		case '*':
			b.WriteString(`.*`)
		case '?':
			b.WriteString(`.`)
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString(`)$`)
	return regexp.MustCompile(b.String())
}

// branchRequires reports whether an enforced protection on repo's default
// branch has a rule that holds, given the rule's normalized kind.
func (r *Roster) branchRequires(repo Repository, holds func(kind string, rule BranchRule) bool) bool {
	for _, p := range repo.Protections {
		if r.Terms.VCSEnforcements[p.Enforcement] != StateEnforced {
			continue
		}
		if slices.ContainsFunc(p.Rules, func(rule BranchRule) bool { return holds(r.Terms.VCSRules[rule.Type], rule) }) {
			return true
		}
	}
	return false
}

// deriveVCS gives vcs-posture's values. The repositories are every one in
// the organization, and the scan covers those the collector can read that
// its patterns select. A
// scanned repository's default branch requires what an enforced protection
// on it requires, whatever exceptions the protection makes, such as for
// admins: pull requests by a pull_request rule, an approving review by a
// pull_request or approvals rule asking for at least one, status checks by
// a status_checks rule naming at least one check, and signed commits by a
// signed_commits rule. Each security feature percentage is the coverage of
// the scanning block's one scanner of its category, as vuln-scanning gives
// it.
func deriveVCS(r *Roster, out Values) error {
	g := r.VCS
	if g == nil {
		return nil
	}
	v := out[VCSPosture]
	if v == nil {
		v = map[string]any{}
		out[VCSPosture] = v
	}
	var scanned []Repository
	for _, repo := range g.Repositories {
		if g.scans(repo.Key) {
			scanned = append(scanned, repo)
		}
	}
	v["/organization"] = g.Organization
	v["/org_security/two_factor_required"] = g.TwoFactorRequirement
	v["/repository_count"] = len(g.Repositories)
	v["/scanned_repository_count"] = len(scanned)

	requiring := func(holds func(kind string, rule BranchRule) bool) int {
		return count(scanned, func(repo Repository) bool { return r.branchRequires(repo, holds) })
	}
	const bp = "/branch_protection/"
	v[bp+"pr_required_repository_count"] = requiring(func(kind string, _ BranchRule) bool { return kind == BranchRulePullRequest })
	v[bp+"approving_reviews_repository_count"] = requiring(func(kind string, rule BranchRule) bool {
		return (kind == BranchRulePullRequest || kind == BranchRuleApprovals) && rule.Approvals >= 1
	})
	v[bp+"status_checks_repository_count"] = requiring(func(kind string, rule BranchRule) bool {
		return kind == BranchRuleStatusChecks && len(rule.Checks) > 0
	})
	v[bp+"signed_commits_repository_count"] = requiring(func(kind string, _ BranchRule) bool { return kind == BranchRuleSignedCommits })

	for field, category := range map[string]string{
		"vuln_alerts_pct":     VulnDependencies,
		"secret_scanning_pct": VulnSecrets,
		"code_scanning_pct":   VulnCode,
	} {
		covered, resources, ok := r.scanCoverage(category)
		if !ok {
			continue
		}
		if p := componentsdk.Percent(covered, resources, componentsdk.RoundDown); p != nil {
			v["/security_features/"+field] = *p
		} else {
			v["/security_features/"+field] = nil
		}
	}
	return nil
}
