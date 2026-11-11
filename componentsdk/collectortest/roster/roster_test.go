package roster

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// tenant has three enabled members, one of them a Global Administrator
// with a security key, a guest Security Administrator, a disabled member,
// and an MFA policy for everyone but the break-glass account.
const tenant = `{
  "version": 1,
  "vendor": "test",
  "tenant": {"domain": "example.test"},
  "accounts": {
    "breakglass": {"kind": "member", "enabled": true, "roles": ["Global Administrator"], "mfa": "fido2SecurityKey", "signed_in_days_ago": 90},
    "alice": {"kind": "member", "enabled": true, "mfa": ["email", "mobilePhone"], "signed_in_days_ago": 91, "upn": "alice@example.test"},
    "bob": {"kind": "member", "enabled": true},
    "guest": {"kind": "guest", "enabled": true, "roles": ["Security Administrator"], "mfa": "mobilePhone"},
    "gone": {"kind": "member", "enabled": false, "roles": ["Global Administrator"]}
  },
  "sign_in_policies": {
    "mfa": {"state": "enabled", "include": "all", "exclude": {"accounts": ["breakglass"]}, "requires": "mfa"},
    "risky": {"state": "enabled", "include": "all", "requires": "mfa", "conditions": ["sign_in_risk"]}
  },
  "apps": {
    "saml": {"sso_mode": "saml"},
    "daemon": {},
    "off": {"enabled": false, "sso_mode": "saml"}
  },
  "terms": {
    "account_kinds": {"member": "member", "guest": "guest"},
    "mfa_methods": {"email": "none", "mobilePhone": "mfa", "fido2SecurityKey": "phishing_resistant"},
    "roles": {"Global Administrator": "super_admin", "Security Administrator": "admin"},
    "policy_states": {"enabled": "enforced"},
    "requirements": {"mfa": "mfa"},
    "sso_modes": {"saml": "sso"}
  },
  "unsettled": {"bob": ["mfa"]}
}`

func TestDeriveFollowsTheSchemaDefinitions(t *testing.T) {
	r, err := Parse([]byte(tenant))
	if err != nil {
		t.Fatal(err)
	}
	values, err := Derive(r)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"/user_security/users_present":                                true,
		"/user_security/user_count":                                   3,
		"/user_security/mfa_user_count":                               2,
		"/user_security/phishing_resistant_user_count":                1,
		"/user_security/mfa_coverage_pct":                             66,
		"/user_security/mfa_phishing_resistant_pct":                   33,
		"/user_security/inactive_user_count":                          2,
		"/user_security/inactive_pct":                                 67,
		"/app_security/app_count":                                     2,
		"/app_security/sso_coverage_pct":                              50,
		"/privileged_access/privileged_users_count":                   2,
		"/privileged_access/super_admin_count":                        1,
		"/privileged_access/privileged_mfa_coverage_pct":              100,
		"/privileged_access/privileged_phishing_resistant_pct":        50,
		"/privileged_access/standing_privileged_users_present":        true,
		"/lifecycle/account_count":                                    5,
		"/lifecycle/suspended_pct":                                    20,
		"/policy/mfa_required":                                        true,
		"/policy/mfa_required_user_count":                             2,
		"/policy/mfa_required_coverage_pct":                           66,
		"/policy/legacy_auth_blocked":                                 false,
		"/policy/phishing_resistant_required_for_privileged":          false,
		"/device_access/managed_device_required_for_admins":           false,
		"/privileged_access/privileged_phishing_resistant_user_count": 1,
	}
	for pointer, w := range want {
		if got, ok := values[IDPPosture][pointer]; !ok || got != w {
			t.Errorf("%s = %v (set %t), want %v", pointer, got, ok, w)
		}
	}
	if _, ok := values[IDPPosture]["/lifecycle/archived_pct"]; ok {
		t.Error("archived_pct is set, but the roster says nothing of archived accounts")
	}
}

func TestPercentageOverNoOneIsNull(t *testing.T) {
	r, err := Parse([]byte(tenant))
	if err != nil {
		t.Fatal(err)
	}
	r.Apps = nil
	values, err := Derive(r)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := values[IDPPosture]["/app_security/sso_coverage_pct"]; !ok || got != nil {
		t.Fatalf("sso_coverage_pct = %v (set %t), want null", got, ok)
	}
	if got := values[IDPPosture]["/app_security/apps_present"]; got != false {
		t.Fatalf("apps_present = %v, want false", got)
	}
}

func TestParseRefusesUnmappedTerms(t *testing.T) {
	cases := map[string]struct{ from, to, want string }{
		"kind":   {`"kind": "member", "enabled": true}`, `"kind": "service", "enabled": true}`, `kind "service" has no entry in terms.account_kinds`},
		"method": {`"mfa": "fido2SecurityKey"`, `"mfa": "smartCard"`, `mfa "smartCard" has no entry in terms.mfa_methods`},
		"role":   {`["Security Administrator"]`, `["Helpdesk Administrator"]`, `role "Helpdesk Administrator" has no entry in terms.roles`},
		"state":  {`"state": "enabled", "include": "all", "exclude"`, `"state": "enabledForReportingButNotEnforced", "include": "all", "exclude"`, `has no entry in terms.policy_states`},
		"term":   {`"saml": "sso"}`, `"saml": "federated"}`, `maps "saml" to "federated"`},
		"key":    {`{"accounts": ["breakglass"]}`, `{"accounts": ["nobody"]}`, `account nobody is not in the roster`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			changed := strings.Replace(tenant, tc.from, tc.to, 1)
			if changed == tenant {
				t.Fatalf("%q is not in the roster", tc.from)
			}
			_, err := Parse([]byte(changed))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Parse() error = %v, want one containing %q", err, tc.want)
			}
		})
	}
}

func TestExtrasStayWithTheirEntries(t *testing.T) {
	r, err := Parse([]byte(tenant))
	if err != nil {
		t.Fatal(err)
	}
	alice, _ := r.Account("alice")
	var upn string
	if ok, err := alice.Extra.Get("upn", &upn); !ok || err != nil || upn != "alice@example.test" {
		t.Fatalf("upn = %q, %t, %v", upn, ok, err)
	}
	var tenantExtra struct{ Domain string }
	if ok, err := r.Extra.Get("tenant", &tenantExtra); !ok || err != nil || tenantExtra.Domain != "example.test" {
		t.Fatalf("tenant = %+v, %t, %v", tenantExtra, ok, err)
	}
}

func TestSettleTakesUnsettledAttributesBothWays(t *testing.T) {
	r, err := Parse([]byte(tenant))
	if err != nil {
		t.Fatal(err)
	}
	realizations, err := r.Realizations()
	if err != nil {
		t.Fatal(err)
	}
	if len(realizations) != 2 || realizations[0].Name != "" || realizations[1].Name != "bob.mfa=mfa" {
		t.Fatalf("realizations = %+v", realizations)
	}
	settled, err := Settle(r)
	if err != nil {
		t.Fatal(err)
	}
	idp := settled[IDPPosture]
	if e := idp["/user_security/mfa_user_count"]; !e.Range || e.Min != 2 || e.Max != 3 {
		t.Errorf("mfa_user_count = %s, want {min: 2, max: 3}", e)
	}
	if e := idp["/user_security/user_count"]; e.Range || e.Exact != 3 {
		t.Errorf("user_count = %s, want 3", e)
	}
	if !idp["/user_security/mfa_coverage_pct"].Holds(float64(100)) || idp["/user_security/mfa_coverage_pct"].Holds(float64(50)) {
		t.Errorf("mfa_coverage_pct = %s, want 66 to 100", idp["/user_security/mfa_coverage_pct"])
	}
}

func TestPolicyScopeAndGrantOperators(t *testing.T) {
	r, err := Parse([]byte(tenant))
	if err != nil {
		t.Fatal(err)
	}
	r.Terms.Requirements = map[string]string{"mfa": RequiresMFA, "compliantDevice": RequiresManagedDevice, "termsOfUse": RequiresOther}
	cases := []struct {
		name       string
		change     func(*Policy)
		mfaUsers   int
		mfaPolicy  bool
		deviceAll  bool
		wantChange string
	}{
		{"all of mfa and a device", func(p *Policy) { p.Requires = []string{"mfa", "compliantDevice"} }, 2, true, true, ""},
		{"mfa or a device", func(p *Policy) { p.Requires, p.RequireAny = []string{"mfa", "compliantDevice"}, true }, 0, false, false, ""},
		{"mfa or terms of use", func(p *Policy) { p.Requires, p.RequireAny = []string{"mfa", "termsOfUse"}, true }, 0, false, false, ""},
		{"every app but one", func(p *Policy) { p.ExcludeApps = []string{"Office365"} }, 0, false, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := r.Clone()
			tc.change(&c.Policies[0])
			if err := c.Validate(); err != nil {
				t.Fatal(err)
			}
			values, err := Derive(c)
			if err != nil {
				t.Fatal(err)
			}
			idp := values[IDPPosture]
			if idp["/policy/mfa_required_user_count"] != tc.mfaUsers || idp["/policy/mfa_required"] != tc.mfaPolicy || idp["/device_access/managed_device_required"] != tc.deviceAll {
				t.Errorf("mfa_required_user_count %v, mfa_required %v, managed_device_required %v", idp["/policy/mfa_required_user_count"], idp["/policy/mfa_required"], idp["/device_access/managed_device_required"])
			}
			if len(r.Policies[0].Requires) != 1 || len(r.Policies[0].ExcludeApps) != 0 {
				t.Error("changing the clone changed the roster")
			}
		})
	}
	if _, err := Parse([]byte(strings.Replace(tenant, `"requires": "mfa"}`, `"requires": {"all": ["mfa"]}}`, 1))); err == nil || !strings.Contains(err.Error(), `{"any": [...]}`) {
		t.Errorf("Parse() error = %v, want one about the requires forms", err)
	}
}

func TestPairwiseCoversEveryPair(t *testing.T) {
	values := func(n int) []Value {
		out := make([]Value, n)
		for i := range out {
			out[i] = Value{Name: fmt.Sprint(i)}
		}
		return out
	}
	axes := []Axis{{"a", values(4)}, {"b", values(3)}, {"c", values(5)}, {"d", values(2)}, {"e", values(4)}}
	rows := Pairwise(axes)
	for i := range axes {
		for j := i + 1; j < len(axes); j++ {
			for a := range axes[i].Values {
				for b := range axes[j].Values {
					if !slices.ContainsFunc(rows, func(row Row) bool { return row[i] == a && row[j] == b }) {
						t.Errorf("no row has %s=%d with %s=%d", axes[i].Name, a, axes[j].Name, b)
					}
				}
			}
		}
	}
	if full := 4 * 3 * 5 * 2 * 4; len(rows) >= full/4 {
		t.Errorf("%d rows, a quarter or more of the %d combinations", len(rows), full)
	}
	if !slices.EqualFunc(rows, Pairwise(axes), slices.Equal[Row]) {
		t.Error("Pairwise gave different rows the second time")
	}
	if got, want := len(OneAtATime(axes)), 1+3+2+4+1+3; got != want {
		t.Errorf("OneAtATime gave %d rows, want %d", got, want)
	}
}

func TestBuildAndUnexplained(t *testing.T) {
	r, err := Parse([]byte(tenant))
	if err != nil {
		t.Fatal(err)
	}
	disable := func(key string) func(*Roster) {
		return func(r *Roster) {
			for i := range r.Accounts {
				if r.Accounts[i].Key == key {
					r.Accounts[i].Enabled = false
				}
			}
		}
	}
	axes := []Axis{
		{"alice", []Value{{Name: "enabled"}, {Name: "disabled", Change: disable("alice")}}},
		{"bob", []Value{{Name: "enabled"}, {Name: "disabled", Change: disable("bob")}}},
	}
	v, err := Build(r, axes, Row{1, 1})
	if err != nil {
		t.Fatal(err)
	}
	if v.Name != "alice=disabled,bob=disabled" {
		t.Errorf("Name = %q", v.Name)
	}
	if alice, _ := v.Roster.Account("alice"); alice.Enabled {
		t.Error("alice is still enabled")
	}
	if alice, _ := r.Account("alice"); !alice.Enabled {
		t.Error("Build changed the base roster")
	}
	alone := map[string][]string{"alice=disabled": {"/user_security/user_count"}}
	got := Unexplained(axes, Row{1, 1}, []string{"/user_security/user_count", "/policy/mfa_required"}, alone)
	if !slices.Equal(got, []string{"/policy/mfa_required"}) {
		t.Errorf("Unexplained = %v", got)
	}
	if _, err := Build(r, []Axis{{"x", []Value{{Name: "bad", Change: func(r *Roster) { r.Accounts[0].Kind = "robot" }}}}}, Row{0}); err == nil || !strings.HasPrefix(err.Error(), "base: ") {
		t.Errorf("Build() error = %v, want one naming the variant", err)
	}
}

// cloud has three security groups: one that denies SSH from anywhere
// before it allows it, one that allows a range holding SSH and RDP, and one
// with unordered rules. Two members hold a cloud role directly, a guest holds
// Owner through a group, and a disabled account holds Owner.
const cloud = `{
  "version": 1,
  "vendor": "test",
  "accounts": {
    "ann": {"kind": "member", "enabled": true, "cloud_roles": ["Owner"], "signed_in_days_ago": 3},
    "ben": {"kind": "member", "enabled": true, "cloud_roles": ["Reader"]},
    "gus": {"kind": "guest", "enabled": true, "signed_in_days_ago": 10},
    "old": {"kind": "member", "enabled": false, "cloud_roles": ["Owner"]}
  },
  "groups": {"ops": {"members": ["gus"], "cloud_roles": ["Owner"]}},
  "security_groups": {
    "shadowed": {"rules": {
      "deny": {"direction": "inbound", "access": "deny", "protocol": "*", "ports": ["*"], "sources": ["Internet"], "priority": 100},
      "ssh": {"direction": "inbound", "access": "allow", "protocol": "Tcp", "ports": ["22"], "sources": ["*"], "priority": 200}
    }},
    "range": {"rules": {
      "admin": {"direction": "inbound", "access": "allow", "protocol": "Tcp", "ports": ["20-3400"], "sources": ["0.0.0.0/0"], "priority": 100},
      "out": {"direction": "outbound", "access": "allow", "protocol": "*", "ports": ["*"], "sources": ["*"], "priority": 100}
    }},
    "unordered": {"rules": {
      "private": {"direction": "inbound", "access": "allow", "protocol": "Tcp", "ports": ["22"], "sources": ["10.0.0.0/8"]},
      "udp": {"direction": "inbound", "access": "allow", "protocol": "Udp", "ports": ["3389"], "sources": ["*"]}
    }}
  },
  "storage": {
    "cmk": {"key_source": "Microsoft.Keyvault", "anonymous_access": false},
    "open": {"key_source": "Microsoft.Storage", "anonymous_access": true}
  },
  "terms": {
    "account_kinds": {"member": "member", "guest": "guest"},
    "cloud_roles": {"Owner": "admin", "Reader": "none"},
    "protocols": {"Tcp": "tcp", "Udp": "udp", "*": "any"},
    "network_sources": {"*": "any", "Internet": "any", "0.0.0.0/0": "any", "10.0.0.0/8": "limited"},
    "key_sources": {"Microsoft.Storage": "provider_key", "Microsoft.Keyvault": "customer_key"}
  }
}`

// Policies combine. Between them, the enforced policies that apply to a user
// must require MFA for or block every sign-in to every app from every kind
// of client.
func TestDeriveCombinesPolicies(t *testing.T) {
	r, err := Parse([]byte(tenant))
	if err != nil {
		t.Fatal(err)
	}
	r.Terms.Blocks = map[string]string{"legacy": BlocksLegacyAuth}
	r.Terms.Conditions = map[string]map[string][]string{
		"browser_only": {PartClient: {ClientBrowser}},
		"modern_only":  {PartClient: {ClientBrowser, ClientApps}},
		"trusted":      {PartLocation: {"trusted"}},
		"untrusted":    {PartLocation: {"untrusted"}},
		"known_os":     {PartPlatform: {"android", "ios", "windows", "windows_phone", "macos", "linux"}},
	}
	mfa := r.Policies[0]
	withMFA := func(change func(*Policy)) Policy {
		p := mfa
		p.Key = fmt.Sprint(len(p.Conditions), p.Apps)
		change(&p)
		return p
	}
	block := Policy{Key: "block", State: "enabled", Include: Audience{All: true}, Blocks: "legacy"}
	cases := []struct {
		name     string
		policies []Policy
		want     bool
	}{
		{"one app, and every app but that one", []Policy{
			withMFA(func(p *Policy) { p.Apps = []string{"Office365"} }),
			withMFA(func(p *Policy) { p.ExcludeApps = []string{"Office365"} }),
		}, true},
		{"every app but one", []Policy{withMFA(func(p *Policy) { p.ExcludeApps = []string{"Office365"} })}, false},
		{"modern clients, legacy blocked", []Policy{withMFA(func(p *Policy) { p.Conditions = []string{"modern_only"} }), block}, true},
		{"modern clients, legacy allowed", []Policy{withMFA(func(p *Policy) { p.Conditions = []string{"modern_only"} })}, false},
		{"browsers only, legacy blocked", []Policy{withMFA(func(p *Policy) { p.Conditions = []string{"browser_only"} }), block}, false},
		{"trusted and untrusted locations", []Policy{
			withMFA(func(p *Policy) { p.Conditions = []string{"trusted"} }),
			withMFA(func(p *Policy) { p.Conditions = []string{"untrusted"} }),
		}, true},
		{"every known platform", []Policy{withMFA(func(p *Policy) { p.Conditions = []string{"known_os"} })}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := r.Clone()
			c.Policies = tc.policies
			if err := c.Validate(); err != nil {
				t.Fatal(err)
			}
			values, err := Derive(c)
			if err != nil {
				t.Fatal(err)
			}
			idp := values[IDPPosture]
			// Every user but the break-glass account the MFA policy
			// excludes is covered when the policies cover every sign-in.
			users := 0
			if tc.want {
				users = 2
			}
			if idp["/policy/mfa_required"] != tc.want || idp["/policy/mfa_required_user_count"] != users {
				t.Errorf("mfa_required %v, mfa_required_user_count %v, want %v and %d", idp["/policy/mfa_required"], idp["/policy/mfa_required_user_count"], tc.want, users)
			}
		})
	}
}

func TestDeriveCloudAndAccess(t *testing.T) {
	r, err := Parse([]byte(cloud))
	if err != nil {
		t.Fatal(err)
	}
	values, err := Derive(r)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]map[string]any{
		CloudPosture: {
			"/accounts/0/network/security_groups_present":       true,
			"/accounts/0/network/security_group_count":          3,
			"/accounts/0/network/ssh_open_security_group_count": 1,
			"/accounts/0/network/rdp_open_security_group_count": 1,
			"/accounts/0/network/ssh_open_to_world_pct":         34,
			"/accounts/0/storage/encryption_pct":                100,
			"/accounts/0/storage/public_access_blocked_pct":     50,
		},
		AccessPosture: {
			"/members/member_count":                      3,
			"/members/external_member_count":             1,
			"/members/inactive_member_count":             1,
			"/members/inactive_pct":                      34,
			"/admins/admin_count":                        2,
			"/admins/admin_share_pct":                    67,
			"/scopes/0/admins/admin_share_pct":           67,
			"/scopes/0/members/external_members_present": true,
		},
	}
	for schemaID, pointers := range want {
		for pointer, w := range pointers {
			if got, ok := values[schemaID][pointer]; !ok || got != w {
				t.Errorf("%s %s = %v (set %t), want %v", schemaID, pointer, got, ok, w)
			}
		}
	}
	if _, err := Parse([]byte(strings.Replace(cloud, `"ports": ["20-3400"]`, `"ports": ["3400-20"]`, 1))); err == nil || !strings.Contains(err.Error(), `port "3400-20"`) {
		t.Errorf("Parse() error = %v, want one about the port", err)
	}

	// A role on part of the subscription makes a member but not an admin.
	partial := r.Clone()
	partial.Accounts = append(partial.Accounts, Account{Key: "cal", Kind: "member", Enabled: true, PartialCloudRoles: []string{"Owner"}})
	if err := partial.Validate(); err != nil {
		t.Fatal(err)
	}
	if values, err = Derive(partial); err != nil {
		t.Fatal(err)
	}
	if got := values[AccessPosture]["/members/member_count"]; got != 4 {
		t.Errorf("member_count with a resource group Owner = %v, want 4", got)
	}
	if got := values[AccessPosture]["/admins/admin_count"]; got != 2 {
		t.Errorf("admin_count with a resource group Owner = %v, want 2", got)
	}
}
