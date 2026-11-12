package roster

import (
	"os"
	"strings"
	"testing"
)

// directoryTenant has three enabled members, one locked out with a short
// weak password, a guest and a service account that are locked out or weak
// too, a disabled member, an archived one, and an account local to a cloud
// account. Its apps provision in different ways and come from different
// publishers, and its policies set session limits.
const directoryTenant = `{
  "version": 1,
  "vendor": "test",
  "directory": {"domain": "example.test", "password_policy": {"min_length": 12}},
  "accounts": {
    "ann": {"kind": "member", "enabled": true, "state": "LOCKED_OUT", "password_strength": "WEAK", "password_length": 8},
    "ben": {"kind": "member", "enabled": true, "state": "ACTIVE", "password_strength": "STRONG", "password_length": 14},
    "cal": {"kind": "member", "enabled": true},
    "gus": {"kind": "guest", "enabled": true, "state": "LOCKED_OUT", "password_strength": "WEAK", "password_length": 4},
    "svc": {"kind": "service", "enabled": true, "roles": ["Global Administrator"], "password_strength": "WEAK", "password_length": 4},
    "off": {"kind": "member", "enabled": false, "state": "LOCKED_OUT"},
    "gone": {"kind": "member", "enabled": false, "state": "DELETED"},
    "iam": {"kind": "member", "enabled": true, "cloud_account": "prod", "state": "LOCKED_OUT", "password_length": 4}
  },
  "sign_in_policies": {
    "day": {"state": "on", "include": "all", "session_lifetime_minutes": 1440, "idle_timeout_minutes": 30},
    "admins": {"state": "on", "include": {"roles": ["Global Administrator"]}, "session_lifetime_minutes": 60, "idle_timeout_minutes": 90},
    "trial": {"state": "report", "include": "all", "session_lifetime_minutes": 10080, "idle_timeout_minutes": 600}
  },
  "apps": {
    "hr": {"publisher": "gallery", "provisioning": ["push_users", "deactivate_users"]},
    "chat": {"publisher": "gallery", "provisioning": "push_users"},
    "portal": {"publisher": "own"},
    "console": {"publisher": "vendor", "provisioning": "push_groups"},
    "old": {"enabled": false, "publisher": "gallery", "provisioning": ["push_users", "deactivate_users"]}
  },
  "cloud": {"accounts": {"prod": {"id": "1", "kind": "Account"}}},
  "terms": {
    "account_kinds": {"member": "member", "guest": "guest", "service": "service"},
    "roles": {"Global Administrator": "super_admin"},
    "policy_states": {"on": "enforced", "report": "report_only"},
    "account_states": {"ACTIVE": "other", "LOCKED_OUT": "locked_out", "DELETED": "archived"},
    "password_strengths": {"WEAK": "weak", "STRONG": "strong"},
    "app_publishers": {"gallery": "third_party", "own": "organization", "vendor": "provider"},
    "provisioning_features": {"push_users": "create", "deactivate_users": "deactivate", "push_groups": "other"},
    "cloud_account_kinds": {"Account": "account"}
  }
}`

func deriveIDP(t *testing.T, r *Roster) map[string]any {
	t.Helper()
	values, err := Derive(r)
	if err != nil {
		t.Fatal(err)
	}
	return values[IDPPosture]
}

func checkPointers(t *testing.T, got map[string]any, want map[string]any) {
	t.Helper()
	for _, pointer := range sortedKeys(want) {
		if v, ok := got[pointer]; !ok || !sameValue(v, want[pointer]) {
			t.Errorf("%s = %v (set %t), want %v", pointer, v, ok, want[pointer])
		}
	}
}

func checkUnset(t *testing.T, got map[string]any, pointers ...string) {
	t.Helper()
	for _, pointer := range pointers {
		if v, ok := got[pointer]; ok {
			t.Errorf("%s = %v, want it unset", pointer, v)
		}
	}
}

func parseDirectoryTenant(t *testing.T) *Roster {
	t.Helper()
	r, err := Parse([]byte(directoryTenant))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// Locked-out, weak-password and noncompliant users are users: enabled
// members of the directory, so guests, service accounts, disabled accounts
// and local cloud accounts don't count. A user with no password in the
// directory meets the password policy.
func TestDirectoryCountsUsersByStateAndPassword(t *testing.T) {
	r := parseDirectoryTenant(t)
	checkPointers(t, deriveIDP(t, r), map[string]any{
		"/org_domain":                                            "example.test",
		"/user_security/user_count":                              3,
		"/user_security/locked_out_user_count":                   1,
		"/user_security/locked_out_pct":                          34,
		"/user_security/weak_password_user_count":                1,
		"/user_security/weak_password_pct":                       34,
		"/user_security/password_policy_noncompliant_user_count": 1,
		"/user_security/password_policy_noncompliant_pct":        34,
	})

	r.Directory.PasswordPolicy = nil
	checkPointers(t, deriveIDP(t, r), map[string]any{"/user_security/password_policy_noncompliant_user_count": 0})
}

// An archived account counts among the accounts and as archived, not as
// suspended. An enabled one is refused.
func TestDirectoryCountsArchivedApartFromSuspended(t *testing.T) {
	r := parseDirectoryTenant(t)
	checkPointers(t, deriveIDP(t, r), map[string]any{
		"/lifecycle/account_count":           7,
		"/lifecycle/suspended_account_count": 1,
		"/lifecycle/archived_account_count":  1,
		"/lifecycle/archived_pct":            15,
	})
	changed := strings.Replace(directoryTenant, `"gone": {"kind": "member", "enabled": false`, `"gone": {"kind": "member", "enabled": true`, 1)
	if _, err := Parse([]byte(changed)); err == nil || !strings.Contains(err.Error(), "archived and enabled") {
		t.Errorf("Parse() error = %v, want one about an enabled archived account", err)
	}
}

// Only enabled apps count. Provisioning needs a feature that creates
// accounts, deprovisioning one that deactivates them, and an authorized
// third-party app a third-party publisher.
func TestDirectoryCountsAppProvisioningAndPublishers(t *testing.T) {
	r := parseDirectoryTenant(t)
	checkPointers(t, deriveIDP(t, r), map[string]any{
		"/app_security/app_count":                         4,
		"/app_security/provisioning_app_count":            2,
		"/app_security/provisioning_enabled_pct":          50,
		"/app_security/deprovisioning_app_count":          1,
		"/app_security/deprovisioning_enabled_pct":        25,
		"/app_security/authorized_third_party_apps_count": 2,
	})
}

// The session limits are the longest an enforced policy sets, and null when
// none sets one.
func TestDirectorySessionLimitsAreTheLongestEnforced(t *testing.T) {
	r := parseDirectoryTenant(t)
	checkPointers(t, deriveIDP(t, r), map[string]any{
		"/policy/session_lifetime_max_min": 1440,
		"/policy/idle_timeout_max_min":     90,
	})
	for i := range r.Policies {
		if r.Policies[i].Key != "trial" {
			r.Policies[i].SessionLifetimeMinutes, r.Policies[i].IdleTimeoutMinutes = nil, nil
		}
	}
	checkPointers(t, deriveIDP(t, r), map[string]any{
		"/policy/session_lifetime_max_min": nil,
		"/policy/idle_timeout_max_min":     nil,
	})
}

// A service account with an admin role is not a privileged user, and a
// local cloud account is not in the directory at all.
func TestDirectoryLeavesOutServiceAndLocalAccounts(t *testing.T) {
	r := parseDirectoryTenant(t)
	checkPointers(t, deriveIDP(t, r), map[string]any{
		"/privileged_access/privileged_users_count":   0,
		"/privileged_access/privileged_users_present": false,
	})
}

// Without a directory block, Derive gives none of the values it needs, and
// the rest stay as they were.
func TestWithoutADirectoryBlockNothingNewIsDerived(t *testing.T) {
	r := parseDirectoryTenant(t)
	r.Directory = nil
	idp := deriveIDP(t, r)
	checkUnset(t, idp, "/org_domain", "/user_security/locked_out_user_count", "/user_security/weak_password_user_count",
		"/user_security/password_policy_noncompliant_user_count", "/app_security/provisioning_app_count",
		"/app_security/deprovisioning_app_count", "/app_security/authorized_third_party_apps_count",
		"/lifecycle/archived_account_count", "/lifecycle/archived_pct", "/policy/session_lifetime_max_min", "/policy/idle_timeout_max_min")
	checkPointers(t, idp, map[string]any{"/user_security/user_count": 3, "/lifecycle/suspended_account_count": 1})

	old, err := Parse([]byte(tenant))
	if err != nil {
		t.Fatal(err)
	}
	for pointer := range deriveIDP(t, old) {
		if !strings.HasPrefix(pointer, "/user_security/") && !strings.HasPrefix(pointer, "/app_security/") &&
			!strings.HasPrefix(pointer, "/privileged_access/") && !strings.HasPrefix(pointer, "/lifecycle/") &&
			!strings.HasPrefix(pointer, "/policy/") && !strings.HasPrefix(pointer, "/device_access/") && pointer != "/schema_version" {
			t.Errorf("a roster without a directory block gives %s", pointer)
		}
	}
}

func TestParseRefusesBadDirectoryFacts(t *testing.T) {
	cases := map[string]struct{ from, to, want string }{
		"state":     {`"state": "ACTIVE"`, `"state": "RECOVERY"`, `state "RECOVERY" has no entry in terms.account_states`},
		"strength":  {`"password_strength": "STRONG"`, `"password_strength": "FAIR"`, `password_strength "FAIR" has no entry in terms.password_strengths`},
		"publisher": {`"publisher": "own"`, `"publisher": "unknown"`, `publisher "unknown" has no entry in terms.app_publishers`},
		"feature":   {`"provisioning": "push_users"`, `"provisioning": "sync_passwords"`, `provisioning "sync_passwords" has no entry in terms.provisioning_features`},
		"term":      {`"DELETED": "archived"`, `"DELETED": "deleted"`, `maps "DELETED" to "deleted"`},
		"domain":    {`"domain": "example.test", `, ``, `the directory has no domain`},
		"session":   {`"session_lifetime_minutes": 60`, `"session_lifetime_minutes": 0`, `session_lifetime_minutes is 0`},
		"key":       {`"cloud_account": "prod"`, `"cloud_account": "staging"`, `cloud account staging is not in the roster`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			changed := strings.Replace(directoryTenant, tc.from, tc.to, 1)
			if changed == directoryTenant {
				t.Fatalf("%q is not in the roster", tc.from)
			}
			if _, err := Parse([]byte(changed)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Parse() error = %v, want one containing %q", err, tc.want)
			}
		})
	}
}

// Another identity provider decides MFA for the accounts it signs in. With
// Carol signing in through one, the MFA values over users are left out and
// the admins' stay. With Helpdesk, an admin, the admins' go too.
func TestDeriveLeavesMFAOutForAccountsAnotherProviderSignsIn(t *testing.T) {
	raw, err := os.ReadFile("testdata/identity.roster.json")
	if err != nil {
		t.Fatal(err)
	}
	userMFA := []string{
		"/user_security/mfa_user_count", "/user_security/phishing_resistant_user_count",
		"/user_security/mfa_coverage_pct", "/user_security/mfa_phishing_resistant_pct",
		"/policy/mfa_required", "/policy/mfa_required_user_count", "/policy/mfa_required_coverage_pct",
	}
	adminMFA := []string{"/privileged_access/privileged_mfa_user_count", "/privileged_access/privileged_mfa_coverage_pct"}
	for name, tc := range map[string]struct {
		from, to    string
		adminsUnset bool
	}{
		"user":  {`"carol": {"kind": "user", "enabled": true,`, `"carol": {"kind": "user", "enabled": true, "signs_in_through": "partner-idp",`, false},
		"admin": {`"helpdesk": {"kind": "user", "enabled": true,`, `"helpdesk": {"kind": "user", "enabled": true, "signs_in_through": "partner-idp",`, true},
	} {
		t.Run(name, func(t *testing.T) {
			changed := strings.Replace(string(raw), tc.from, tc.to, 1)
			if changed == string(raw) {
				t.Fatalf("%q is not in the roster", tc.from)
			}
			r, err := Parse([]byte(changed))
			if err != nil {
				t.Fatal(err)
			}
			v := deriveSchema(t, r, IDPPosture)
			checkPointers(t, v, map[string]any{"/user_security/user_count": 5})
			checkUnset(t, v, userMFA...)
			if tc.adminsUnset {
				checkUnset(t, v, adminMFA...)
			} else if _, ok := v["/privileged_access/privileged_mfa_user_count"]; !ok {
				t.Error("/privileged_access/privileged_mfa_user_count is unset, want it given")
			}
		})
	}
}
