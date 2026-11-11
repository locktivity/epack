package roster

import "testing"

// signInTenant has two members, one in a group, and policies scoped by
// condition, app, and audience.
const signInTenant = `{
  "version": 1,
  "vendor": "test",
  "accounts": {
    "ann": {"kind": "member", "enabled": true, "roles": ["Global Administrator"]},
    "ben": {"kind": "member", "enabled": true}
  },
  "groups": {"ops": {"members": ["ben"]}},
  "sign_in_policies": {
    "everyone": {"state": "enabled", "include": "all", "requires": "mfa"},
    "browser": {"state": "report", "include": "all", "conditions": ["browser_only"], "requires": "mfa"},
    "modern": {"state": "enabled", "include": "all", "conditions": ["modern_only"], "requires": "mfa"},
    "legacy": {"state": "enabled", "include": "all", "exclude": {"accounts": ["ann"]}, "blocks": "legacy_auth"},
    "other_only": {"state": "enabled", "include": "all", "conditions": ["other_only"], "blocks": "legacy_auth"},
    "office": {"state": "enabled", "include": "all", "apps": ["Office365"], "requires": "mfa"},
    "not_saml": {"state": "enabled", "include": "all", "exclude_apps": ["saml"], "requires": "mfa"},
    "admins": {"state": "enabled", "include": {"roles": ["Global Administrator"]}, "requires": "mfa"},
    "group": {"state": "enabled", "include": {"groups": ["ops"]}, "requires": "mfa"},
    "untrusted": {"state": "enabled", "include": "all", "conditions": ["untrusted"], "requires": "mfa"},
    "filtered": {"state": "enabled", "include": "all", "requires": "mfa", "conditions": ["device_filter"]}
  },
  "terms": {
    "account_kinds": {"member": "member"},
    "roles": {"Global Administrator": "super_admin"},
    "policy_states": {"enabled": "enforced", "report": "report_only"},
    "requirements": {"mfa": "mfa"},
    "blocks": {"legacy_auth": "legacy_auth"},
    "conditions": {
      "browser_only": {"client": ["browser"]},
      "modern_only": {"client": ["browser", "apps"]},
      "other_only": {"client": ["legacy"]},
      "untrusted": {"location": ["untrusted"]}
    }
  }
}`

func TestAppliesReadsAudienceAppsAndConditions(t *testing.T) {
	r, err := Parse([]byte(signInTenant))
	if err != nil {
		t.Fatal(err)
	}
	exchange := []string{"exchange", "Office365"}
	saml := []string{"saml"}
	client := func(c string) map[string]string { return map[string]string{PartClient: c} }
	for _, tc := range []struct {
		policy, account string
		apps            []string
		parts           map[string]string
		want            bool
	}{
		{"everyone", "ann", saml, client(ClientLegacy), true},
		{"browser", "ben", saml, client(ClientBrowser), true},
		{"browser", "ben", saml, client(ClientApps), false},
		{"modern", "ben", saml, client(ClientApps), true},
		{"modern", "ben", saml, client(ClientMailSync), false},
		{"legacy", "ben", saml, client(ClientMailSync), true},
		{"legacy", "ben", saml, client(ClientBrowser), false},
		{"legacy", "ann", saml, client(ClientLegacy), false},
		{"other_only", "ben", saml, client(ClientLegacy), true},
		{"other_only", "ben", saml, client(ClientMailSync), false},
		{"office", "ben", exchange, client(ClientBrowser), true},
		{"office", "ben", saml, client(ClientBrowser), false},
		{"not_saml", "ben", exchange, client(ClientBrowser), true},
		{"not_saml", "ben", saml, client(ClientBrowser), false},
		{"admins", "ann", saml, client(ClientBrowser), true},
		{"admins", "ben", saml, client(ClientBrowser), false},
		{"group", "ben", saml, client(ClientBrowser), true},
		{"group", "ann", saml, client(ClientBrowser), false},
		{"untrusted", "ben", saml, map[string]string{PartClient: ClientBrowser, PartLocation: "untrusted"}, true},
		{"untrusted", "ben", saml, client(ClientBrowser), false},
		{"filtered", "ben", saml, client(ClientBrowser), false},
	} {
		var p Policy
		for _, q := range r.Policies {
			if q.Key == tc.policy {
				p = q
			}
		}
		a, _ := r.Account(tc.account)
		if got := r.Applies(p, a, SignIn{Apps: tc.apps, Parts: tc.parts}); got != tc.want {
			t.Errorf("Applies(%s, %s, %v %v) = %v, want %v", tc.policy, tc.account, tc.apps, tc.parts, got, tc.want)
		}
	}
}

func TestOutcomeCountsEnforcedPolicies(t *testing.T) {
	r, err := Parse([]byte(signInTenant))
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]Policy{}
	for _, p := range r.Policies {
		byKey[p.Key] = p
	}
	for _, tc := range []struct {
		policies []string
		want     string
	}{
		{nil, OutcomeNone},
		{[]string{"browser"}, OutcomeNone},
		{[]string{"browser", "modern"}, OutcomeMFA},
		{[]string{"modern", "legacy"}, OutcomeBlocked},
	} {
		var ps []Policy
		for _, k := range tc.policies {
			ps = append(ps, byKey[k])
		}
		if got := r.Outcome(ps); got != tc.want {
			t.Errorf("Outcome(%v) = %s, want %s", tc.policies, got, tc.want)
		}
	}
}
