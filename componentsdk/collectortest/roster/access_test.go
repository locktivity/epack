package roster

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/outputcheck"
)

// awsOrg has two cloud accounts the collector reads and one it can't. Ana
// is an admin in prod and a reader in dev, Ben an admin in prod through a
// group who can also sign in with a password, and Gus a guest with a role
// on part of dev. Prod has a local IAM user, a disabled one, a service user
// and a root user with MFA. Dev has a root user without. The credentials
// cover each judgment, and dev's don't say when they were made.
const awsOrg = `{
  "version": 1,
  "vendor": "test",
  "accounts": {
    "ana": {"kind": "member", "enabled": true, "logins": "sso", "mfa": "totp", "signed_in_days_ago": 1,
      "cloud_access": {"prod": {"roles": ["Admin"]}, "dev": {"roles": ["Reader"]}}},
    "ben": {"kind": "member", "enabled": true, "logins": ["sso", "password"], "signed_in_days_ago": 200},
    "gus": {"kind": "guest", "enabled": true, "logins": "sso", "cloud_access": {"dev": {"partial_roles": ["Admin"]}}},
    "iam_user": {"kind": "member", "enabled": true, "cloud_account": "prod", "logins": "password", "mfa": "totp", "signed_in_days_ago": 2},
    "iam_old": {"kind": "member", "enabled": false, "cloud_account": "prod", "logins": "password", "cloud_roles": ["Admin"]},
    "robot": {"kind": "service", "enabled": true, "cloud_account": "prod", "cloud_roles": ["Admin"]},
    "prod_root": {"kind": "root", "enabled": true, "cloud_account": "prod", "logins": "password", "mfa": "totp"},
    "dev_root": {"kind": "root", "enabled": true, "cloud_account": "dev", "logins": "password"},
    "audit_root": {"kind": "root", "enabled": true, "cloud_account": "audit"}
  },
  "groups": {"ops": {"members": ["ben"], "cloud_access": {"prod": {"roles": ["Admin"]}}}},
  "apps": {
    "vendor_tool": {"publisher": "partner", "cloud_roles": ["Reader"]},
    "own_tool": {"publisher": "us", "cloud_roles": ["Admin"]},
    "idle": {"publisher": "partner"},
    "off": {"enabled": false, "publisher": "partner", "cloud_roles": ["Reader"]}
  },
  "cloud": {
    "system_type": "cloud",
    "accounts": {
      "prod": {"id": "111", "name": "Production", "kind": "Account", "identity_providers": {"idc": {"kind": "IdentityCenter"}},
        "local_mfa_enforced": true, "provisioning": ["create", "delete"]},
      "dev": {"id": "222", "kind": "Account", "identity_providers": {"idc": {"kind": "IdentityCenter"}, "okta": {"kind": "SAML"}},
        "local_mfa_enforced": true},
      "audit": {"id": "333", "kind": "Account", "collector_access": false}
    },
    "credentials": {
      "user_key": {"cloud_account": "prod", "owner": "iam_user", "created_days_ago": 120, "last_used_days_ago": 2, "permissions": "AdministratorAccess"},
      "robot_key": {"cloud_account": "prod", "owner": "robot", "created_days_ago": 10, "expires_in_days": 30, "last_used_days_ago": 1,
        "allowed_sources": ["10.0.0.0/8"], "permissions": "AdministratorAccess"},
      "robot_open": {"cloud_account": "prod", "owner": "robot", "created_days_ago": 10, "last_used_days_ago": 91,
        "allowed_sources": ["0.0.0.0/0"], "permissions": "AdministratorAccess"},
      "root_key": {"cloud_account": "prod", "owner": "prod_root", "created_days_ago": 91, "permissions": "AdministratorAccess"},
      "old_key": {"cloud_account": "prod", "owner": "iam_user", "active": false, "created_days_ago": 900, "permissions": "AdministratorAccess"},
      "reader": {"cloud_account": "dev", "app": "vendor_tool", "last_used_days_ago": 90, "permissions": "ReadOnly"}
    }
  },
  "terms": {
    "account_kinds": {"member": "member", "guest": "guest", "service": "service", "root": "root"},
    "mfa_methods": {"totp": "mfa"},
    "login_methods": {"sso": "sso", "password": "local"},
    "cloud_roles": {"Admin": "admin", "Reader": "none"},
    "network_sources": {"0.0.0.0/0": "any", "10.0.0.0/8": "limited"},
    "key_sources": {"kms": "customer_key", "sse": "provider_key", "plain": "none"},
    "protocols": {"tcp": "tcp"},
    "app_publishers": {"partner": "third_party", "us": "organization"},
    "provisioning_features": {"create": "create", "delete": "deactivate"},
    "cloud_account_kinds": {"Account": "account"},
    "cloud_network_access": {"Enabled": "open", "Limited": "limited", "Disabled": "off"},
    "cloud_identity_providers": {"IdentityCenter": "workforce", "SAML": "saml"},
    "cloud_credential_permissions": {"AdministratorAccess": "full", "PowerUser": "write", "ReadOnly": "read"},
    "workforce_identity_sources": {"IdentityStore": "sign_in_service", "External": "external_idp"}
  }
}`

func parseAWSOrg(t *testing.T) *Roster {
	t.Helper()
	r, err := Parse([]byte(awsOrg))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func deriveSchema(t *testing.T, r *Roster, schemaID string) map[string]any {
	t.Helper()
	values, err := Derive(r)
	if err != nil {
		t.Fatal(err)
	}
	return values[schemaID]
}

// Scopes are the accounts the collector reads, in key order: dev, then
// prod. A member holds a role anywhere in the account or is local to it,
// and is a person: service and root accounts are neither members nor
// admins, and disabled accounts aren't members. The totals count each
// person once.
func TestAccessMembersAcrossScopes(t *testing.T) {
	v := deriveSchema(t, parseAWSOrg(t), AccessPosture)
	checkPointers(t, v, map[string]any{
		"/scopes/0/id":                             "222",
		"/scopes/0/kind":                           "account",
		"/scopes/1/id":                             "111",
		"/scopes/1/name":                           "Production",
		"/scopes/0/members/member_count":           2,
		"/scopes/0/admins/admin_count":             0,
		"/scopes/1/members/member_count":           3,
		"/scopes/1/admins/admin_count":             2,
		"/scopes/1/admins/admin_share_pct":         67,
		"/members/member_count":                    4,
		"/members/external_member_count":           1,
		"/members/inactive_member_count":           2,
		"/admins/admin_count":                      2,
		"/admins/admin_share_pct":                  50,
		"/scopes/1/members/sso_member_count":       2,
		"/scopes/1/members/local_member_count":     2,
		"/scopes/1/members/local_mfa_member_count": 1,
		"/scopes/1/admins/local_admin_count":       1,
		"/scopes/1/admins/local_mfa_admin_count":   0,
		"/scopes/0/members/local_members_present":  false,
		"/members/sso_member_count":                3,
		"/members/sso_coverage_pct":                75,
		"/members/local_member_count":              2,
		"/members/local_mfa_coverage_pct":          50,
		"/admins/local_admin_mfa_coverage_pct":     0,
	})
	checkUnset(t, v, "/scopes/0/name", "/scopes/2/id")
}

// Each sign-in value of the totals is false when it is false in any scope.
// SSO is required when it is configured and no member can sign in without
// it, and SCIM is on when provisioning both creates and deactivates.
func TestAccessSignInPerScopeAndTotal(t *testing.T) {
	v := deriveSchema(t, parseAWSOrg(t), AccessPosture)
	checkPointers(t, v, map[string]any{
		"/scopes/0/sign_in/sso_configured": true,
		"/scopes/0/sign_in/sso_required":   true,
		"/scopes/0/sign_in/mfa_required":   true,
		"/scopes/0/sign_in/scim_enabled":   false,
		"/scopes/1/sign_in/sso_required":   false,
		"/scopes/1/sign_in/scim_enabled":   true,
		"/sign_in/sso_configured":          true,
		"/sign_in/sso_required":            false,
		"/sign_in/mfa_required":            true,
		"/sign_in/scim_enabled":            false,
		"/system_type":                     "cloud",
	})
}

// Root accounts are each scope's own, the unread account's left out. A
// root account has access keys when an active credential is its own.
func TestAccessRootAccounts(t *testing.T) {
	v := deriveSchema(t, parseAWSOrg(t), AccessPosture)
	checkPointers(t, v, map[string]any{
		"/scopes/0/root/root_account_count":       1,
		"/scopes/0/root/root_mfa_coverage_pct":    0,
		"/scopes/0/root/root_access_keys_present": false,
		"/scopes/1/root/root_access_keys_present": true,
		"/root/root_account_count":                2,
		"/root/root_mfa_account_count":            1,
		"/root/root_mfa_coverage_pct":             50,
		"/root/root_access_keys_present":          true,
	})
}

// Active credentials count. Unused means never used or not in the last 90
// days, unrestricted means full permissions with no IP limit, and a list of
// allowed sources that holds every address is no limit. Rotation is given
// only where the system records when every credential was made.
func TestAccessCredentials(t *testing.T) {
	v := deriveSchema(t, parseAWSOrg(t), AccessPosture)
	checkPointers(t, v, map[string]any{
		"/scopes/1/credentials/credential_count":                  4,
		"/scopes/1/credentials/never_expiring_credential_count":   3,
		"/scopes/1/credentials/unused_credential_count":           2,
		"/scopes/1/credentials/unrestricted_credential_count":     3,
		"/scopes/1/credentials/write_access_credential_count":     4,
		"/scopes/1/credentials/rotation_overdue_credential_count": 2,
		"/scopes/1/credentials/rotation_overdue_pct":              50,
		"/scopes/0/credentials/credential_count":                  1,
		"/scopes/0/credentials/unused_credential_count":           0,
		"/scopes/0/credentials/write_access_credential_count":     0,
		"/credentials/credential_count":                           5,
		"/credentials/never_expiring_pct":                         80,
		"/credentials/unrestricted_pct":                           60,
	})
	checkUnset(t, v, "/scopes/0/credentials/rotation_overdue_credential_count", "/credentials/rotation_overdue_credential_count",
		"/credentials/rotation_overdue_pct")

	r := parseAWSOrg(t)
	created := 5
	for i := range r.Cloud.Credentials {
		if r.Cloud.Credentials[i].Key == "reader" {
			r.Cloud.Credentials[i].CreatedDaysAgo = &created
		}
	}
	checkPointers(t, deriveSchema(t, r, AccessPosture), map[string]any{"/credentials/rotation_overdue_credential_count": 2})
}

// A connected app is an enabled third-party app with a cloud role.
func TestAccessConnectedApps(t *testing.T) {
	checkPointers(t, deriveSchema(t, parseAWSOrg(t), AccessPosture), map[string]any{
		"/connected_apps/app_count":    1,
		"/connected_apps/apps_present": true,
	})
}

// A roster whose one system is a version control organization gives its
// two-factor requirement as access-posture's MFA requirement, the same
// value vcs-posture gives. One with a cloud side as well is refused.
func TestAccessForACodeHostFollowsTheTwoFactorRequirement(t *testing.T) {
	r := &Roster{Version: 1, VCS: &VCS{Organization: "acme", TwoFactorRequirement: true}}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	values, err := Derive(r)
	if err != nil {
		t.Fatal(err)
	}
	checkPointers(t, values[AccessPosture], map[string]any{"/sign_in/mfa_required": true, "/system_type": "code_host"})
	checkPointers(t, values[VCSPosture], map[string]any{"/org_security/two_factor_required": true})
	if _, ok := values[IDPPosture]; ok {
		t.Error("Derive gives idp-posture values for a code host, whose accounts are no directory's")
	}

	both := parseAWSOrg(t)
	both.VCS = r.VCS
	if err := both.Validate(); err == nil || !strings.Contains(err.Error(), "describes one system") {
		t.Errorf("Validate() error = %v, want one about a cloud side and a vcs block", err)
	}
}

// A GitHub organization's members are its enabled people, the outside
// collaborator among them, and not its bot. Its admins are the two owners.
// Its credentials are the token, which belongs to the organization, and the
// deploy key of api, which the scan covers, and not the deploy key of
// sandbox-play, which it leaves out. The token has no creation date, so
// rotation is left out. The collector's own App belongs to the organization
// and the suspended App has no access, so one App is connected.
func TestAccessForAGitHubOrganization(t *testing.T) {
	r, err := Load("testdata/vcs.roster.json")
	if err != nil {
		t.Fatal(err)
	}
	v := deriveSchema(t, r, AccessPosture)
	checkPointers(t, v, map[string]any{
		"/system_type":                                 "code_host",
		"/provider":                                    "github",
		"/sign_in/sso_configured":                      true,
		"/sign_in/sso_required":                        false,
		"/sign_in/mfa_required":                        true,
		"/sign_in/scim_enabled":                        true,
		"/members/member_count":                        5,
		"/members/external_member_count":               1,
		"/members/sso_member_count":                    2,
		"/members/sso_coverage_pct":                    40,
		"/members/local_member_count":                  5,
		"/members/local_mfa_member_count":              3,
		"/members/local_mfa_coverage_pct":              60,
		"/members/inactive_member_count":               2,
		"/members/inactive_pct":                        40,
		"/admins/admin_count":                          2,
		"/admins/admin_share_pct":                      40,
		"/admins/local_admin_count":                    2,
		"/admins/local_mfa_admin_count":                1,
		"/admins/local_admin_mfa_coverage_pct":         50,
		"/root/root_account_count":                     0,
		"/root/root_accounts_present":                  false,
		"/root/root_mfa_coverage_pct":                  nil,
		"/root/root_access_keys_present":               false,
		"/credentials/credential_count":                2,
		"/credentials/never_expiring_credential_count": 1,
		"/credentials/unused_credential_count":         1,
		"/credentials/unrestricted_credential_count":   0,
		"/credentials/write_access_credential_count":   1,
		"/credentials/write_access_pct":                50,
		"/connected_apps/app_count":                    1,
		"/connected_apps/apps_present":                 true,
	})
	checkUnset(t, v, "/credentials/rotation_overdue_credential_count", "/credentials/rotation_overdue_pct", "/scopes/0/id")
}

// A GitLab group's members leave out the blocked account and the bot, and
// only the Owner is an admin. The group's IP allow list limits every
// credential, so none is unrestricted though one token has the api scope.
// The deploy key on scripts and platform-docs counts once, since the scan
// covers platform-docs. The revoked token and the key on scripts alone
// don't count. Every credential records its creation, so rotation is given.
func TestAccessForAGitLabGroup(t *testing.T) {
	r, err := Load("testdata/vcs-gitlab.roster.json")
	if err != nil {
		t.Fatal(err)
	}
	v := deriveSchema(t, r, AccessPosture)
	checkPointers(t, v, map[string]any{
		"/sign_in/sso_configured":                        false,
		"/sign_in/sso_required":                          false,
		"/sign_in/mfa_required":                          false,
		"/sign_in/scim_enabled":                          false,
		"/members/member_count":                          3,
		"/members/external_member_count":                 1,
		"/members/sso_coverage_pct":                      33,
		"/members/local_mfa_coverage_pct":                66,
		"/members/inactive_member_count":                 1,
		"/members/inactive_pct":                          34,
		"/admins/admin_count":                            1,
		"/admins/admin_share_pct":                        34,
		"/admins/local_admin_mfa_coverage_pct":           100,
		"/credentials/credential_count":                  3,
		"/credentials/never_expiring_pct":                34,
		"/credentials/unused_credential_count":           2,
		"/credentials/unrestricted_credential_count":     0,
		"/credentials/write_access_credential_count":     2,
		"/credentials/rotation_overdue_credential_count": 1,
		"/credentials/rotation_overdue_pct":              34,
		"/connected_apps/app_count":                      0,
		"/connected_apps/apps_present":                   false,
	})

	r.VCS.AllowedSources = nil
	checkPointers(t, deriveSchema(t, r, AccessPosture), map[string]any{"/credentials/unrestricted_credential_count": 1})
}

// An artifact for a code host that writes every access-posture field but
// scopes, which a code host has none of, has nothing Derive doesn't cover,
// apart from rotation where the system doesn't record when a credential
// was made. The schema leaves rotation out with a gap then.
func TestCodeHostAccessIsCovered(t *testing.T) {
	s, err := compileSchema(AccessPosture)
	if err != nil {
		t.Fatal(err)
	}
	artifact := map[string]any{}
	for _, field := range outputcheck.Fields(s) {
		if strings.HasPrefix(field, "/scopes/") {
			continue
		}
		at := artifact
		tokens := strings.Split(strings.TrimPrefix(field, "/"), "/")
		for _, token := range tokens[:len(tokens)-1] {
			if at[token] == nil {
				at[token] = map[string]any{}
			}
			at = at[token].(map[string]any)
		}
		at[tokens[len(tokens)-1]] = 1
	}
	raw, err := json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string][]string{
		"testdata/vcs.roster.json":        {"/credentials/rotation_overdue_credential_count", "/credentials/rotation_overdue_pct"},
		"testdata/vcs-gitlab.roster.json": nil,
	} {
		r, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		uncovered, err := Uncovered(AccessPosture, raw, deriveSchema(t, r, AccessPosture))
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(uncovered, want) {
			t.Errorf("%s: Derive gives no value for %v, want %v", path, uncovered, want)
		}
	}
}

func TestParseRefusesBadCodeHostCredentials(t *testing.T) {
	cases := map[string]struct{ from, to, want string }{
		"repository":  {`"repositories": ["api"]`, `"repositories": ["nothing"]`, `credential api-deploy repository nothing is not in the roster`},
		"permissions": {`"permissions": "read_only"`, `"permissions": "admin"`, `permissions "admin" has no entry in terms.vcs_credential_permissions`},
		"owner":       {`"owner": "dev-1"`, `"owner": "nobody"`, `owner nobody is not in the roster`},
		"source":      {`"single_sign_on": true,`, `"single_sign_on": true, "allowed_sources": ["office"],`, `allowed source "office" has no entry in terms.network_sources`},
	}
	raw, err := os.ReadFile("testdata/vcs.roster.json")
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			changed := strings.Replace(string(raw), tc.from, tc.to, 1)
			if changed == string(raw) {
				t.Fatalf("%q is not in the roster", tc.from)
			}
			if _, err := Parse([]byte(changed)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Parse() error = %v, want one containing %q", err, tc.want)
			}
		})
	}
}

// Without a cloud block, the access-posture and cloud-posture values are
// the members, admins, network and storage counts they always were.
func TestWithoutACloudBlockTheCloudSideStaysAsBefore(t *testing.T) {
	r, err := Parse([]byte(cloud))
	if err != nil {
		t.Fatal(err)
	}
	values, err := Derive(r)
	if err != nil {
		t.Fatal(err)
	}
	for pointer := range values[AccessPosture] {
		rest := strings.TrimPrefix(pointer, "/scopes/0")
		if !strings.HasPrefix(rest, "/members/") && !strings.HasPrefix(rest, "/admins/") {
			t.Errorf("access-posture %s is set", pointer)
		}
	}
	for pointer := range values[CloudPosture] {
		if !strings.HasPrefix(pointer, "/accounts/0/network/") && !strings.HasPrefix(pointer, "/accounts/0/storage/") && pointer != "/schema_version" {
			t.Errorf("cloud-posture %s is set", pointer)
		}
	}
	checkUnset(t, values[CloudPosture], "/accounts/0/storage/network_restricted_storage_resource_count")
}

func TestParseRefusesBadAccessFacts(t *testing.T) {
	cases := map[string]struct{ from, to, want string }{
		"login":       {`"logins": "sso", "mfa": "totp"`, `"logins": "magic_link", "mfa": "totp"`, `login "magic_link" has no entry in terms.login_methods`},
		"permissions": {`"permissions": "ReadOnly"`, `"permissions": "Billing"`, `permissions "Billing" has no entry in terms.cloud_credential_permissions`},
		"kind":        {`"id": "333", "kind": "Account"`, `"id": "333", "kind": "Project"`, `kind "Project" has no entry in terms.cloud_account_kinds`},
		"provider":    {`"okta": {"kind": "SAML"}`, `"okta": {"kind": "OIDC"}`, `kind "OIDC" has no entry in terms.cloud_identity_providers`},
		"term":        {`"SAML": "saml"`, `"SAML": "federated"`, `maps "SAML" to "federated"`},
		"access":      {`"dev": {"roles": ["Reader"]}`, `"staging": {"roles": ["Reader"]}`, `cloud_access cloud account staging is not in the roster`},
		"owner":       {`"owner": "iam_user", "created_days_ago": 120`, `"owner": "nobody", "created_days_ago": 120`, `owner nobody is not in the roster`},
		"app":         {`"app": "vendor_tool"`, `"app": "nothing"`, `app nothing is not in the roster`},
		"placement":   {`"cloud_account": "dev", "app"`, `"app"`, `credential reader names no cloud_account, and the cloud block has several`},
		"roles":       {`"ben": {"kind": "member", "enabled": true,`, `"ben": {"kind": "member", "enabled": true, "cloud_roles": ["Reader"],`, `account ben cloud_roles names no cloud_account`},
		"root":        {`"cloud_account": "audit"}`, `"enabled": true}`, `audit_root is a root account and names no cloud_account`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			changed := strings.Replace(awsOrg, tc.from, tc.to, 1)
			if changed == awsOrg {
				t.Fatalf("%q is not in the roster", tc.from)
			}
			if _, err := Parse([]byte(changed)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Parse() error = %v, want one containing %q", err, tc.want)
			}
		})
	}
}
