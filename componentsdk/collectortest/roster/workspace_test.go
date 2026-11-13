package roster

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/outputcheck"
)

func loadWorkspace(t *testing.T) *Roster {
	t.Helper()
	r, err := Load("testdata/workspace.roster.json")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// A workspace's members are its enabled people, the guest included, and
// leave out the service account and the disabled former Owner. The Owner
// and the Manager are its admins, and only the SAML member signs in through
// SSO. Its credentials are the three active ones: the deploy token and the
// office token have full permissions, but the office one is limited to a
// network, and the proxy token, which can only read, has never been used.
// Only the tracker counts as a connected app: the paused one is suspended,
// and the workspace's own app is not a third party's.
func TestAccessForAWorkspace(t *testing.T) {
	values, err := Derive(loadWorkspace(t))
	if err != nil {
		t.Fatal(err)
	}
	if got := slices.Sorted(func(yield func(string) bool) {
		for k := range values {
			if !yield(k) {
				return
			}
		}
	}); !slices.Equal(got, []string{AccessPosture}) {
		t.Fatalf("Derive gives values for %v, want access-posture alone, since the accounts are the workspace's", got)
	}
	v := values[AccessPosture]
	checkPointers(t, v, map[string]any{
		"/system_type":                                   "platform",
		"/provider":                                      "acme-platform",
		"/sign_in/sso_configured":                        true,
		"/sign_in/sso_required":                          false,
		"/sign_in/mfa_required":                          false,
		"/sign_in/scim_enabled":                          true,
		"/members/member_count":                          5,
		"/members/external_member_count":                 1,
		"/members/sso_member_count":                      1,
		"/members/sso_coverage_pct":                      20,
		"/members/local_member_count":                    4,
		"/members/local_mfa_member_count":                2,
		"/members/local_mfa_coverage_pct":                50,
		"/members/inactive_member_count":                 1,
		"/members/inactive_pct":                          20,
		"/admins/admin_count":                            2,
		"/admins/admin_share_pct":                        40,
		"/admins/local_admin_count":                      2,
		"/admins/local_mfa_admin_count":                  1,
		"/admins/local_admin_mfa_coverage_pct":           50,
		"/root/root_account_count":                       0,
		"/root/root_access_keys_present":                 false,
		"/credentials/credential_count":                  3,
		"/credentials/never_expiring_credential_count":   2,
		"/credentials/never_expiring_pct":                67,
		"/credentials/unused_credential_count":           1,
		"/credentials/unrestricted_credential_count":     1,
		"/credentials/write_access_credential_count":     2,
		"/credentials/rotation_overdue_credential_count": 1,
		"/credentials/rotation_overdue_pct":              34,
		"/connected_apps/app_count":                      1,
		"/connected_apps/apps_present":                   true,
	})
	checkUnset(t, v, "/scopes/0/id")
}

// SSO is required when it is set up and no member can sign in without it,
// and MFA when the workspace's own setting is on. A network allow list on
// the workspace limits every credential, so none is unrestricted.
func TestWorkspaceSignInAndAllowList(t *testing.T) {
	r := loadWorkspace(t)
	r.Workspace.MFARequired = true
	r.Workspace.AllowedSources = []string{"10.0.0.0/8"}
	for i := range r.Accounts {
		r.Accounts[i].Logins = []string{"saml"}
	}
	checkPointers(t, deriveSchema(t, r, AccessPosture), map[string]any{
		"/sign_in/sso_required":                      true,
		"/sign_in/mfa_required":                      true,
		"/members/local_member_count":                0,
		"/credentials/unrestricted_credential_count": 0,
	})
}

// An artifact for a workspace that writes every access-posture field but
// scopes, which a workspace has none of, has nothing Derive doesn't cover.
func TestWorkspaceAccessIsCovered(t *testing.T) {
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
	uncovered, err := Uncovered(AccessPosture, raw, deriveSchema(t, loadWorkspace(t), AccessPosture))
	if err != nil {
		t.Fatal(err)
	}
	if len(uncovered) > 0 {
		t.Errorf("Derive gives no value for %v", uncovered)
	}
}

func TestParseRefusesBadWorkspaces(t *testing.T) {
	cases := map[string]struct{ from, to, want string }{
		"system type": {`"system_type": "platform"`, `"system_type": "code_host"`, `system_type "code_host" is none of`},
		"name":        {`"name": "acme",`, ``, `the block names no workspace`},
		"permissions": {`"permissions": "invoke"`, `"permissions": "admin"`, `permissions "admin" has no entry in terms.workspace_credential_permissions`},
		"term":        {`"invoke": "read"`, `"invoke": "execute"`, `terms.workspace_credential_permissions maps "invoke" to "execute"`},
		"owner":       {`"owner": "ci"`, `"owner": "nobody"`, `owner nobody is not in the roster`},
		"source":      {`"single_sign_on": true,`, `"single_sign_on": true, "allowed_sources": ["office"],`, `allowed source "office" has no entry in terms.network_sources`},
		"vcs":         {`"workspace": {`, `"vcs": {"organization": "acme"}, "workspace": {`, `access-posture describes one system`},
	}
	raw, err := os.ReadFile("testdata/workspace.roster.json")
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

// A workspace beside a cloud side is refused too: cloud roles make one.
func TestParseRefusesAWorkspaceBesideACloudSide(t *testing.T) {
	raw, err := os.ReadFile("testdata/workspace.roster.json")
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(string(raw), `"roles": ["Manager"]}`, `"roles": ["Manager"], "cloud_roles": ["Admin"]}`, 1)
	changed = strings.Replace(changed, `"roles": {"Owner"`, `"cloud_roles": {"Admin": "admin"}, "roles": {"Owner"`, 1)
	if _, err := Parse([]byte(changed)); err == nil || !strings.Contains(err.Error(), "access-posture describes one system") {
		t.Fatalf("Parse() error = %v, want one saying access-posture describes one system", err)
	}
}

// A clone's workspace is its own.
func TestCloneCopiesTheWorkspace(t *testing.T) {
	r := loadWorkspace(t)
	c := r.Clone()
	c.Workspace.Provisioning[0] = "changed"
	*c.Workspace.Credentials[0].CreatedDaysAgo = 1
	if r.Workspace.Provisioning[0] == "changed" || *r.Workspace.Credentials[0].CreatedDaysAgo == 1 {
		t.Fatal("changing the clone's workspace changed the roster's")
	}
}
