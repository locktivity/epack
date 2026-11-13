package roster

import (
	"encoding/json"
	"fmt"
	"slices"
)

// workspaceSystemTypes are the access-posture system types a workspace can
// be. A cloud account has a cloud block, and a code host a vcs block.
var workspaceSystemTypes = []string{"platform", "database", "monitoring", "saas"}

// Workspace is a hosted service's workspace, such as an organization on a
// compute platform or a database service: who can sign in to it, how, and
// its machine credentials. In a roster file:
//
//	"workspace": {
//	  "name": "...", "system_type": "platform",
//	  "single_sign_on": true, "mfa_required": true, "provisioning": [...],
//	  "allowed_sources": [...],
//	  "credentials": {"<key>": {"owner": "...", "app": "...",
//	    "active": true, "created_days_ago": 30, "expires_in_days": 60,
//	    "last_used_days_ago": 2, "allowed_sources": [...],
//	    "permissions": "..."}}
//	}
//
// and in the terms block, "workspace_credential_permissions" maps each
// credential's permissions to full, write or read.
//
// name is the workspace's name. system_type is the kind of system it is,
// as access-posture's system_type gives it: platform, database, monitoring
// or saas. single_sign_on is whether sign-in through an identity provider is
// set up for the workspace, and its provisioning features, mapped in
// terms.provisioning_features, are those of its SCIM provisioning.
// mfa_required is whether the workspace's own setting makes everyone who
// signs in without SSO use MFA. allowed_sources are the networks its IP
// allow list lets every credential in from, mapped in terms.network_sources,
// and left out when it has no allow list.
//
// A roster with a workspace block describes the one workspace. Its accounts
// are the workspace's members, its guests, and the service accounts it has,
// each of kind member, guest or service. An account's roles are its
// workspace roles, mapped in terms.roles, its logins the ways it can sign
// in, and signed_in_days_ago the age of its last sign-in or other recorded
// activity. The roster's apps are the apps connected to the workspace, and
// enabled false marks a suspended one.
//
// Each credential is one machine credential, such as an API token, a
// service account's key or an access token, read as the cloud block's are.
type Workspace struct {
	Name           string
	SystemType     string
	SingleSignOn   bool
	MFARequired    bool
	Provisioning   []string
	AllowedSources []string
	Credentials    []MachineCredential
	Extra          Extra
}

// WorkspaceTerms maps the vendor terms a roster's workspace block uses to
// normalized ones.
type WorkspaceTerms struct {
	// WorkspaceCredentialPermissions maps a credential's permissions to
	// full, write or read.
	WorkspaceCredentialPermissions map[string]string `json:"workspace_credential_permissions"`
}

var workspaceDomain = domain{
	key: "workspace",
	parse: func(r *Roster, raw json.RawMessage) error {
		w, err := parseWorkspace(raw)
		if err != nil {
			return err
		}
		r.Workspace = w
		return nil
	},
	validate: validateWorkspace,
	clone: func(c, r *Roster) {
		if r.Workspace != nil {
			c.Workspace = r.Workspace.clone()
		}
	},
	derive: func(*Roster, Values) error { return nil },
}

func parseWorkspace(raw json.RawMessage) (*Workspace, error) {
	var b struct {
		Name           string                     `json:"name"`
		SystemType     string                     `json:"system_type"`
		SingleSignOn   bool                       `json:"single_sign_on"`
		MFARequired    bool                       `json:"mfa_required"`
		Provisioning   oneOrMore                  `json:"provisioning"`
		AllowedSources []string                   `json:"allowed_sources"`
		Credentials    map[string]json.RawMessage `json:"credentials"`
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, err
	}
	w := &Workspace{
		Name: b.Name, SystemType: b.SystemType, SingleSignOn: b.SingleSignOn, MFARequired: b.MFARequired,
		Provisioning: b.Provisioning, AllowedSources: b.AllowedSources,
	}
	var err error
	if w.Extra, err = extra(raw, "name", "system_type", "single_sign_on", "mfa_required", "provisioning", "allowed_sources", "credentials"); err != nil {
		return nil, err
	}
	if w.Credentials, err = parseCredentials(b.Credentials, ""); err != nil {
		return nil, err
	}
	return w, nil
}

func validateWorkspace(r *Roster) error {
	t := r.Terms
	for _, vendor := range sortedKeys(t.WorkspaceCredentialPermissions) {
		allow := []string{PermissionsFull, PermissionsWrite, PermissionsRead}
		if !slices.Contains(allow, t.WorkspaceCredentialPermissions[vendor]) {
			return fmt.Errorf("terms.workspace_credential_permissions maps %q to %q, which is none of %v", vendor, t.WorkspaceCredentialPermissions[vendor], allow)
		}
	}
	w := r.Workspace
	if w == nil {
		return nil
	}
	if w.Name == "" {
		return fmt.Errorf("the block names no workspace")
	}
	if !slices.Contains(workspaceSystemTypes, w.SystemType) {
		return fmt.Errorf("system_type %q is none of %v", w.SystemType, workspaceSystemTypes)
	}
	if err := mapped(t.ProvisioningFeatures, "provisioning_features", "provisioning", w.Provisioning...); err != nil {
		return err
	}
	if err := mapped(t.NetworkSources, "network_sources", "allowed source", w.AllowedSources...); err != nil {
		return err
	}
	accounts, apps := map[string]bool{}, map[string]bool{}
	for _, a := range r.Accounts {
		accounts[a.Key] = true
	}
	for _, a := range r.Apps {
		apps[a.Key] = true
	}
	for _, m := range w.Credentials {
		if err := r.validateCredential(m, accounts, apps, t.WorkspaceCredentialPermissions, "workspace_credential_permissions"); err != nil {
			return err
		}
	}
	return nil
}

func (w *Workspace) clone() *Workspace {
	c := *w
	c.Provisioning, c.AllowedSources = slices.Clone(w.Provisioning), slices.Clone(w.AllowedSources)
	c.Credentials = cloneCredentials(w.Credentials)
	return &c
}

// workspaceAccess gives who and what has access to the workspace. Its
// members are the enabled accounts of people, guests included, and its
// admins those of them holding a role that maps to admin or super_admin,
// directly or through a group. Its credentials are the active ones.
func (r *Roster) workspaceAccess() scopeAccess {
	var out scopeAccess
	for _, a := range r.Accounts {
		if a.Enabled && r.person(a) {
			r.addMember(&out, a, r.admin(a))
		}
	}
	for _, m := range r.Workspace.Credentials {
		if m.Active {
			out.credentials = append(out.credentials, m)
		}
	}
	return out
}

// deriveWorkspaceAccess gives access-posture's values for a roster whose
// one system is a workspace, with the members, admins and credentials
// workspaceAccess gives. SSO is configured when the workspace's
// single_sign_on is set, and MFA required of those who sign in without SSO
// when its mfa_required is. A workspace has no root account. Its connected
// apps are the enabled third-party apps connected to it.
func deriveWorkspaceAccess(r *Roster) map[string]any {
	w := r.Workspace
	sa := r.workspaceAccess()
	v := map[string]any{"/system_type": w.SystemType}
	for name, value := range r.signIn(w.SingleSignOn, w.MFARequired, w.Provisioning, sa) {
		v["/sign_in/"+name] = value
	}
	r.addMembers(v, "", sa)
	r.addRoots(v, "", nil, sa.credentials)
	r.addCredentials(v, "", sa.credentials)
	if sa.creationKnown() {
		v["/credentials/rotation_overdue_credential_count"] = count(sa.credentials, rotationOverdue)
	}
	connected := count(r.Apps, func(a App) bool { return a.Enabled && r.thirdPartyApp(a) })
	v["/connected_apps/app_count"] = connected
	v["/connected_apps/apps_present"] = connected > 0
	return v
}
