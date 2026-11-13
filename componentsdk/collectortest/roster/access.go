package roster

import (
	"slices"
	"strconv"
)

// scopeAccess is who and what has access to one cloud account.
type scopeAccess struct {
	// members are the enabled accounts of people with an account in the
	// cloud account or a cloud role anywhere in it, and admins those of
	// them with an admin role over the whole of it.
	members, admins []Account
	// local are the members who can sign in without SSO, and sso those
	// linked to SSO.
	local, sso []Account
	// localAdmins are the admins among local.
	localAdmins []Account
	// roots are its root accounts, enabled or not.
	roots []Account
	// credentials are its active machine credentials.
	credentials []MachineCredential
}

// cloudRolesIn gives the cloud roles a holds over the whole of cloud account
// key and on part of it, directly or through a group. An account's own
// cloud_roles and partial_cloud_roles are in its home cloud account, and a
// group's cloud_roles in the only one.
func (r *Roster) cloudRolesIn(a Account, key string) (whole, partial []string) {
	if r.cloudHome(a.CloudAccount) == key {
		whole, partial = slices.Clone(a.CloudRoles), slices.Clone(a.PartialCloudRoles)
	}
	whole, partial = append(whole, a.CloudAccess[key].Roles...), append(partial, a.CloudAccess[key].PartialRoles...)
	for _, g := range r.Groups {
		if !slices.Contains(g.Members, a.Key) {
			continue
		}
		if r.cloudHome("") == key {
			whole = append(whole, g.CloudRoles...)
		}
		whole, partial = append(whole, g.CloudAccess[key].Roles...), append(partial, g.CloudAccess[key].PartialRoles...)
	}
	return whole, partial
}

func (r *Roster) hasMFA(a Account) bool { return r.MFAClass(a) != MFANone }

func (r *Roster) logsIn(a Account, method string) bool {
	return slices.ContainsFunc(a.Logins, func(l string) bool { return r.Terms.LoginMethods[l] == method })
}

// signsInLocally reports whether a can sign in without SSO.
func (r *Roster) signsInLocally(a Account) bool { return r.logsIn(a, LoginLocal) }

// scopeAccess gives who and what has access to s. A member is an enabled
// person's account, guests included, that holds a cloud role in s, over the
// whole of it or on part of it, or that is local to s. An admin holds a
// cloud role that maps to admin over the whole of s. Its credentials are
// the active ones in s.
func (r *Roster) scopeAccess(s cloudScope) scopeAccess {
	var out scopeAccess
	for _, a := range r.Accounts {
		if r.kindOf(a) == KindRoot {
			if s.key != "" && a.CloudAccount == s.key {
				out.roots = append(out.roots, a)
			}
			continue
		}
		if !a.Enabled || !r.person(a) {
			continue
		}
		whole, partial := r.cloudRolesIn(a, s.key)
		if len(whole) == 0 && len(partial) == 0 && (a.CloudAccount == "" || a.CloudAccount != s.key) {
			continue
		}
		r.addMember(&out, a, slices.ContainsFunc(whole, func(role string) bool { return r.Terms.CloudRoles[role] == RoleAdmin }))
	}
	if r.Cloud != nil {
		for _, m := range r.Cloud.Credentials {
			if m.Active && r.cloudHome(m.CloudAccount) == s.key {
				out.credentials = append(out.credentials, m)
			}
		}
	}
	return out
}

// addMember counts a among sa's members, and among its admins when admin is
// true, with the ways it signs in.
func (r *Roster) addMember(sa *scopeAccess, a Account, admin bool) {
	sa.members = append(sa.members, a)
	if admin {
		sa.admins = append(sa.admins, a)
	}
	if r.logsIn(a, LoginSSO) {
		sa.sso = append(sa.sso, a)
	}
	if r.signsInLocally(a) {
		sa.local = append(sa.local, a)
		if admin {
			sa.localAdmins = append(sa.localAdmins, a)
		}
	}
}

// codeHostAccess gives who and what has access to the vcs block's
// organization. Its members are the enabled accounts of people, outside
// collaborators included, and its admins those of them holding a role that
// maps to admin or super_admin, directly or through a group. Its
// credentials are the active ones that belong to the organization or to a
// repository the scan covers.
func (r *Roster) codeHostAccess() scopeAccess {
	var out scopeAccess
	g := r.VCS
	// Every member, but no outside collaborator, holds the base permission.
	class := r.Terms.Roles[g.BasePermission]
	baseAdmin := class == RoleAdmin || class == RoleSuperAdmin
	for _, a := range r.Accounts {
		if a.Enabled && r.person(a) {
			r.addMember(&out, a, r.admin(a) || (baseAdmin && r.kindOf(a) == KindMember))
		}
	}
	for _, m := range g.Credentials {
		if m.Active && (len(m.Repositories) == 0 || slices.ContainsFunc(m.Repositories, g.scans)) {
			out.credentials = append(out.credentials, m)
		}
	}
	return out
}

// creationKnown reports whether the system records when each of the
// scope's credentials was made.
func (sa scopeAccess) creationKnown() bool {
	return !slices.ContainsFunc(sa.credentials, func(m MachineCredential) bool { return m.CreatedDaysAgo == nil })
}

// rotationOverdue reports whether a credential was made more than the
// rotation window ago.
func rotationOverdue(m MachineCredential) bool {
	return m.CreatedDaysAgo != nil && *m.CreatedDaysAgo > rotationDays
}

// deriveAccess gives access-posture's values for each cloud account Derive
// gives values for, under scopes, and their totals. The totals count each
// member and admin once, however many accounts they are in, and sum the
// root accounts and credentials, each of which is in one account.
//
// Without a cloud block it gives the members and admins of the roster's one
// account. With one it also gives each account's ID, name and kind, its
// sign-in, root accounts and credentials, the system's connected apps, and
// its system type.
func deriveAccess(r *Roster) map[string]any {
	v := map[string]any{}
	var total scopeAccess
	union := func(into *[]Account, from []Account) {
		for _, a := range from {
			if !slices.ContainsFunc(*into, func(b Account) bool { return b.Key == a.Key }) {
				*into = append(*into, a)
			}
		}
	}
	scopes := r.cloudScopes()
	signIns := map[string][]bool{}
	for i, s := range scopes {
		at := "/scopes/" + strconv.Itoa(i)
		sa := r.scopeAccess(s)
		r.addMembers(v, at, sa)
		union(&total.members, sa.members)
		union(&total.admins, sa.admins)
		union(&total.local, sa.local)
		union(&total.sso, sa.sso)
		union(&total.localAdmins, sa.localAdmins)
		if s.account == nil {
			continue
		}
		v[at+"/id"] = s.account.ID
		if s.account.Name != "" {
			v[at+"/name"] = s.account.Name
		}
		v[at+"/kind"] = r.Terms.CloudAccountKinds[s.account.Kind]
		for name, value := range r.signIn(len(s.account.IdentityProviders) > 0, s.account.LocalMFAEnforced, s.account.Provisioning, sa) {
			v[at+"/sign_in/"+name] = value
			signIns[name] = append(signIns[name], value)
		}
		r.addRoots(v, at, sa.roots, sa.credentials)
		r.addCredentials(v, at, sa.credentials)
		total.roots = append(total.roots, sa.roots...)
		total.credentials = append(total.credentials, sa.credentials...)
	}
	r.addMembers(v, "", total)
	if r.Cloud == nil {
		return v
	}
	for name, values := range signIns {
		v["/sign_in/"+name] = !slices.Contains(values, false)
	}
	r.addRoots(v, "", total.roots, total.credentials)
	r.addCredentials(v, "", total.credentials)
	if creationKnownIn(v, len(scopes)) {
		v["/credentials/rotation_overdue_credential_count"] = count(total.credentials, rotationOverdue)
	}
	connected := count(r.Apps, func(a App) bool { return a.Enabled && r.thirdPartyApp(a) && len(a.CloudRoles) > 0 })
	v["/connected_apps/app_count"] = connected
	v["/connected_apps/apps_present"] = connected > 0
	if r.Cloud.SystemType != "" {
		v["/system_type"] = r.Cloud.SystemType
	}
	return v
}

// creationKnownIn reports whether every one of n scopes in v gives its
// credentials' rotation.
func creationKnownIn(v map[string]any, n int) bool {
	for i := range n {
		if _, ok := v["/scopes/"+strconv.Itoa(i)+"/credentials/rotation_overdue_credential_count"]; !ok {
			return false
		}
	}
	return true
}

// addMembers gives a scope's or the totals' members and admins at at. With
// a cloud, vcs or workspace block, it also gives those linked to SSO and those who can
// sign in without SSO, with MFA or without.
func (r *Roster) addMembers(v map[string]any, at string, sa scopeAccess) {
	external := count(sa.members, r.Guest)
	v[at+"/members/member_count"] = len(sa.members)
	v[at+"/members/external_members_present"] = external > 0
	v[at+"/members/external_member_count"] = external
	v[at+"/members/inactive_member_count"] = count(sa.members, func(a Account) bool { return a.SignedInDaysAgo == nil || *a.SignedInDaysAgo > inactiveDays })
	v[at+"/members/members_present"] = len(sa.members) > 0
	v[at+"/admins/admin_count"] = len(sa.admins)
	v[at+"/admins/admins_present"] = len(sa.admins) > 0
	if r.Cloud == nil && r.VCS == nil && r.Workspace == nil {
		return
	}
	v[at+"/members/sso_member_count"] = len(sa.sso)
	v[at+"/members/local_member_count"] = len(sa.local)
	v[at+"/members/local_mfa_member_count"] = count(sa.local, r.hasMFA)
	v[at+"/admins/local_admin_count"] = len(sa.localAdmins)
	v[at+"/admins/local_mfa_admin_count"] = count(sa.localAdmins, r.hasMFA)
}

// signIn gives a system's sign-in values. SSO is configured when configured
// is true, as it is for a cloud account that trusts an identity provider,
// and required when it is and no member can sign in without it. MFA is
// required of those who sign in without SSO when mfaEnforced, the system's
// own setting, is true. Accounts are created and removed through SCIM when
// the provisioning features of its SCIM provisioning both create and
// deactivate them.
func (r *Roster) signIn(configured, mfaEnforced bool, provisioning []string, sa scopeAccess) map[string]bool {
	feature := func(want string) bool {
		return slices.ContainsFunc(provisioning, func(f string) bool { return r.Terms.ProvisioningFeatures[f] == want })
	}
	return map[string]bool{
		"sso_configured": configured,
		"sso_required":   configured && len(sa.local) == 0,
		"mfa_required":   mfaEnforced,
		"scim_enabled":   feature(ProvisionCreate) && feature(ProvisionDeactivate),
	}
}

// addRoots gives root accounts' counts at at. A root account has access
// keys when an active credential is its own.
func (r *Roster) addRoots(v map[string]any, at string, roots []Account, credentials []MachineCredential) {
	v[at+"/root/root_account_count"] = len(roots)
	v[at+"/root/root_mfa_account_count"] = count(roots, r.hasMFA)
	v[at+"/root/root_access_keys_present"] = slices.ContainsFunc(credentials, func(m MachineCredential) bool {
		return slices.ContainsFunc(roots, func(root Account) bool { return root.Key == m.Owner })
	})
}

// addCredentials gives credentials' counts at at. A credential never
// expires when it has no expiry, and is unused when it was never used or
// last used more than the inactive window ago. It is unrestricted when it
// has full permissions and no IP limit, which a list of allowed sources
// sets unless one of them holds every address: its own, or a code host's
// IP allow list. It can write when its permissions are full or write. It is
// overdue for rotation when it was made more than the rotation window ago,
// a count given only when the system records when each credential was made.
func (r *Roster) addCredentials(v map[string]any, at string, credentials []MachineCredential) {
	permissions := func(m MachineCredential) string { return r.Terms.CloudCredentialPermissions[m.Permissions] }
	limits := func(sources []string) bool {
		return len(sources) > 0 && !slices.ContainsFunc(sources, func(s string) bool { return r.Terms.NetworkSources[s] == SourceAny })
	}
	ipLimited := func(m MachineCredential) bool { return limits(m.AllowedSources) }
	switch {
	case r.VCS != nil:
		permissions = func(m MachineCredential) string { return r.Terms.VCSCredentialPermissions[m.Permissions] }
		ipLimited = func(m MachineCredential) bool { return limits(m.AllowedSources) || limits(r.VCS.AllowedSources) }
	case r.Workspace != nil:
		permissions = func(m MachineCredential) string { return r.Terms.WorkspaceCredentialPermissions[m.Permissions] }
		ipLimited = func(m MachineCredential) bool { return limits(m.AllowedSources) || limits(r.Workspace.AllowedSources) }
	}
	v[at+"/credentials/credential_count"] = len(credentials)
	v[at+"/credentials/never_expiring_credential_count"] = count(credentials, func(m MachineCredential) bool { return m.ExpiresInDays == nil })
	v[at+"/credentials/unused_credential_count"] = count(credentials, func(m MachineCredential) bool {
		return m.LastUsedDaysAgo == nil || *m.LastUsedDaysAgo > inactiveDays
	})
	v[at+"/credentials/unrestricted_credential_count"] = count(credentials, func(m MachineCredential) bool { return permissions(m) == PermissionsFull && !ipLimited(m) })
	v[at+"/credentials/write_access_credential_count"] = count(credentials, func(m MachineCredential) bool {
		return permissions(m) == PermissionsFull || permissions(m) == PermissionsWrite
	})
	if at != "" && (scopeAccess{credentials: credentials}).creationKnown() {
		v[at+"/credentials/rotation_overdue_credential_count"] = count(credentials, rotationOverdue)
	}
}

// deriveCodeHostAccess gives access-posture's values for a roster whose one
// system is a version control organization, with the members, admins and
// credentials codeHostAccess gives. SSO is configured when the
// organization's single_sign_on is set. MFA is required of those who sign
// in without SSO when its two-factor requirement is on, the rule
// vcs-posture's two_factor_required follows, since the schemas say the two
// are the same value. An organization has no root account. Its connected
// apps are the enabled third-party apps installed on it.
func deriveCodeHostAccess(r *Roster) map[string]any {
	g := r.VCS
	sa := r.codeHostAccess()
	v := map[string]any{"/system_type": "code_host"}
	for name, value := range r.signIn(g.SingleSignOn, g.TwoFactorRequirement, g.Provisioning, sa) {
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
