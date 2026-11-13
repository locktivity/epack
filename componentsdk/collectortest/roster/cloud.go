package roster

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"

	"github.com/locktivity/epack/componentsdk"
)

// The cloud block's normalized terms.
const (
	CloudKindAccount      = "account"
	CloudKindSubscription = "subscription"

	// NetworkOpen lets any network connect, NetworkLimited only the
	// allowed sources and private endpoints, and NetworkOff only private
	// endpoints.
	NetworkOpen    = "open"
	NetworkLimited = "limited"
	NetworkOff     = "off"

	// IdPWorkforce is a provider a workforce sign-in service, such as AWS
	// IAM Identity Center, created in the account to sign people in.
	IdPSAML      = "saml"
	IdPOIDC      = "oidc"
	IdPWorkforce = "workforce"

	// PermissionsFull is every permission over everything, PermissionsWrite
	// write or admin access to some of it, and PermissionsRead read access
	// only.
	PermissionsFull  = "full"
	PermissionsWrite = "write"
	PermissionsRead  = "read"

	// SourceSignInService is a workforce sign-in service whose own
	// directory sets its users' MFA, and SourceExternalIdP one whose users
	// come from an external identity provider that sets it.
	SourceSignInService = "sign_in_service"
	SourceExternalIdP   = "external_idp"
)

// rotationDays is the age past which access-posture counts a credential as
// overdue for rotation.
const rotationDays = 90

// systemTypes are access-posture's system types.
var systemTypes = []string{"cloud", "code_host", "database", "platform", "monitoring", "saas"}

// Cloud is the cloud side's accounts or subscriptions and what they hold
// beyond security groups and storage. Its file format:
//
//	"cloud": {
//	  "system_type": "cloud",
//	  "accounts": {"<key>": {"id": "...", "name": "...", "kind": "...",
//	    "collector_access": true, "regions": [...],
//	    "identity_providers": {"<key>": {"kind": "..."}},
//	    "local_mfa_enforced": true, "provisioning": [...],
//	    "audit_logs": {"<key>": {"enabled": true, "regions": [...]}},
//	    "threat_detection": [...]}},
//	  "databases": {"<key>": {"cloud_account": "...", "key_source": "...",
//	    "network_access": "...", "allowed_sources": [...], "zones": 2,
//	    "backup_retention_days": 7}},
//	  "credentials": {"<key>": {"cloud_account": "...", "owner": "...",
//	    "app": "...", "active": true, "created_days_ago": 30,
//	    "expires_in_days": 60, "last_used_days_ago": 2,
//	    "allowed_sources": [...], "permissions": "..."}},
//	  "workforce_sign_in": {"identity_source": "..."}
//	}
//
// system_type is access-posture's kind of system. Each account is one
// account or subscription: id is its vendor ID, name its name, and kind is
// mapped in terms.cloud_account_kinds (account or subscription).
// collector_access false marks an account the collection is configured to
// cover whose data the collector's identity can't read, such as an AWS
// account with no role for it to assume. regions are the regions the account
// uses. A list of regions a service is on in holds * when it is on in every
// region, or when the cloud's service is global.
//
// An account's identity_providers are the sign-in providers it trusts, each
// kind mapped in terms.cloud_identity_providers (saml, oidc, or workforce
// for one a workforce sign-in service made). local_mfa_enforced is the
// account's setting that makes anyone signing in without SSO use MFA. Its
// provisioning features, mapped in terms.provisioning_features, are those of
// its SCIM provisioning. An audit log of management activity covers the
// regions it lists, and enabled false marks one that is turned off.
// threat_detection lists the regions threat detection is on in. Its
// vulnerability scanners and what they found are the scanning block's scope
// with its id, as Scanning documents.
//
// A database's key_source is mapped in terms.key_sources and its
// network_access in terms.cloud_network_access (open, limited or off), with
// the allowed sources of a limited one in terms.network_sources. zones is
// how many availability zones it runs in, one when left out, and
// backup_retention_days how long its backups are kept, left out when it has
// none. A storage resource's network_access and allowed_sources read the
// same way.
//
// Each credential is one machine credential, such as an access key, a token
// or a service user's password. owner is the account it belongs to and app
// the app, or neither for one that belongs to the system. active false marks
// one that is turned off. created_days_ago is left out when the system
// doesn't record when it was made, expires_in_days when it never expires,
// and last_used_days_ago when it was never used. allowed_sources are the
// networks it can be used from, left out when there is no IP limit, and
// permissions, mapped in terms.cloud_credential_permissions (full, write or
// read), what it can do.
//
// workforce_sign_in is the central service that signs people in to the
// accounts, such as AWS IAM Identity Center, when there is one. Its
// directory is the roster's directory accounts. identity_source is mapped
// in terms.workforce_identity_sources (sign_in_service or external_idp).
//
// A storage resource, security group, database, credential or local account
// names its cloud_account. It may leave it out when the block has one
// account, as may an account's or group's cloud_roles.
type Cloud struct {
	SystemType  string
	Accounts    []CloudAccount
	Databases   []Database
	Credentials []MachineCredential
	Workforce   *WorkforceSignIn
	Extra       Extra
}

// CloudTerms maps the vendor terms a roster's cloud block uses to
// normalized ones.
type CloudTerms struct {
	CloudAccountKinds          map[string]string `json:"cloud_account_kinds"`
	CloudNetworkAccess         map[string]string `json:"cloud_network_access"`
	CloudIdentityProviders     map[string]string `json:"cloud_identity_providers"`
	CloudCredentialPermissions map[string]string `json:"cloud_credential_permissions"`
	WorkforceIdentitySources   map[string]string `json:"workforce_identity_sources"`
}

// CloudAccount is one cloud account or subscription.
type CloudAccount struct {
	Key  string
	ID   string
	Name string
	Kind string
	// CollectorAccess is whether the collector's identity can read the
	// account.
	CollectorAccess   bool
	Regions           []string
	IdentityProviders []IdentityProvider
	LocalMFAEnforced  bool
	Provisioning      []string
	AuditLogs         []AuditLog
	ThreatDetection   []string
	Extra             Extra
}

// IdentityProvider is a sign-in provider a cloud account trusts.
type IdentityProvider struct {
	Key   string
	Kind  string
	Extra Extra
}

// AuditLog is an audit log of a cloud account's management activity.
type AuditLog struct {
	Key     string
	Enabled bool
	Regions []string
	Extra   Extra
}

// Database is a managed database.
type Database struct {
	Key            string
	CloudAccount   string
	KeySource      string
	NetworkAccess  string
	AllowedSources []string
	// Zones is how many availability zones the database runs in.
	Zones               int
	BackupRetentionDays *int
	Extra               Extra
}

// MachineCredential is one credential a program uses.
type MachineCredential struct {
	Key          string
	CloudAccount string
	// Repositories are the repositories a code host's credential belongs
	// to, such as a deploy key's, and empty for one that belongs to the
	// organization.
	Repositories    []string
	Owner           string
	App             string
	Active          bool
	CreatedDaysAgo  *int
	ExpiresInDays   *int
	LastUsedDaysAgo *int
	AllowedSources  []string
	Permissions     string
	Extra           Extra
}

// WorkforceSignIn is a central service that signs people in to the cloud
// accounts.
type WorkforceSignIn struct {
	IdentitySource string
	Extra          Extra
}

func parseCloud(raw json.RawMessage) (*Cloud, error) {
	var c struct {
		SystemType  string                     `json:"system_type"`
		Accounts    map[string]json.RawMessage `json:"accounts"`
		Databases   map[string]json.RawMessage `json:"databases"`
		Credentials map[string]json.RawMessage `json:"credentials"`
		Workforce   json.RawMessage            `json:"workforce_sign_in"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	out := &Cloud{SystemType: c.SystemType}
	var err error
	if out.Extra, err = extra(raw, "system_type", "accounts", "databases", "credentials", "workforce_sign_in"); err != nil {
		return nil, err
	}
	for _, key := range sortedKeys(c.Accounts) {
		a, err := parseCloudAccount(key, c.Accounts[key])
		if err != nil {
			return nil, fmt.Errorf("account %s: %w", key, err)
		}
		out.Accounts = append(out.Accounts, a)
	}
	for _, key := range sortedKeys(c.Databases) {
		var d struct {
			CloudAccount    string   `json:"cloud_account"`
			KeySource       string   `json:"key_source"`
			NetworkAccess   string   `json:"network_access"`
			AllowedSources  []string `json:"allowed_sources"`
			Zones           *int     `json:"zones"`
			BackupRetention *int     `json:"backup_retention_days"`
		}
		if err := json.Unmarshal(c.Databases[key], &d); err != nil {
			return nil, fmt.Errorf("database %s: %w", key, err)
		}
		e, err := extra(c.Databases[key], "cloud_account", "key_source", "network_access", "allowed_sources", "zones", "backup_retention_days")
		if err != nil {
			return nil, fmt.Errorf("database %s: %w", key, err)
		}
		zones := 1
		if d.Zones != nil {
			zones = *d.Zones
		}
		out.Databases = append(out.Databases, Database{Key: key, CloudAccount: d.CloudAccount, KeySource: d.KeySource, NetworkAccess: d.NetworkAccess,
			AllowedSources: d.AllowedSources, Zones: zones, BackupRetentionDays: d.BackupRetention, Extra: e})
	}
	if out.Credentials, err = parseCredentials(c.Credentials, "cloud_account"); err != nil {
		return nil, err
	}
	if len(c.Workforce) > 0 {
		var w struct {
			IdentitySource string `json:"identity_source"`
		}
		if err := json.Unmarshal(c.Workforce, &w); err != nil {
			return nil, fmt.Errorf("workforce_sign_in: %w", err)
		}
		e, err := extra(c.Workforce, "identity_source")
		if err != nil {
			return nil, fmt.Errorf("workforce_sign_in: %w", err)
		}
		out.Workforce = &WorkforceSignIn{IdentitySource: w.IdentitySource, Extra: e}
	}
	return out, nil
}

func parseCloudAccount(key string, raw json.RawMessage) (CloudAccount, error) {
	var a struct {
		ID                string                     `json:"id"`
		Name              string                     `json:"name"`
		Kind              string                     `json:"kind"`
		CollectorAccess   *bool                      `json:"collector_access"`
		Regions           []string                   `json:"regions"`
		IdentityProviders map[string]json.RawMessage `json:"identity_providers"`
		LocalMFAEnforced  bool                       `json:"local_mfa_enforced"`
		Provisioning      oneOrMore                  `json:"provisioning"`
		AuditLogs         map[string]json.RawMessage `json:"audit_logs"`
		ThreatDetection   []string                   `json:"threat_detection"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return CloudAccount{}, err
	}
	out := CloudAccount{
		Key: key, ID: a.ID, Name: a.Name, Kind: a.Kind, CollectorAccess: a.CollectorAccess == nil || *a.CollectorAccess,
		Regions: a.Regions, LocalMFAEnforced: a.LocalMFAEnforced, Provisioning: a.Provisioning, ThreatDetection: a.ThreatDetection,
	}
	var err error
	if out.Extra, err = extra(raw, "id", "name", "kind", "collector_access", "regions", "identity_providers", "local_mfa_enforced",
		"provisioning", "audit_logs", "threat_detection"); err != nil {
		return CloudAccount{}, err
	}
	for _, pk := range sortedKeys(a.IdentityProviders) {
		var p struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(a.IdentityProviders[pk], &p); err != nil {
			return CloudAccount{}, fmt.Errorf("identity provider %s: %w", pk, err)
		}
		e, err := extra(a.IdentityProviders[pk], "kind")
		if err != nil {
			return CloudAccount{}, fmt.Errorf("identity provider %s: %w", pk, err)
		}
		out.IdentityProviders = append(out.IdentityProviders, IdentityProvider{Key: pk, Kind: p.Kind, Extra: e})
	}
	for _, lk := range sortedKeys(a.AuditLogs) {
		var l struct {
			Enabled *bool    `json:"enabled"`
			Regions []string `json:"regions"`
		}
		if err := json.Unmarshal(a.AuditLogs[lk], &l); err != nil {
			return CloudAccount{}, fmt.Errorf("audit log %s: %w", lk, err)
		}
		e, err := extra(a.AuditLogs[lk], "enabled", "regions")
		if err != nil {
			return CloudAccount{}, fmt.Errorf("audit log %s: %w", lk, err)
		}
		out.AuditLogs = append(out.AuditLogs, AuditLog{Key: lk, Enabled: l.Enabled == nil || *l.Enabled, Regions: l.Regions, Extra: e})
	}
	return out, nil
}

func (c *Cloud) clone() *Cloud {
	if c == nil {
		return nil
	}
	out := *c
	out.Accounts = slices.Clone(c.Accounts)
	for i := range out.Accounts {
		a := &out.Accounts[i]
		a.Regions, a.IdentityProviders, a.Provisioning, a.ThreatDetection = slices.Clone(a.Regions), slices.Clone(a.IdentityProviders), slices.Clone(a.Provisioning), slices.Clone(a.ThreatDetection)
		a.AuditLogs = slices.Clone(a.AuditLogs)
		for j := range a.AuditLogs {
			a.AuditLogs[j].Regions = slices.Clone(a.AuditLogs[j].Regions)
		}
	}
	out.Databases = slices.Clone(c.Databases)
	for i := range out.Databases {
		out.Databases[i].AllowedSources, out.Databases[i].BackupRetentionDays = slices.Clone(out.Databases[i].AllowedSources), cloneInt(out.Databases[i].BackupRetentionDays)
	}
	out.Credentials = cloneCredentials(c.Credentials)
	if c.Workforce != nil {
		w := *c.Workforce
		out.Workforce = &w
	}
	return &out
}

// placed checks that an entry's cloud account, its cloud_account or empty
// for none, is one the roster has, and that an entry naming none belongs to
// the only one.
func (r *Roster) placed(what, cloudAccount string) error {
	if cloudAccount == "" {
		if r.Cloud != nil && len(r.Cloud.Accounts) > 1 {
			return fmt.Errorf("%s names no cloud_account, and the cloud block has several", what)
		}
		return nil
	}
	if r.Cloud == nil || !slices.ContainsFunc(r.Cloud.Accounts, func(a CloudAccount) bool { return a.Key == cloudAccount }) {
		return fmt.Errorf("%s cloud account %s is not in the roster", what, cloudAccount)
	}
	return nil
}

func (r *Roster) validateCloudAccess(what string, access map[string]CloudGrant) error {
	for _, key := range sortedKeys(access) {
		if err := r.placed(what+" cloud_access", key); err != nil {
			return err
		}
		if err := mapped(r.Terms.CloudRoles, "cloud_roles", what+" cloud role", append(slices.Clone(access[key].Roles), access[key].PartialRoles...)...); err != nil {
			return err
		}
	}
	return nil
}

// validateNetworkAccess checks a resource's network access and allowed
// sources. With a cloud block, every resource states its network access.
func (r *Roster) validateNetworkAccess(what, access string, sources []string) error {
	if access == "" {
		if r.Cloud != nil {
			return fmt.Errorf("%s has no network_access", what)
		}
	} else if err := mapped(r.Terms.CloudNetworkAccess, "cloud_network_access", what+" network_access", access); err != nil {
		return err
	}
	return mapped(r.Terms.NetworkSources, "network_sources", what+" allowed source", sources...)
}

func (r *Roster) validateCloud(accounts map[string]bool) error {
	t := r.Terms
	for name, m := range map[string]struct {
		terms map[string]string
		allow []string
	}{
		"cloud_account_kinds":          {t.CloudAccountKinds, []string{CloudKindAccount, CloudKindSubscription}},
		"cloud_network_access":         {t.CloudNetworkAccess, []string{NetworkOpen, NetworkLimited, NetworkOff}},
		"cloud_identity_providers":     {t.CloudIdentityProviders, []string{IdPSAML, IdPOIDC, IdPWorkforce}},
		"cloud_credential_permissions": {t.CloudCredentialPermissions, []string{PermissionsFull, PermissionsWrite, PermissionsRead}},
		"workforce_identity_sources":   {t.WorkforceIdentitySources, []string{SourceSignInService, SourceExternalIdP}},
	} {
		for _, vendor := range sortedKeys(m.terms) {
			if !slices.Contains(m.allow, m.terms[vendor]) {
				return fmt.Errorf("terms.%s maps %q to %q, which is none of %v", name, vendor, m.terms[vendor], m.allow)
			}
		}
	}
	c := r.Cloud
	if c == nil {
		return nil
	}
	if c.SystemType != "" && !slices.Contains(systemTypes, c.SystemType) {
		return fmt.Errorf("system_type %q is none of %v", c.SystemType, systemTypes)
	}
	if len(c.Accounts) == 0 {
		return fmt.Errorf("the cloud block has no accounts")
	}
	for _, a := range c.Accounts {
		what := "account " + a.Key
		if a.ID == "" {
			return fmt.Errorf("%s has no id", what)
		}
		if err := mapped(t.CloudAccountKinds, "cloud_account_kinds", what+" kind", a.Kind); err != nil {
			return err
		}
		for _, p := range a.IdentityProviders {
			if err := mapped(t.CloudIdentityProviders, "cloud_identity_providers", what+" identity provider "+p.Key+" kind", p.Kind); err != nil {
				return err
			}
		}
		if err := mapped(t.ProvisioningFeatures, "provisioning_features", what+" provisioning", a.Provisioning...); err != nil {
			return err
		}
	}
	for _, d := range c.Databases {
		what := "database " + d.Key
		if err := r.placed(what, d.CloudAccount); err != nil {
			return err
		}
		if err := mapped(t.KeySources, "key_sources", what+" key source", d.KeySource); err != nil {
			return err
		}
		if err := r.validateNetworkAccess(what, d.NetworkAccess, d.AllowedSources); err != nil {
			return err
		}
		if d.Zones < 1 {
			return fmt.Errorf("%s runs in %d zones", what, d.Zones)
		}
		if d.BackupRetentionDays != nil && *d.BackupRetentionDays <= 0 {
			return fmt.Errorf("%s keeps backups %d days; leave backup_retention_days out for none", what, *d.BackupRetentionDays)
		}
	}
	apps := map[string]bool{}
	for _, a := range r.Apps {
		apps[a.Key] = true
	}
	for _, m := range c.Credentials {
		if err := r.placed("credential "+m.Key, m.CloudAccount); err != nil {
			return err
		}
		if err := r.validateCredential(m, accounts, apps, t.CloudCredentialPermissions, "cloud_credential_permissions"); err != nil {
			return err
		}
	}
	if c.Workforce != nil {
		if err := mapped(t.WorkforceIdentitySources, "workforce_identity_sources", "workforce_sign_in identity_source", c.Workforce.IdentitySource); err != nil {
			return err
		}
	}
	return nil
}

func ifSet(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

// parseCredentials reads a block's machine credentials. place is the field
// that says where each one is: cloud_account in a cloud block, repositories
// in a vcs block, and none in a workspace block, whose credentials are all
// the workspace's.
func parseCredentials(raw map[string]json.RawMessage, place string) ([]MachineCredential, error) {
	var out []MachineCredential
	for _, key := range sortedKeys(raw) {
		var m struct {
			CloudAccount    string   `json:"cloud_account"`
			Repositories    []string `json:"repositories"`
			Owner           string   `json:"owner"`
			App             string   `json:"app"`
			Active          *bool    `json:"active"`
			CreatedDaysAgo  *int     `json:"created_days_ago"`
			ExpiresInDays   *int     `json:"expires_in_days"`
			LastUsedDaysAgo *int     `json:"last_used_days_ago"`
			AllowedSources  []string `json:"allowed_sources"`
			Permissions     string   `json:"permissions"`
		}
		if err := json.Unmarshal(raw[key], &m); err != nil {
			return nil, fmt.Errorf("credential %s: %w", key, err)
		}
		e, err := extra(raw[key], place, "owner", "app", "active", "created_days_ago", "expires_in_days", "last_used_days_ago", "allowed_sources", "permissions")
		if err != nil {
			return nil, fmt.Errorf("credential %s: %w", key, err)
		}
		c := MachineCredential{
			Key: key, Owner: m.Owner, App: m.App, Active: m.Active == nil || *m.Active,
			CreatedDaysAgo: m.CreatedDaysAgo, ExpiresInDays: m.ExpiresInDays, LastUsedDaysAgo: m.LastUsedDaysAgo,
			AllowedSources: m.AllowedSources, Permissions: m.Permissions, Extra: e,
		}
		switch place {
		case "cloud_account":
			c.CloudAccount = m.CloudAccount
		case "repositories":
			c.Repositories = m.Repositories
		}
		out = append(out, c)
	}
	return out, nil
}

// validateCredential checks a machine credential's owner, app, permissions,
// allowed sources and ages. permissions are the terms its block maps
// permissions in, called block in the terms block.
func (r *Roster) validateCredential(m MachineCredential, accounts, apps map[string]bool, permissions map[string]string, block string) error {
	what := "credential " + m.Key
	if m.Owner != "" && m.App != "" {
		return fmt.Errorf("%s names both an owner and an app", what)
	}
	if err := known(accounts, what+" owner", ifSet(m.Owner)...); err != nil {
		return err
	}
	if err := known(apps, what+" app", ifSet(m.App)...); err != nil {
		return err
	}
	if err := mapped(permissions, block, what+" permissions", m.Permissions); err != nil {
		return err
	}
	if err := mapped(r.Terms.NetworkSources, "network_sources", what+" allowed source", m.AllowedSources...); err != nil {
		return err
	}
	for name, days := range map[string]*int{"created_days_ago": m.CreatedDaysAgo, "last_used_days_ago": m.LastUsedDaysAgo} {
		if days != nil && *days < 0 {
			return fmt.Errorf("%s %s is %d, in the future", what, name, *days)
		}
	}
	return nil
}

func cloneCredentials(credentials []MachineCredential) []MachineCredential {
	out := slices.Clone(credentials)
	for i := range out {
		m := &out[i]
		m.CreatedDaysAgo, m.ExpiresInDays, m.LastUsedDaysAgo = cloneInt(m.CreatedDaysAgo), cloneInt(m.ExpiresInDays), cloneInt(m.LastUsedDaysAgo)
		m.AllowedSources, m.Repositories = slices.Clone(m.AllowedSources), slices.Clone(m.Repositories)
	}
	return out
}

// cloudScope is a cloud account Derive gives values for: one in the cloud block
// the collector can read, or the one account of a roster without a cloud
// block, which has no key and no account.
type cloudScope struct {
	key     string
	account *CloudAccount
}

// cloudScopes lists the cloud accounts Derive gives values for, in the roster's
// order.
func (r *Roster) cloudScopes() []cloudScope {
	if r.Cloud == nil {
		return []cloudScope{{}}
	}
	var out []cloudScope
	for i := range r.Cloud.Accounts {
		if a := &r.Cloud.Accounts[i]; a.CollectorAccess {
			out = append(out, cloudScope{key: a.Key, account: a})
		}
	}
	return out
}

// cloudHome is the key of the cloud account an entry is in: the one it names,
// or the only one.
func (r *Roster) cloudHome(cloudAccount string) string {
	if cloudAccount != "" || r.Cloud == nil {
		return cloudAccount
	}
	return r.Cloud.Accounts[0].Key
}

// covers reports whether a service on in regions is on in every region the
// account uses.
func (a *CloudAccount) covers(regions []string) bool {
	if len(regions) == 0 {
		return false
	}
	if slices.Contains(regions, "*") {
		return true
	}
	return !slices.ContainsFunc(a.Regions, func(region string) bool { return !slices.Contains(regions, region) })
}

// refusesInternet reports whether a resource with the network access and
// allowed sources given refuses traffic from the public internet: its
// public network access is off, or only listed networks may connect and no
// listed network holds every address.
func (r *Roster) refusesInternet(access string, sources []string) bool {
	switch r.Terms.CloudNetworkAccess[access] {
	case NetworkOff:
		return true
	case NetworkLimited:
		return !slices.ContainsFunc(sources, func(s string) bool { return r.Terms.NetworkSources[s] == SourceAny })
	}
	return false
}

// deriveCloud gives cloud-posture's values, one accounts entry for each
// cloud account Derive gives values for. A security group is open to a
// port when a connection to it over TCP from any address gets in. Storage
// counts as encrypted with any key, the provider's own included, and as
// blocking public access when no one can read its data without signing in.
// With a cloud block, it also gives the rest of each account and the
// collection's coverage, as deriveCloudAccount says.
func deriveCloud(r *Roster) map[string]any {
	v := map[string]any{}
	for i, s := range r.cloudScopes() {
		at := "/accounts/" + strconv.Itoa(i)
		groups := slices.DeleteFunc(slices.Clone(r.SecurityGroups), func(g SecurityGroup) bool { return r.cloudHome(g.CloudAccount) != s.key })
		storage := slices.DeleteFunc(slices.Clone(r.Storage), func(st Storage) bool { return r.cloudHome(st.CloudAccount) != s.key })
		v[at+"/network/security_group_count"] = len(groups)
		v[at+"/network/ssh_open_security_group_count"] = count(groups, func(g SecurityGroup) bool { return r.openToAny(g, 22) })
		v[at+"/network/rdp_open_security_group_count"] = count(groups, func(g SecurityGroup) bool { return r.openToAny(g, 3389) })
		v[at+"/storage/storage_resource_count"] = len(storage)
		v[at+"/storage/encrypted_storage_resource_count"] = count(storage, func(st Storage) bool { return r.Terms.KeySources[st.KeySource] != NoKey })
		v[at+"/storage/public_access_blocked_storage_resource_count"] = count(storage, func(st Storage) bool { return !st.AnonymousAccess })
		if s.account != nil {
			r.deriveCloudAccount(v, at, s, storage)
		}
	}
	if r.Cloud != nil {
		v["/accounts_expected"] = len(r.Cloud.Accounts)
		v["/all_accounts_collected"] = !slices.ContainsFunc(r.Cloud.Accounts, func(a CloudAccount) bool { return !a.CollectorAccess })
		if w := r.Cloud.Workforce; w != nil {
			v["/workforce_sign_in/in_use"] = slices.ContainsFunc(r.cloudScopes(), func(s cloudScope) bool {
				return slices.ContainsFunc(s.account.IdentityProviders, func(p IdentityProvider) bool { return r.Terms.CloudIdentityProviders[p.Kind] == IdPWorkforce })
			})
			v["/workforce_sign_in/user_count"] = count(r.Accounts, func(a Account) bool { return inDirectory(a) && r.person(a) })
			v["/workforce_sign_in/mfa_source"] = r.Terms.WorkforceIdentitySources[w.IdentitySource]
		}
	}
	return v
}

// deriveCloudAccount gives the values of a cloud account in the cloud
// block beyond its network and storage counts, at at.
//
// Storage and a database refuse the public internet as refusesInternet
// says. A database is encrypted with any key, and runs across availability
// zones when it runs in more than one. The audit log is enabled when one is,
// and covers every region when the enabled ones between them do. Backup
// retention is the shortest any database or storage resource with backups
// keeps them, or null when none has backups. Threat detection is enabled
// when it is on in every region the account uses. Vulnerability scanning
// reads the scanning block, as cloudVulnScanning says.
//
// The iam values are those access-posture gives the account, as their
// descriptions say: users are the members who can sign in without SSO, and
// the owner identities are its root accounts. A root account is protected
// from password-only use when it has MFA, or no way to sign in without SSO
// and no active credential. Users with access keys are the owners of the
// account's active credentials, each app or ownerless credential its own
// owner, and an owner's credentials are rotated in time when none is older
// than the rotation window. SAML providers are those the account trusts
// directly, not ones a workforce sign-in service made.
func (r *Roster) deriveCloudAccount(v map[string]any, at string, s cloudScope, storage []Storage) {
	a := s.account
	v[at+"/account_id"] = a.ID
	v[at+"/storage/network_restricted_storage_resource_count"] = count(storage, func(st Storage) bool { return r.refusesInternet(st.NetworkAccess, st.AllowedSources) })

	databases := slices.DeleteFunc(slices.Clone(r.Cloud.Databases), func(d Database) bool { return r.cloudHome(d.CloudAccount) != s.key })
	v[at+"/database/database_count"] = len(databases)
	v[at+"/database/encrypted_database_count"] = count(databases, func(d Database) bool { return r.Terms.KeySources[d.KeySource] != NoKey })
	v[at+"/database/public_access_blocked_database_count"] = count(databases, func(d Database) bool { return r.refusesInternet(d.NetworkAccess, d.AllowedSources) })
	v[at+"/database/multi_az_database_count"] = count(databases, func(d Database) bool { return d.Zones > 1 })

	var logged []string
	enabled := false
	for _, l := range a.AuditLogs {
		if l.Enabled {
			enabled = true
			logged = append(logged, l.Regions...)
		}
	}
	allRegions := enabled && a.covers(logged)
	v[at+"/logging/audit_log_enabled"] = enabled
	v[at+"/logging/audit_log_all_regions"] = allRegions
	v[at+"/logging/cloudtrail_enabled"] = enabled
	v[at+"/logging/cloudtrail_multiregion"] = allRegions

	var retention []int
	for _, d := range databases {
		if d.BackupRetentionDays != nil {
			retention = append(retention, *d.BackupRetentionDays)
		}
	}
	for _, st := range storage {
		if st.BackupRetentionDays != nil {
			retention = append(retention, *st.BackupRetentionDays)
		}
	}
	if len(retention) > 0 {
		v[at+"/backup/retention_days_min"] = slices.Min(retention)
	} else {
		v[at+"/backup/retention_days_min"] = nil
	}

	v[at+"/threat_detection/enabled"] = a.covers(a.ThreatDetection)

	if r.Scanning != nil {
		enabled, scanned, unpatched := r.cloudVulnScanning(a.ID)
		v[at+"/vuln_scanning/enabled"] = enabled
		v[at+"/vuln_scanning/unpatched_pct"] = percentOrNull(unpatched, scanned, componentsdk.RoundUp)
	}

	sa := r.scopeAccess(s)
	v[at+"/iam/user_count"] = len(sa.local)
	v[at+"/iam/mfa_coverage_pct"] = percentOrNull(count(sa.local, r.hasMFA), len(sa.local), componentsdk.RoundDown)
	if len(sa.roots) == 0 {
		v[at+"/iam/root_mfa_enabled"] = nil
		v[at+"/iam/root_access_protected"] = nil
	} else {
		v[at+"/iam/root_mfa_enabled"] = !slices.ContainsFunc(sa.roots, func(root Account) bool { return !r.hasMFA(root) })
		v[at+"/iam/root_access_protected"] = !slices.ContainsFunc(sa.roots, func(root Account) bool {
			standing := r.signsInLocally(root) || slices.ContainsFunc(sa.credentials, func(m MachineCredential) bool { return m.Owner == root.Key })
			return !r.hasMFA(root) && standing
		})
	}
	owners := map[string][]MachineCredential{}
	for _, m := range sa.credentials {
		owner := "credential " + m.Key
		switch {
		case m.Owner != "":
			owner = "account " + m.Owner
		case m.App != "":
			owner = "app " + m.App
		}
		owners[owner] = append(owners[owner], m)
	}
	v[at+"/iam/access_key_user_count"] = len(owners)
	if sa.creationKnown() {
		rotated := count(sortedKeys(owners), func(owner string) bool {
			return !slices.ContainsFunc(owners[owner], rotationOverdue)
		})
		v[at+"/iam/access_key_rotation_compliant_pct"] = percentOrNull(rotated, len(owners), componentsdk.RoundDown)
	}
	v[at+"/iam/saml_provider_count"] = count(a.IdentityProviders, func(p IdentityProvider) bool { return r.Terms.CloudIdentityProviders[p.Kind] == IdPSAML })
}

// percentOrNull is n over total as a percentage, or nil over none.
func percentOrNull(n, total int, rounding componentsdk.Rounding) any {
	if p := componentsdk.Percent(n, total, rounding); p != nil {
		return *p
	}
	return nil
}

// cloudVulnScanning reads the scanning block's scope with the cloud
// account's ID. Vulnerability scanning is enabled when any of the scope's
// scanners is enabled there, as vuln-scanning gives it. The scanned
// resources are those a scanner lists as scanned, and an unpatched one has
// an open finding. An account with no scope in the block has no scanner.
func (r *Roster) cloudVulnScanning(id string) (enabled bool, scanned, unpatched int) {
	i := slices.IndexFunc(r.Scanning.Scopes, func(sc ScanScope) bool { return sc.ID == id })
	if i < 0 {
		return false, 0, 0
	}
	scope := r.Scanning.Scopes[i]
	enabled = slices.ContainsFunc(r.scanEntries(), func(e scanEntry) bool { return r.tallyScanner(e, scope).enabled })
	for _, res := range scope.Resources {
		if !slices.ContainsFunc(sortedKeys(res.Scans), func(scanner string) bool { return r.Terms.VulnScanStatuses[res.Scans[scanner]] == VulnScanned }) {
			continue
		}
		scanned++
		if slices.ContainsFunc(res.Findings, func(f VulnFinding) bool { return r.Terms.VulnFindingStates[f.State] == VulnOpen }) {
			unpatched++
		}
	}
	return enabled, scanned, unpatched
}
