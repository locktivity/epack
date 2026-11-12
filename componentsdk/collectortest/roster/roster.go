// Package roster reads a tenant's roster, the accounts, roles, sign-in
// policies and apps a sandbox or a simulated tenant holds, and derives from
// it the normalized values a collector must report for that tenant.
//
// A roster names everything in the vendor's own terms, such as a role called
// Global Administrator or an MFA method called mobilePhone, so a simulator
// can answer as the vendor would. Its terms block maps each vendor term to a
// normalized one, and Parse refuses a roster that uses a term the block does
// not map. Derive then reads only the normalized terms, so the values it
// gives follow the normalized schemas' definitions rather than any
// collector's code.
//
// The file format, version 1:
//
//	{
//	  "version": 1,
//	  "vendor": "microsoft-entra",
//	  "accounts": {"<key>": {"kind": "...", "enabled": true, "roles": [...],
//	    "eligible_roles": [...], "cloud_roles": [...],
//	    "partial_cloud_roles": [...], "mfa": "..." or [...],
//	    "signed_in_days_ago": 3, "state": "...", "password_strength": "...",
//	    "password_length": 12, "logins": "..." or [...],
//	    "cloud_account": "<cloud account key>",
//	    "cloud_access": {"<cloud account key>": {"roles": [...], "partial_roles": [...]}}}},
//	  "groups": {"<key>": {"members": [...], "roles": [...], "cloud_roles": [...],
//	    "cloud_access": {...}}},
//	  "sign_in_policies": {"<key>": {"state": "...", "include": "all" or
//	    {"accounts": [...], "groups": [...], "roles": [...]}, "exclude": {...},
//	    "apps": "all" or [...], "exclude_apps": [...],
//	    "requires": "..." or [...] or {"any": [...]}, "blocks": "...",
//	    "conditions": [...], "session_lifetime_minutes": 720,
//	    "idle_timeout_minutes": 60}},
//	  "apps": {"<key>": {"enabled": true, "sso_mode": "...",
//	    "publisher": "...", "provisioning": "..." or [...], "cloud_roles": [...],
//	    "credentials": {"<key>": {"kind": "...", "start": "...", "end": "..."}}}},
//	  "security_groups": {"<key>": {"cloud_account": "...",
//	    "rules": {"<key>": {"direction": "inbound",
//	    "access": "allow", "protocol": "...", "ports": ["22", "1000-2000", "*"],
//	    "sources": [...], "priority": 100}}}},
//	  "storage": {"<key>": {"key_source": "...", "anonymous_access": false,
//	    "cloud_account": "...", "network_access": "...", "allowed_sources": [...],
//	    "backup_retention_days": 7}},
//	  "directory": {...}, "cloud": {...},
//	  "providers": {"<schema short name>": "..."},
//	  "endpoint": {...}, "scanning": {...}, "vcs": {...}, "tls": {...},
//	  "email_dns": {...},
//	  "terms": {"account_kinds": {...}, "mfa_methods": {...}, "roles": {...},
//	    "cloud_roles": {...}, "policy_states": {...}, "requirements": {...},
//	    "blocks": {...}, "sso_modes": {...}, "protocols": {...},
//	    "network_sources": {...}, "key_sources": {...},
//	    "account_states": {...}, "password_strengths": {...},
//	    "login_methods": {...}, "app_publishers": {...},
//	    "provisioning_features": {...},
//	    "conditions": {"<condition>": {"<part>": [...]}}},
//	  "unsettled": {"<account key>": ["mfa", "signed_in"]}
//	}
//
// Any other field of an entry, or of the file, is a vendor extra that Parse
// keeps for the vendor's simulator and Derive never reads. An account with no
// signed_in_days_ago has never signed in. A policy's requires lists what a
// sign-in it covers must satisfy: all of a list, or one of an "any" list. Its
// conditions are vendor conditions, such as a sign-in risk level, that limit
// it to some sign-ins.
//
// A condition terms.conditions maps limits a policy to the sign-ins whose
// parts take the values listed there. The parts are the client (browser,
// apps for mobile and desktop apps with modern sign-in, mail_sync for legacy
// mail sync such as Exchange ActiveSync, and legacy for other legacy
// clients), the device platform (android, ios, windows, windows_phone,
// macos, linux, or other for one the vendor doesn't recognize), the location
// (trusted or untrusted), and the sign-in and user risk (none, low, medium,
// high). Any other condition limits a policy in a way Derive doesn't
// follow. A policy that blocks legacy authentication covers mail_sync and
// legacy clients only.
//
// The cloud side is one subscription or account. Its members are the
// accounts that hold a cloud role, directly or through a group, over the
// whole subscription or on part of it, such as one resource group. An
// account's partial_cloud_roles are those it holds on part of it only. A security
// group's rules are in priority order, lowest first, and the first rule a
// connection matches decides it. Rules with no priority are unordered, and
// any allow rule lets a connection in, as with a vendor that has no deny
// rules. A storage resource's key source is how its data is encrypted at
// rest, and anonymous_access whether anyone can read its data without
// signing in.
//
// An account's kind is a person in the organization (member), a person
// from outside it (guest), an account a program uses (service), or a
// built-in account that bypasses normal administration, such as the AWS
// root user (root). An account with a cloud_account is a local account of
// that cloud account, such as an AWS IAM user or the root user, rather than
// one in the identity provider's directory, and the identity side doesn't
// count it. Its cloud_roles and partial_cloud_roles are in that cloud
// account. cloud_access gives the roles an account or group holds in each of
// several cloud accounts.
//
// directory and cloud say more about the identity and cloud sides, in the
// formats Directory and Cloud document. Without a directory block, Derive
// gives none of the identity side's values that need one: the domain,
// account states, passwords, app provisioning and publishers, and session
// limits. Without a cloud block, the cloud side is one account with no ID,
// and Derive gives only its network and storage counts and its members and
// admins. A roster with either block describes that side fully, so an
// account with no state is in none of the states the schemas count, an app
// with no publisher is the organization's own, and a cloud account with no
// audit log has none.
//
// An account's state, password_strength and logins are vendor terms, mapped
// in account_states (locked_out, archived, or other), password_strengths
// (weak or strong) and login_methods (sso, or local for a password, a social
// login or any other way in that skips SSO). password_length is the length
// of its password, left out when it has none in the directory. An app's
// publisher is mapped in app_publishers (organization, provider for the
// identity provider's own apps, or third_party), and each of its
// provisioning features in provisioning_features (create, deactivate, or
// other). A policy's session_lifetime_minutes and idle_timeout_minutes are
// the session limits it sets, left out when it sets none. A storage
// resource's network_access is mapped in the cloud block's terms, and its
// allowed_sources, the networks a limited one lets in, in network_sources.
//
// providers gives the provider value of each normalized schema, by the
// schema's short name, such as idp-posture. endpoint, scanning, vcs, tls and
// email_dns each describe one more part of a tenant, in the format the
// matching type documents: Endpoint, Scanning, VCS, Hosts and MailDomains.
// Their terms are in the terms block with the others.
package roster

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"
)

// Normalized terms.
const (
	KindMember  = "member"
	KindGuest   = "guest"
	KindService = "service"
	KindRoot    = "root"

	// AccountOther is any account state the schemas don't count apart, such
	// as active or suspended.
	AccountLockedOut = "locked_out"
	AccountArchived  = "archived"
	AccountOther     = "other"

	PasswordWeak   = "weak"
	PasswordStrong = "strong"

	// LoginLocal is any way to sign in that skips SSO, such as a password or
	// a social login.
	LoginSSO   = "sso"
	LoginLocal = "local"

	// PublisherProvider is the identity provider's vendor, such as Microsoft
	// for its own apps in Entra.
	PublisherOrganization = "organization"
	PublisherProvider     = "provider"
	PublisherThirdParty   = "third_party"

	// ProvisionCreate creates accounts in the app, and ProvisionDeactivate
	// removes access when the directory deprovisions a user.
	ProvisionCreate     = "create"
	ProvisionDeactivate = "deactivate"
	ProvisionOther      = "other"

	MFANone              = "none"
	MFA                  = "mfa"
	MFAPhishingResistant = "phishing_resistant"

	RoleSuperAdmin = "super_admin"
	RoleAdmin      = "admin"
	RoleNone       = "none"

	StateEnforced   = "enforced"
	StateReportOnly = "report_only"
	StateOff        = "off"

	RequiresMFA                  = "mfa"
	RequiresPhishingResistantMFA = "phishing_resistant_mfa"
	RequiresManagedDevice        = "managed_device"
	// RequiresOther is a requirement that is none of the others, such as
	// accepting terms of use.
	RequiresOther = "other"

	BlocksLegacyAuth = "legacy_auth"

	PartClient     = "client"
	PartPlatform   = "platform"
	PartLocation   = "location"
	PartSignInRisk = "sign_in_risk"
	PartUserRisk   = "user_risk"

	ClientBrowser  = "browser"
	ClientApps     = "apps"
	ClientMailSync = "mail_sync"
	ClientLegacy   = "legacy"

	SSO   = "sso"
	NoSSO = "none"

	Inbound  = "inbound"
	Outbound = "outbound"
	Allow    = "allow"
	Deny     = "deny"

	ProtocolTCP = "tcp"
	ProtocolUDP = "udp"
	ProtocolAny = "any"

	// SourceAny is a source that holds every address, such as 0.0.0.0/0,
	// and SourceLimited one that holds only some.
	SourceAny     = "any"
	SourceLimited = "limited"

	ProviderKey = "provider_key"
	CustomerKey = "customer_key"
	NoKey       = "none"
)

// Roster is a tenant in the vendor's terms, with the map to normalized ones.
type Roster struct {
	Version  int
	Vendor   string
	Accounts []Account
	Groups   []Group
	Policies []Policy
	Apps     []App
	// SecurityGroups and Storage are the cloud side's network rules and
	// storage resources.
	SecurityGroups []SecurityGroup
	Storage        []Storage
	// Directory and Cloud say more of the identity and cloud sides. Each is
	// nil when the roster leaves it out.
	Directory *Directory
	Cloud     *Cloud
	// Providers gives each normalized schema's provider value, by the
	// schema's short name.
	Providers map[string]string
	// Endpoint, Scanning, VCS, Hosts and MailDomains are the parts of a
	// tenant beyond its identity and cloud sides. Each is nil when the roster
	// leaves it out.
	Endpoint    *Endpoint
	Scanning    *Scanning
	VCS         *VCS
	Hosts       *Hosts
	MailDomains *MailDomains
	Terms       Terms
	// Unsettled lists, by account key, the attributes a live tenant has not
	// yet shown, mfa or signed_in. Realizations and Settle take each both
	// ways.
	Unsettled map[string][]string
	Extra     Extra
}

// Account is a user account.
type Account struct {
	Key     string
	Kind    string
	Enabled bool
	// Roles are the directory roles the account holds now and at all times.
	// Roles held through a group are on the Group.
	Roles []string
	// EligibleRoles are roles the account can activate and does not hold.
	EligibleRoles []string
	// CloudRoles are held over the whole subscription or account, and
	// PartialCloudRoles on part of it only, such as one resource group.
	CloudRoles        []string
	PartialCloudRoles []string
	// Methods are the MFA methods the account has registered.
	Methods []string
	// SignedInDaysAgo is the age of the account's last successful sign-in,
	// or nil when it has never signed in.
	SignedInDaysAgo *int
	// State is the vendor's account state, such as LOCKED_OUT, or empty for
	// none the schemas count apart.
	State string
	// PasswordStrength is the vendor's rating of the account's password, and
	// PasswordLength its length, nil when it has no password in the
	// directory.
	PasswordStrength string
	PasswordLength   *int
	// Logins are the ways the account can sign in to the cloud side, or reach
	// a vcs block's organization.
	Logins []string
	// CloudAccount is the cloud account the account is local to, or empty
	// for an account in the directory.
	CloudAccount string
	// CloudAccess gives the cloud roles the account holds in each cloud
	// account, by its key.
	CloudAccess map[string]CloudGrant
	Extra       Extra
}

// CloudGrant is the cloud roles held in one cloud account: over the whole of
// it, and on part of it only.
type CloudGrant struct {
	Roles        []string
	PartialRoles []string
}

// Group is a group whose members hold its roles.
type Group struct {
	Key         string
	Members     []string
	Roles       []string
	CloudRoles  []string
	CloudAccess map[string]CloudGrant
	Extra       Extra
}

// SecurityGroup is a set of network rules.
type SecurityGroup struct {
	Key          string
	CloudAccount string
	Rules        []NetworkRule
	Extra        Extra
}

// NetworkRule allows or denies connections in or out.
type NetworkRule struct {
	Key       string
	Direction string
	Access    string
	Protocol  string
	// Ports lists ports and ranges, such as 22 or 1000-2000, or * for every
	// port.
	Ports    []string
	Sources  []string
	Priority int
	Extra    Extra
}

// Storage is a storage resource, such as a bucket or a storage account.
type Storage struct {
	Key             string
	KeySource       string
	AnonymousAccess bool
	CloudAccount    string
	// NetworkAccess is whether the public internet can connect, in the
	// vendor's terms, and AllowedSources the networks a limited one lets in.
	NetworkAccess  string
	AllowedSources []string
	// BackupRetentionDays is how long its backups are kept, or nil when it
	// has none.
	BackupRetentionDays *int
	Extra               Extra
}

// Policy is a sign-in policy.
type Policy struct {
	Key     string
	State   string
	Include Audience
	Exclude Audience
	// Apps lists the vendor apps the policy covers. Empty means every app
	// but those in ExcludeApps.
	Apps        []string
	ExcludeApps []string
	// Requires lists what a sign-in the policy covers must satisfy: all of
	// them, or any one when RequireAny is set.
	Requires   []string
	RequireAny bool
	Blocks     string
	Conditions []string
	// SessionLifetimeMinutes and IdleTimeoutMinutes are the session limits
	// the policy sets, or nil when it sets none.
	SessionLifetimeMinutes *int
	IdleTimeoutMinutes     *int
	Extra                  Extra
}

// Audience is who a policy includes or excludes.
type Audience struct {
	All      bool
	Accounts []string
	Groups   []string
	Roles    []string
}

// App is an app connected to the identity provider.
type App struct {
	Key     string
	Enabled bool
	SSOMode string
	// Publisher is who publishes the app, and Provisioning the provisioning
	// features turned on for it, in the vendor's terms.
	Publisher    string
	Provisioning []string
	// CloudRoles are the cloud roles the app holds anywhere on the cloud
	// side.
	CloudRoles  []string
	Credentials []Credential
	Extra       Extra
}

// Credential is an app's secret or certificate.
type Credential struct {
	Key   string
	Kind  string
	Start string
	End   string
	Extra Extra
}

// Terms maps each vendor term a roster uses to its normalized term.
type Terms struct {
	AccountKinds   map[string]string `json:"account_kinds"`
	MFAMethods     map[string]string `json:"mfa_methods"`
	Roles          map[string]string `json:"roles"`
	CloudRoles     map[string]string `json:"cloud_roles"`
	PolicyStates   map[string]string `json:"policy_states"`
	Requirements   map[string]string `json:"requirements"`
	Blocks         map[string]string `json:"blocks"`
	SSOModes       map[string]string `json:"sso_modes"`
	Protocols      map[string]string `json:"protocols"`
	NetworkSources map[string]string `json:"network_sources"`
	KeySources     map[string]string `json:"key_sources"`
	// Conditions maps a policy condition to the values of each part of a
	// sign-in it limits the policy to.
	Conditions           map[string]map[string][]string `json:"conditions"`
	AccountStates        map[string]string              `json:"account_states"`
	PasswordStrengths    map[string]string              `json:"password_strengths"`
	LoginMethods         map[string]string              `json:"login_methods"`
	AppPublishers        map[string]string              `json:"app_publishers"`
	ProvisioningFeatures map[string]string              `json:"provisioning_features"`
	CloudTerms
	EndpointTerms
	ScanningTerms
	VCSTerms
	HostsTerms
	MailDomainsTerms
}

// Extra holds an entry's vendor fields by name.
type Extra map[string]json.RawMessage

// Get decodes the vendor field name into v and reports whether it is set.
func (e Extra) Get(name string, v any) (bool, error) {
	raw, ok := e[name]
	if !ok {
		return false, nil
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return true, fmt.Errorf("vendor field %s: %w", name, err)
	}
	return true, nil
}

// Load reads and parses the roster file at path.
func Load(path string) (*Roster, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	r, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return r, nil
}

// Parse reads a roster and validates it.
func Parse(data []byte) (*Roster, error) {
	var file struct {
		Version   int                        `json:"version"`
		Vendor    string                     `json:"vendor"`
		Accounts  map[string]json.RawMessage `json:"accounts"`
		Groups    map[string]json.RawMessage `json:"groups"`
		Policies  map[string]json.RawMessage `json:"sign_in_policies"`
		Apps      map[string]json.RawMessage `json:"apps"`
		SecGroups map[string]json.RawMessage `json:"security_groups"`
		Storage   map[string]json.RawMessage `json:"storage"`
		Directory json.RawMessage            `json:"directory"`
		Cloud     json.RawMessage            `json:"cloud"`
		Providers map[string]string          `json:"providers"`
		Terms     *Terms                     `json:"terms"`
		Unsettled map[string][]string        `json:"unsettled"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	if file.Version != 1 {
		return nil, fmt.Errorf("roster version %d, want 1", file.Version)
	}
	if file.Terms == nil {
		return nil, fmt.Errorf("roster has no terms block")
	}
	r := &Roster{Version: file.Version, Vendor: file.Vendor, Providers: file.Providers, Terms: *file.Terms, Unsettled: file.Unsettled}
	known := append([]string{"version", "vendor", "accounts", "groups", "sign_in_policies", "apps", "security_groups", "storage", "directory", "cloud", "providers", "terms", "unsettled"}, domainKeys()...)
	var err error
	if r.Extra, err = extra(data, known...); err != nil {
		return nil, err
	}
	if len(file.Directory) > 0 {
		if r.Directory, err = parseDirectory(file.Directory); err != nil {
			return nil, fmt.Errorf("directory: %w", err)
		}
	}
	if len(file.Cloud) > 0 {
		if r.Cloud, err = parseCloud(file.Cloud); err != nil {
			return nil, fmt.Errorf("cloud: %w", err)
		}
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, err
	}
	for _, d := range domains {
		if raw, ok := top[d.key]; ok {
			if err := d.parse(r, raw); err != nil {
				return nil, fmt.Errorf("%s: %w", d.key, err)
			}
		}
	}
	for _, key := range sortedKeys(file.Accounts) {
		a, err := parseAccount(key, file.Accounts[key])
		if err != nil {
			return nil, err
		}
		r.Accounts = append(r.Accounts, a)
	}
	for _, key := range sortedKeys(file.Groups) {
		var g struct {
			Members     []string                   `json:"members"`
			Roles       []string                   `json:"roles"`
			CloudRoles  []string                   `json:"cloud_roles"`
			CloudAccess map[string]json.RawMessage `json:"cloud_access"`
		}
		if err := json.Unmarshal(file.Groups[key], &g); err != nil {
			return nil, fmt.Errorf("group %s: %w", key, err)
		}
		e, err := extra(file.Groups[key], "members", "roles", "cloud_roles", "cloud_access")
		if err != nil {
			return nil, fmt.Errorf("group %s: %w", key, err)
		}
		access, err := parseCloudAccess(g.CloudAccess)
		if err != nil {
			return nil, fmt.Errorf("group %s: %w", key, err)
		}
		r.Groups = append(r.Groups, Group{Key: key, Members: g.Members, Roles: g.Roles, CloudRoles: g.CloudRoles, CloudAccess: access, Extra: e})
	}
	for _, key := range sortedKeys(file.Policies) {
		p, err := parsePolicy(key, file.Policies[key])
		if err != nil {
			return nil, err
		}
		r.Policies = append(r.Policies, p)
	}
	for _, key := range sortedKeys(file.Apps) {
		a, err := parseApp(key, file.Apps[key])
		if err != nil {
			return nil, err
		}
		r.Apps = append(r.Apps, a)
	}
	for _, key := range sortedKeys(file.SecGroups) {
		g, err := parseSecurityGroup(key, file.SecGroups[key])
		if err != nil {
			return nil, err
		}
		r.SecurityGroups = append(r.SecurityGroups, g)
	}
	for _, key := range sortedKeys(file.Storage) {
		var st struct {
			KeySource       string   `json:"key_source"`
			AnonymousAccess bool     `json:"anonymous_access"`
			CloudAccount    string   `json:"cloud_account"`
			NetworkAccess   string   `json:"network_access"`
			AllowedSources  []string `json:"allowed_sources"`
			BackupRetention *int     `json:"backup_retention_days"`
		}
		if err := json.Unmarshal(file.Storage[key], &st); err != nil {
			return nil, fmt.Errorf("storage %s: %w", key, err)
		}
		e, err := extra(file.Storage[key], "key_source", "anonymous_access", "cloud_account", "network_access", "allowed_sources", "backup_retention_days")
		if err != nil {
			return nil, fmt.Errorf("storage %s: %w", key, err)
		}
		r.Storage = append(r.Storage, Storage{Key: key, KeySource: st.KeySource, AnonymousAccess: st.AnonymousAccess, CloudAccount: st.CloudAccount,
			NetworkAccess: st.NetworkAccess, AllowedSources: st.AllowedSources, BackupRetentionDays: st.BackupRetention, Extra: e})
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

func parseSecurityGroup(key string, raw json.RawMessage) (SecurityGroup, error) {
	var g struct {
		CloudAccount string                     `json:"cloud_account"`
		Rules        map[string]json.RawMessage `json:"rules"`
	}
	if err := json.Unmarshal(raw, &g); err != nil {
		return SecurityGroup{}, fmt.Errorf("security group %s: %w", key, err)
	}
	out := SecurityGroup{Key: key, CloudAccount: g.CloudAccount}
	var err error
	if out.Extra, err = extra(raw, "cloud_account", "rules"); err != nil {
		return SecurityGroup{}, fmt.Errorf("security group %s: %w", key, err)
	}
	for _, rk := range sortedKeys(g.Rules) {
		var rule struct {
			Direction string   `json:"direction"`
			Access    string   `json:"access"`
			Protocol  string   `json:"protocol"`
			Ports     []string `json:"ports"`
			Sources   []string `json:"sources"`
			Priority  int      `json:"priority"`
		}
		if err := json.Unmarshal(g.Rules[rk], &rule); err != nil {
			return SecurityGroup{}, fmt.Errorf("security group %s rule %s: %w", key, rk, err)
		}
		re, err := extra(g.Rules[rk], "direction", "access", "protocol", "ports", "sources", "priority")
		if err != nil {
			return SecurityGroup{}, fmt.Errorf("security group %s rule %s: %w", key, rk, err)
		}
		out.Rules = append(out.Rules, NetworkRule{Key: rk, Direction: rule.Direction, Access: rule.Access, Protocol: rule.Protocol,
			Ports: rule.Ports, Sources: rule.Sources, Priority: rule.Priority, Extra: re})
	}
	return out, nil
}

func parseAccount(key string, raw json.RawMessage) (Account, error) {
	var a struct {
		Kind            string                     `json:"kind"`
		Enabled         *bool                      `json:"enabled"`
		Roles           []string                   `json:"roles"`
		EligibleRoles   []string                   `json:"eligible_roles"`
		CloudRoles      []string                   `json:"cloud_roles"`
		PartialRoles    []string                   `json:"partial_cloud_roles"`
		MFA             oneOrMore                  `json:"mfa"`
		SignedInDaysAgo *int                       `json:"signed_in_days_ago"`
		State           string                     `json:"state"`
		PasswordRating  string                     `json:"password_strength"`
		PasswordLength  *int                       `json:"password_length"`
		Logins          oneOrMore                  `json:"logins"`
		CloudAccount    string                     `json:"cloud_account"`
		CloudAccess     map[string]json.RawMessage `json:"cloud_access"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return Account{}, fmt.Errorf("account %s: %w", key, err)
	}
	if a.Enabled == nil {
		return Account{}, fmt.Errorf("account %s has no enabled", key)
	}
	e, err := extra(raw, "kind", "enabled", "roles", "eligible_roles", "cloud_roles", "partial_cloud_roles", "mfa", "signed_in_days_ago",
		"state", "password_strength", "password_length", "logins", "cloud_account", "cloud_access")
	if err != nil {
		return Account{}, fmt.Errorf("account %s: %w", key, err)
	}
	access, err := parseCloudAccess(a.CloudAccess)
	if err != nil {
		return Account{}, fmt.Errorf("account %s: %w", key, err)
	}
	return Account{
		Key: key, Kind: a.Kind, Enabled: *a.Enabled, Roles: a.Roles, EligibleRoles: a.EligibleRoles,
		CloudRoles: a.CloudRoles, PartialCloudRoles: a.PartialRoles, Methods: a.MFA, SignedInDaysAgo: a.SignedInDaysAgo,
		State: a.State, PasswordStrength: a.PasswordRating, PasswordLength: a.PasswordLength, Logins: a.Logins,
		CloudAccount: a.CloudAccount, CloudAccess: access, Extra: e,
	}, nil
}

// parseCloudAccess reads cloud_access, the roles held in each cloud account.
func parseCloudAccess(raw map[string]json.RawMessage) (map[string]CloudGrant, error) {
	if raw == nil {
		return nil, nil
	}
	out := map[string]CloudGrant{}
	for _, key := range sortedKeys(raw) {
		var g struct {
			Roles        []string `json:"roles"`
			PartialRoles []string `json:"partial_roles"`
		}
		dec := json.NewDecoder(bytes.NewReader(raw[key]))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&g); err != nil {
			return nil, fmt.Errorf("cloud_access %s: want an object of roles and partial_roles: %w", key, err)
		}
		out[key] = CloudGrant{Roles: g.Roles, PartialRoles: g.PartialRoles}
	}
	return out, nil
}

func parsePolicy(key string, raw json.RawMessage) (Policy, error) {
	var p struct {
		State       string          `json:"state"`
		Include     json.RawMessage `json:"include"`
		Exclude     json.RawMessage `json:"exclude"`
		Apps        json.RawMessage `json:"apps"`
		ExcludeApps []string        `json:"exclude_apps"`
		Requires    json.RawMessage `json:"requires"`
		Blocks      string          `json:"blocks"`
		Conditions  []string        `json:"conditions"`
		Lifetime    *int            `json:"session_lifetime_minutes"`
		Idle        *int            `json:"idle_timeout_minutes"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return Policy{}, fmt.Errorf("policy %s: %w", key, err)
	}
	include, err := parseAudience(p.Include)
	if err != nil {
		return Policy{}, fmt.Errorf("policy %s include: %w", key, err)
	}
	exclude, err := parseAudience(p.Exclude)
	if err != nil {
		return Policy{}, fmt.Errorf("policy %s exclude: %w", key, err)
	}
	var apps []string
	if len(p.Apps) > 0 && string(p.Apps) != `"all"` {
		if err := json.Unmarshal(p.Apps, &apps); err != nil || len(apps) == 0 {
			return Policy{}, fmt.Errorf(`policy %s: apps is "all" or a list of apps`, key)
		}
	}
	requires, requireAny, err := parseRequires(p.Requires)
	if err != nil {
		return Policy{}, fmt.Errorf("policy %s: %w", key, err)
	}
	e, err := extra(raw, "state", "include", "exclude", "apps", "exclude_apps", "requires", "blocks", "conditions", "session_lifetime_minutes", "idle_timeout_minutes")
	if err != nil {
		return Policy{}, fmt.Errorf("policy %s: %w", key, err)
	}
	return Policy{
		Key: key, State: p.State, Include: include, Exclude: exclude, Apps: apps, ExcludeApps: p.ExcludeApps,
		Requires: requires, RequireAny: requireAny, Blocks: p.Blocks, Conditions: p.Conditions,
		SessionLifetimeMinutes: p.Lifetime, IdleTimeoutMinutes: p.Idle, Extra: e,
	}, nil
}

func parseRequires(raw json.RawMessage) ([]string, bool, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, false, nil
	}
	if raw[0] == '{' {
		var oneOf struct {
			Any []string `json:"any"`
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&oneOf); err != nil || len(oneOf.Any) == 0 {
			return nil, false, fmt.Errorf(`requires is a requirement, a list of them, or {"any": [...]}`)
		}
		return oneOf.Any, true, nil
	}
	var all oneOrMore
	if err := json.Unmarshal(raw, &all); err != nil {
		return nil, false, fmt.Errorf(`requires is a requirement, a list of them, or {"any": [...]}`)
	}
	return all, false, nil
}

func parseAudience(raw json.RawMessage) (Audience, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return Audience{}, nil
	}
	if string(raw) == `"all"` {
		return Audience{All: true}, nil
	}
	var a struct {
		Accounts []string `json:"accounts"`
		Groups   []string `json:"groups"`
		Roles    []string `json:"roles"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return Audience{}, fmt.Errorf(`want "all" or an object of accounts, groups and roles: %w`, err)
	}
	return Audience{Accounts: a.Accounts, Groups: a.Groups, Roles: a.Roles}, nil
}

func parseApp(key string, raw json.RawMessage) (App, error) {
	var a struct {
		Enabled      *bool                      `json:"enabled"`
		SSOMode      string                     `json:"sso_mode"`
		Publisher    string                     `json:"publisher"`
		Provisioning oneOrMore                  `json:"provisioning"`
		CloudRoles   []string                   `json:"cloud_roles"`
		Credentials  map[string]json.RawMessage `json:"credentials"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return App{}, fmt.Errorf("app %s: %w", key, err)
	}
	out := App{Key: key, Enabled: a.Enabled == nil || *a.Enabled, SSOMode: a.SSOMode, Publisher: a.Publisher, Provisioning: a.Provisioning, CloudRoles: a.CloudRoles}
	var err error
	if out.Extra, err = extra(raw, "enabled", "sso_mode", "publisher", "provisioning", "cloud_roles", "credentials"); err != nil {
		return App{}, fmt.Errorf("app %s: %w", key, err)
	}
	for _, ck := range sortedKeys(a.Credentials) {
		var c struct {
			Kind  string `json:"kind"`
			Start string `json:"start"`
			End   string `json:"end"`
		}
		if err := json.Unmarshal(a.Credentials[ck], &c); err != nil {
			return App{}, fmt.Errorf("app %s credential %s: %w", key, ck, err)
		}
		ce, err := extra(a.Credentials[ck], "kind", "start", "end")
		if err != nil {
			return App{}, fmt.Errorf("app %s credential %s: %w", key, ck, err)
		}
		out.Credentials = append(out.Credentials, Credential{Key: ck, Kind: c.Kind, Start: c.Start, End: c.End, Extra: ce})
	}
	return out, nil
}

// Validate checks that the terms block maps every vendor term the roster
// uses to a normalized term, and that every key an entry names exists. Call
// it after changing a roster in code.
func (r *Roster) Validate() error {
	t := r.Terms
	for name, m := range map[string]struct {
		terms map[string]string
		allow []string
	}{
		"account_kinds":         {t.AccountKinds, []string{KindMember, KindGuest, KindService, KindRoot}},
		"account_states":        {t.AccountStates, []string{AccountLockedOut, AccountArchived, AccountOther}},
		"password_strengths":    {t.PasswordStrengths, []string{PasswordWeak, PasswordStrong}},
		"login_methods":         {t.LoginMethods, []string{LoginSSO, LoginLocal}},
		"app_publishers":        {t.AppPublishers, []string{PublisherOrganization, PublisherProvider, PublisherThirdParty}},
		"provisioning_features": {t.ProvisioningFeatures, []string{ProvisionCreate, ProvisionDeactivate, ProvisionOther}},
		"mfa_methods":           {t.MFAMethods, []string{MFANone, MFA, MFAPhishingResistant}},
		"roles":                 {t.Roles, []string{RoleSuperAdmin, RoleAdmin, RoleNone}},
		"cloud_roles":           {t.CloudRoles, []string{RoleAdmin, RoleNone}},
		"policy_states":         {t.PolicyStates, []string{StateEnforced, StateReportOnly, StateOff}},
		"requirements":          {t.Requirements, []string{RequiresMFA, RequiresPhishingResistantMFA, RequiresManagedDevice, RequiresOther}},
		"blocks":                {t.Blocks, []string{BlocksLegacyAuth}},
		"sso_modes":             {t.SSOModes, []string{SSO, NoSSO}},
		"protocols":             {t.Protocols, []string{ProtocolTCP, ProtocolUDP, ProtocolAny}},
		"network_sources":       {t.NetworkSources, []string{SourceAny, SourceLimited}},
		"key_sources":           {t.KeySources, []string{ProviderKey, CustomerKey, NoKey}},
	} {
		for _, vendor := range sortedKeys(m.terms) {
			if !slices.Contains(m.allow, m.terms[vendor]) {
				return fmt.Errorf("terms.%s maps %q to %q, which is none of %v", name, vendor, m.terms[vendor], m.allow)
			}
		}
	}
	for _, condition := range sortedKeys(t.Conditions) {
		for _, part := range sortedKeys(t.Conditions[condition]) {
			values, ok := signInParts[part]
			if !ok {
				return fmt.Errorf("terms.conditions.%s limits %q, which is no part of a sign-in; the parts are %v", condition, part, sortedKeys(signInParts))
			}
			for _, v := range t.Conditions[condition][part] {
				if !slices.Contains(values, v) {
					return fmt.Errorf("terms.conditions.%s limits %s to %q, which is none of %v", condition, part, v, values)
				}
			}
		}
	}

	accounts := map[string]bool{}
	for _, a := range r.Accounts {
		if accounts[a.Key] {
			return fmt.Errorf("account %s is listed twice", a.Key)
		}
		accounts[a.Key] = true
		if err := mapped(t.AccountKinds, "account_kinds", "account "+a.Key+" kind", a.Kind); err != nil {
			return err
		}
		if err := mapped(t.MFAMethods, "mfa_methods", "account "+a.Key+" mfa", a.Methods...); err != nil {
			return err
		}
		if err := mapped(t.Roles, "roles", "account "+a.Key+" role", append(slices.Clone(a.Roles), a.EligibleRoles...)...); err != nil {
			return err
		}
		if err := mapped(t.CloudRoles, "cloud_roles", "account "+a.Key+" cloud role", append(slices.Clone(a.CloudRoles), a.PartialCloudRoles...)...); err != nil {
			return err
		}
		if a.SignedInDaysAgo != nil && *a.SignedInDaysAgo < 0 {
			return fmt.Errorf("account %s signed in %d days from now", a.Key, *a.SignedInDaysAgo)
		}
		if err := r.validateAccountFacts(a); err != nil {
			return err
		}
	}
	groups := map[string]bool{}
	for _, g := range r.Groups {
		groups[g.Key] = true
		if err := known(accounts, "group "+g.Key+" member", g.Members...); err != nil {
			return err
		}
		if err := mapped(t.Roles, "roles", "group "+g.Key+" role", g.Roles...); err != nil {
			return err
		}
		if err := mapped(t.CloudRoles, "cloud_roles", "group "+g.Key+" cloud role", g.CloudRoles...); err != nil {
			return err
		}
		if len(g.CloudRoles) > 0 {
			if err := r.placed("group "+g.Key+" cloud_roles", ""); err != nil {
				return err
			}
		}
		if err := r.validateCloudAccess("group "+g.Key, g.CloudAccess); err != nil {
			return err
		}
	}
	for _, g := range r.SecurityGroups {
		if err := r.placed("security group "+g.Key, g.CloudAccount); err != nil {
			return err
		}
		for _, rule := range g.Rules {
			what := "security group " + g.Key + " rule " + rule.Key
			if (rule.Direction != Inbound && rule.Direction != Outbound) || (rule.Access != Allow && rule.Access != Deny) {
				return fmt.Errorf("%s: direction is %s or %s, and access %s or %s", what, Inbound, Outbound, Allow, Deny)
			}
			if err := mapped(t.Protocols, "protocols", what+" protocol", rule.Protocol); err != nil {
				return err
			}
			if err := mapped(t.NetworkSources, "network_sources", what+" source", rule.Sources...); err != nil {
				return err
			}
			for _, port := range rule.Ports {
				if _, _, ok := portRange(port); !ok {
					return fmt.Errorf("%s: port %q is no port, range, or *", what, port)
				}
			}
		}
	}
	for _, st := range r.Storage {
		if err := mapped(t.KeySources, "key_sources", "storage "+st.Key+" key source", st.KeySource); err != nil {
			return err
		}
		if err := r.placed("storage "+st.Key, st.CloudAccount); err != nil {
			return err
		}
		if err := r.validateNetworkAccess("storage "+st.Key, st.NetworkAccess, st.AllowedSources); err != nil {
			return err
		}
		if st.BackupRetentionDays != nil && *st.BackupRetentionDays <= 0 {
			return fmt.Errorf("storage %s keeps backups %d days; leave backup_retention_days out for none", st.Key, *st.BackupRetentionDays)
		}
	}
	for _, p := range r.Policies {
		if err := mapped(t.PolicyStates, "policy_states", "policy "+p.Key+" state", p.State); err != nil {
			return err
		}
		if err := mapped(t.Requirements, "requirements", "policy "+p.Key+" requires", p.Requires...); err != nil {
			return err
		}
		if p.Blocks != "" {
			if err := mapped(t.Blocks, "blocks", "policy "+p.Key+" blocks", p.Blocks); err != nil {
				return err
			}
		}
		for name, minutes := range map[string]*int{"session_lifetime_minutes": p.SessionLifetimeMinutes, "idle_timeout_minutes": p.IdleTimeoutMinutes} {
			if minutes != nil && *minutes <= 0 {
				return fmt.Errorf("policy %s %s is %d; leave it out when the policy sets no limit", p.Key, name, *minutes)
			}
		}
		for _, aud := range []Audience{p.Include, p.Exclude} {
			if err := known(accounts, "policy "+p.Key+" account", aud.Accounts...); err != nil {
				return err
			}
			if err := known(groups, "policy "+p.Key+" group", aud.Groups...); err != nil {
				return err
			}
			if err := mapped(t.Roles, "roles", "policy "+p.Key+" role", aud.Roles...); err != nil {
				return err
			}
		}
	}
	for _, a := range r.Apps {
		if err := mapped(t.ProvisioningFeatures, "provisioning_features", "app "+a.Key+" provisioning", a.Provisioning...); err != nil {
			return err
		}
		if err := mapped(t.CloudRoles, "cloud_roles", "app "+a.Key+" cloud role", a.CloudRoles...); err != nil {
			return err
		}
		if a.Publisher != "" {
			if err := mapped(t.AppPublishers, "app_publishers", "app "+a.Key+" publisher", a.Publisher); err != nil {
				return err
			}
		}
		if a.SSOMode == "" {
			continue
		}
		if err := mapped(t.SSOModes, "sso_modes", "app "+a.Key+" sso_mode", a.SSOMode); err != nil {
			return err
		}
	}
	if err := r.validateDirectory(); err != nil {
		return fmt.Errorf("directory: %w", err)
	}
	if err := r.validateCloud(accounts); err != nil {
		return fmt.Errorf("cloud: %w", err)
	}
	if r.VCS != nil && r.hasCloud() {
		return fmt.Errorf("the roster has a cloud side and a vcs block, and access-posture describes one system; give each its own roster")
	}
	for _, short := range sortedKeys(r.Providers) {
		if _, ok := schemaIDs[short]; !ok {
			return fmt.Errorf("providers names %s, which is none of the normalized schemas %v", short, sortedKeys(schemaIDs))
		}
	}
	for _, d := range domains {
		if err := d.validate(r); err != nil {
			return fmt.Errorf("%s: %w", d.key, err)
		}
	}
	for _, key := range sortedKeys(r.Unsettled) {
		if !accounts[key] {
			return fmt.Errorf("unsettled names %s, which is no account", key)
		}
		for _, attr := range r.Unsettled[key] {
			if attr != unsettledMFA && attr != unsettledSignedIn {
				return fmt.Errorf("unsettled: %s.%s can't be left unsettled; only %s and %s can", key, attr, unsettledMFA, unsettledSignedIn)
			}
		}
	}
	return nil
}

func mapped(terms map[string]string, block, what string, vendor ...string) error {
	for _, v := range vendor {
		if _, ok := terms[v]; !ok {
			return fmt.Errorf("%s %q has no entry in terms.%s", what, v, block)
		}
	}
	return nil
}

func known(keys map[string]bool, what string, names ...string) error {
	for _, n := range names {
		if !keys[n] {
			return fmt.Errorf("%s %s is not in the roster", what, n)
		}
	}
	return nil
}

// Guest reports whether a is a guest.
func (r *Roster) Guest(a Account) bool { return r.Terms.AccountKinds[a.Kind] == KindGuest }

// MFAClass is the strongest normalized MFA class among a's methods.
func (r *Roster) MFAClass(a Account) string {
	class := MFANone
	for _, m := range a.Methods {
		switch r.Terms.MFAMethods[m] {
		case MFAPhishingResistant:
			return MFAPhishingResistant
		case MFA:
			class = MFA
		}
	}
	return class
}

// HeldRoles lists the roles a holds now, directly or through a group.
func (r *Roster) HeldRoles(a Account) []string {
	roles := slices.Clone(a.Roles)
	for _, g := range r.Groups {
		if slices.Contains(g.Members, a.Key) {
			roles = append(roles, g.Roles...)
		}
	}
	return roles
}

// HeldCloudRoles lists the cloud roles a holds, directly or through a
// group.
func (r *Roster) HeldCloudRoles(a Account) []string {
	roles := slices.Clone(a.CloudRoles)
	for _, g := range r.Groups {
		if slices.Contains(g.Members, a.Key) {
			roles = append(roles, g.CloudRoles...)
		}
	}
	return roles
}

// Account returns the account with key.
func (r *Roster) Account(key string) (Account, bool) {
	i := slices.IndexFunc(r.Accounts, func(a Account) bool { return a.Key == key })
	if i < 0 {
		return Account{}, false
	}
	return r.Accounts[i], true
}

// Clone returns a copy of r whose entries can be changed without changing r.
func (r *Roster) Clone() *Roster {
	c := *r
	c.Accounts = slices.Clone(r.Accounts)
	for i := range c.Accounts {
		a := &c.Accounts[i]
		a.Roles, a.EligibleRoles, a.CloudRoles, a.Methods = slices.Clone(a.Roles), slices.Clone(a.EligibleRoles), slices.Clone(a.CloudRoles), slices.Clone(a.Methods)
		a.PartialCloudRoles = slices.Clone(a.PartialCloudRoles)
		if a.SignedInDaysAgo != nil {
			days := *a.SignedInDaysAgo
			a.SignedInDaysAgo = &days
		}
		a.PasswordLength, a.Logins, a.CloudAccess = cloneInt(a.PasswordLength), slices.Clone(a.Logins), cloneCloudAccess(a.CloudAccess)
	}
	c.Groups = slices.Clone(r.Groups)
	for i := range c.Groups {
		c.Groups[i].Members, c.Groups[i].Roles, c.Groups[i].CloudRoles = slices.Clone(c.Groups[i].Members), slices.Clone(c.Groups[i].Roles), slices.Clone(c.Groups[i].CloudRoles)
		c.Groups[i].CloudAccess = cloneCloudAccess(c.Groups[i].CloudAccess)
	}
	c.Policies = slices.Clone(r.Policies)
	for i := range c.Policies {
		p := &c.Policies[i]
		p.Include, p.Exclude = p.Include.clone(), p.Exclude.clone()
		p.Apps, p.ExcludeApps, p.Requires, p.Conditions = slices.Clone(p.Apps), slices.Clone(p.ExcludeApps), slices.Clone(p.Requires), slices.Clone(p.Conditions)
		p.SessionLifetimeMinutes, p.IdleTimeoutMinutes = cloneInt(p.SessionLifetimeMinutes), cloneInt(p.IdleTimeoutMinutes)
	}
	c.Apps = slices.Clone(r.Apps)
	for i := range c.Apps {
		c.Apps[i].Provisioning, c.Apps[i].CloudRoles = slices.Clone(c.Apps[i].Provisioning), slices.Clone(c.Apps[i].CloudRoles)
	}
	c.Directory, c.Cloud = r.Directory.clone(), r.Cloud.clone()
	c.SecurityGroups = slices.Clone(r.SecurityGroups)
	for i := range c.SecurityGroups {
		g := &c.SecurityGroups[i]
		g.Rules = slices.Clone(g.Rules)
		for j := range g.Rules {
			g.Rules[j].Ports, g.Rules[j].Sources = slices.Clone(g.Rules[j].Ports), slices.Clone(g.Rules[j].Sources)
		}
	}
	c.Storage = slices.Clone(r.Storage)
	for i := range c.Storage {
		c.Storage[i].AllowedSources, c.Storage[i].BackupRetentionDays = slices.Clone(c.Storage[i].AllowedSources), cloneInt(c.Storage[i].BackupRetentionDays)
	}
	c.Providers = maps.Clone(r.Providers)
	for _, d := range domains {
		d.clone(&c, r)
	}
	c.Unsettled = map[string][]string{}
	for k, v := range r.Unsettled {
		c.Unsettled[k] = slices.Clone(v)
	}
	return &c
}

func (a Audience) clone() Audience {
	a.Accounts, a.Groups, a.Roles = slices.Clone(a.Accounts), slices.Clone(a.Groups), slices.Clone(a.Roles)
	return a
}

func cloneCloudAccess(access map[string]CloudGrant) map[string]CloudGrant {
	if access == nil {
		return nil
	}
	out := make(map[string]CloudGrant, len(access))
	for k, g := range access {
		out[k] = CloudGrant{Roles: slices.Clone(g.Roles), PartialRoles: slices.Clone(g.PartialRoles)}
	}
	return out
}

func cloneInt(n *int) *int {
	if n == nil {
		return nil
	}
	v := *n
	return &v
}

// portRange reads a port, a range of ports, or * for every port.
func portRange(port string) (from, to int, ok bool) {
	if port == "*" {
		return 0, 65535, true
	}
	lo, hi, isRange := strings.Cut(port, "-")
	if !isRange {
		hi = lo
	}
	from, errFrom := strconv.Atoi(lo)
	to, errTo := strconv.Atoi(hi)
	return from, to, errFrom == nil && errTo == nil && from >= 0 && from <= to && to <= 65535
}

// oneOrMore is a JSON string or a list of strings.
type oneOrMore []string

func (o *oneOrMore) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		*o = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return fmt.Errorf("want a string or a list of strings")
	}
	*o = many
	return nil
}

// extra returns the fields of the JSON object raw other than known.
func extra(raw json.RawMessage, known ...string) (Extra, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	for _, k := range known {
		delete(fields, k)
	}
	if len(fields) == 0 {
		return nil, nil
	}
	return fields, nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
