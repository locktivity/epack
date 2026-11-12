package roster

import (
	"encoding/json"
	"fmt"
	"slices"
)

// Directory is the identity provider's own settings. Its file format:
//
//	"directory": {
//	  "domain": "example.com",
//	  "password_policy": {"min_length": 12}
//	}
//
// domain is the organization's domain or tenant identifier. password_policy
// is the password policy accounts' passwords must meet now, left out when
// the directory has none. min_length is the shortest password it allows.
// A roster with a directory block describes the identity side fully: an
// account with no state is in none the schemas count apart, one with no
// password_strength or password_length has no password in the directory,
// an app with no publisher is the organization's own, and one with no
// provisioning has none.
type Directory struct {
	Domain         string
	PasswordPolicy *PasswordPolicy
	Extra          Extra
}

// PasswordPolicy is what the directory's password policy requires of a
// password.
type PasswordPolicy struct {
	MinLength int
	Extra     Extra
}

func parseDirectory(raw json.RawMessage) (*Directory, error) {
	var d struct {
		Domain         string          `json:"domain"`
		PasswordPolicy json.RawMessage `json:"password_policy"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	out := &Directory{Domain: d.Domain}
	var err error
	if out.Extra, err = extra(raw, "domain", "password_policy"); err != nil {
		return nil, err
	}
	if len(d.PasswordPolicy) > 0 {
		var p struct {
			MinLength int `json:"min_length"`
		}
		if err := json.Unmarshal(d.PasswordPolicy, &p); err != nil {
			return nil, fmt.Errorf("password_policy: %w", err)
		}
		e, err := extra(d.PasswordPolicy, "min_length")
		if err != nil {
			return nil, fmt.Errorf("password_policy: %w", err)
		}
		out.PasswordPolicy = &PasswordPolicy{MinLength: p.MinLength, Extra: e}
	}
	return out, nil
}

func (d *Directory) clone() *Directory {
	if d == nil {
		return nil
	}
	c := *d
	if d.PasswordPolicy != nil {
		p := *d.PasswordPolicy
		c.PasswordPolicy = &p
	}
	return &c
}

func (r *Roster) validateDirectory() error {
	d := r.Directory
	if d == nil {
		return nil
	}
	if d.Domain == "" {
		return fmt.Errorf("the directory has no domain")
	}
	if d.PasswordPolicy != nil && d.PasswordPolicy.MinLength <= 0 {
		return fmt.Errorf("password_policy min_length is %d, want a length above 0", d.PasswordPolicy.MinLength)
	}
	return nil
}

// validateAccountFacts checks the facts an account states beyond its roles
// and MFA methods.
func (r *Roster) validateAccountFacts(a Account) error {
	t := r.Terms
	what := "account " + a.Key
	if a.State != "" {
		if err := mapped(t.AccountStates, "account_states", what+" state", a.State); err != nil {
			return err
		}
		if t.AccountStates[a.State] == AccountArchived && a.Enabled {
			return fmt.Errorf("%s is archived and enabled; an archived account can't sign in", what)
		}
	}
	if a.PasswordStrength != "" {
		if err := mapped(t.PasswordStrengths, "password_strengths", what+" password_strength", a.PasswordStrength); err != nil {
			return err
		}
	}
	if a.PasswordLength != nil && *a.PasswordLength <= 0 {
		return fmt.Errorf("%s password_length is %d; leave it out when the account has no password", what, *a.PasswordLength)
	}
	if err := mapped(t.LoginMethods, "login_methods", what+" login", a.Logins...); err != nil {
		return err
	}
	if t.AccountKinds[a.Kind] == KindRoot && a.CloudAccount == "" {
		return fmt.Errorf("%s is a root account and names no cloud_account", what)
	}
	if a.CloudAccount != "" {
		if err := r.placed(what, a.CloudAccount); err != nil {
			return err
		}
	}
	if len(a.CloudRoles) > 0 || len(a.PartialCloudRoles) > 0 {
		if err := r.placed(what+" cloud_roles", a.CloudAccount); err != nil {
			return err
		}
	}
	return r.validateCloudAccess(what, a.CloudAccess)
}

// kindOf is a's normalized kind.
func (r *Roster) kindOf(a Account) string { return r.Terms.AccountKinds[a.Kind] }

// person reports whether a is a person's account, a member's or a guest's.
func (r *Roster) person(a Account) bool {
	kind := r.kindOf(a)
	return kind == KindMember || kind == KindGuest
}

// inDirectory reports whether a is an account in the identity provider's
// directory rather than one local to a cloud account.
func inDirectory(a Account) bool { return a.CloudAccount == "" }

func (r *Roster) stateOf(a Account) string { return r.Terms.AccountStates[a.State] }

// deriveDirectory adds the idp-posture values a directory block determines.
// users and admins are the accounts deriveIdentity counts as users and as
// privileged users. A user is locked out, or has a weak password, when the
// vendor's state or rating for them maps to it, and their password misses
// the policy when it is shorter than the policy's minimum. An app has
// automated provisioning when a provisioning feature that creates accounts
// is on for it, and automated deprovisioning when one that removes access
// is. An authorized third-party app is an enabled app a third party
// publishes. The session limits are the longest any enforced policy sets,
// or null when none sets one.
func (r *Roster) deriveDirectory(v map[string]any, users []Account, directory []Account) {
	d := r.Directory
	v["/org_domain"] = d.Domain
	v["/user_security/locked_out_user_count"] = count(users, func(a Account) bool { return r.stateOf(a) == AccountLockedOut })
	v["/user_security/weak_password_user_count"] = count(users, func(a Account) bool {
		return r.Terms.PasswordStrengths[a.PasswordStrength] == PasswordWeak
	})
	v["/user_security/password_policy_noncompliant_user_count"] = count(users, func(a Account) bool {
		return d.PasswordPolicy != nil && a.PasswordLength != nil && *a.PasswordLength < d.PasswordPolicy.MinLength
	})

	var enabled []App
	for _, a := range r.Apps {
		if a.Enabled {
			enabled = append(enabled, a)
		}
	}
	feature := func(want string) func(App) bool {
		return func(a App) bool {
			return slices.ContainsFunc(a.Provisioning, func(f string) bool { return r.Terms.ProvisioningFeatures[f] == want })
		}
	}
	v["/app_security/provisioning_app_count"] = count(enabled, feature(ProvisionCreate))
	v["/app_security/deprovisioning_app_count"] = count(enabled, feature(ProvisionDeactivate))
	v["/app_security/authorized_third_party_apps_count"] = count(enabled, r.thirdPartyApp)

	v["/lifecycle/archived_account_count"] = count(directory, func(a Account) bool { return r.stateOf(a) == AccountArchived })

	v["/policy/session_lifetime_max_min"] = r.longestLimit(func(p Policy) *int { return p.SessionLifetimeMinutes })
	v["/policy/idle_timeout_max_min"] = r.longestLimit(func(p Policy) *int { return p.IdleTimeoutMinutes })
}

func (r *Roster) thirdPartyApp(a App) bool {
	return r.Terms.AppPublishers[a.Publisher] == PublisherThirdParty
}

// longestLimit gives the longest limit an enforced policy sets, or nil when none
// sets one.
func (r *Roster) longestLimit(limit func(Policy) *int) any {
	var out *int
	for _, p := range r.Policies {
		if n := limit(p); n != nil && r.Terms.PolicyStates[p.State] == StateEnforced && (out == nil || *n > *out) {
			out = n
		}
	}
	if out == nil {
		return nil
	}
	return *out
}
