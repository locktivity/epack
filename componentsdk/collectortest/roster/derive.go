package roster

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/locktivity/epack/componentsdk"
)

// Values maps a normalized artifact type to the values a roster determines,
// by JSON pointer. A value is an int, a bool, or nil for a percentage over no
// one. A pointer the roster does not determine is not in the map.
type Values map[string]map[string]any

// inactiveDays is the window the idp-posture schema's inactive values use.
const inactiveDays = 90

// Derive computes the normalized values r determines. Each count and flag
// follows its field's summary in the SDK's normalized schema. Each
// percentage is then its schema's x-epack-numerator over its
// x-epack-denominator, rounded as its x-epack-rounding says, and its
// x-epack-present flag says whether the denominator is above zero.
//
// A roster with a cloud side, a cloud block, cloud roles, security groups,
// or storage, also gives cloud-posture and access-posture values, for each
// cloud account the collector can read, or for the one account a roster
// without a cloud block has. Access-posture's totals are then across those
// accounts. A roster with a vcs block and no cloud side gives access-posture
// values for the version control organization instead, and no idp-posture
// values, since its accounts are the organization's and not a directory's.
// Each domain the roster has adds its values. A list's entries are
// in the roster's order, and Align matches them to an artifact's.
//
// Every schema Derive gives values for also gets its schema_version, when
// the schema fixes it, and its provider, when the roster's providers block
// gives one.
func Derive(r *Roster) (Values, error) {
	out := Values{}
	switch {
	case r.hasCloud():
		out[IDPPosture] = deriveIdentity(r)
		out[CloudPosture] = deriveCloud(r)
		out[AccessPosture] = deriveAccess(r)
	case r.VCS != nil:
		out[AccessPosture] = deriveCodeHostAccess(r)
	default:
		out[IDPPosture] = deriveIdentity(r)
	}
	for _, d := range domains {
		if err := d.derive(r, out); err != nil {
			return nil, fmt.Errorf("%s: %w", d.key, err)
		}
	}
	for schemaID, v := range out {
		if err := addPercentages(schemaID, v); err != nil {
			return nil, err
		}
		if err := addBookkeeping(r, schemaID, v); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// addBookkeeping adds schemaID's schema_version when its schema fixes one,
// and its provider when r's providers block gives one.
func addBookkeeping(r *Roster, schemaID string, v map[string]any) error {
	var schema struct {
		Properties struct {
			SchemaVersion struct {
				Const *string `json:"const"`
			} `json:"schema_version"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(componentsdk.NormalizedSchemaJSON(schemaID), &schema); err != nil {
		return fmt.Errorf("%s: %w", schemaID, err)
	}
	if c := schema.Properties.SchemaVersion.Const; c != nil {
		v["/schema_version"] = *c
	}
	if p, ok := r.Providers[shortName(schemaID)]; ok {
		v["/provider"] = p
	}
	return nil
}

func (r *Roster) hasCloud() bool {
	if r.Cloud != nil || len(r.SecurityGroups) > 0 || len(r.Storage) > 0 {
		return true
	}
	return slices.ContainsFunc(r.Accounts, func(a Account) bool { return len(a.CloudRoles) > 0 || len(a.PartialCloudRoles) > 0 }) ||
		slices.ContainsFunc(r.Groups, func(g Group) bool { return len(g.CloudRoles) > 0 })
}

// openToAny reports whether a TCP connection to port from any address gets
// through a security group.
func (r *Roster) openToAny(g SecurityGroup, port int) bool {
	var matching []NetworkRule
	for _, rule := range g.Rules {
		protocol := r.Terms.Protocols[rule.Protocol]
		if rule.Direction != Inbound || (protocol != ProtocolTCP && protocol != ProtocolAny) {
			continue
		}
		if !slices.ContainsFunc(rule.Ports, func(p string) bool { from, to, _ := portRange(p); return port >= from && port <= to }) {
			continue
		}
		if slices.ContainsFunc(rule.Sources, func(s string) bool { return r.Terms.NetworkSources[s] == SourceAny }) {
			matching = append(matching, rule)
		}
	}
	if len(matching) == 0 {
		return false
	}
	if slices.ContainsFunc(matching, func(rule NetworkRule) bool { return rule.Priority == 0 }) {
		return slices.ContainsFunc(matching, func(rule NetworkRule) bool { return rule.Access == Allow })
	}
	first := slices.MinFunc(matching, func(a, b NetworkRule) int { return a.Priority - b.Priority })
	return first.Access == Allow
}

// deriveIdentity gives idp-posture's counts and flags. It reads the
// accounts in the directory only. Users are enabled members, guests left
// out. Admins are enabled accounts of people, guests included, that hold an
// admin role now. Service accounts are neither.
func deriveIdentity(r *Roster) map[string]any {
	v := map[string]any{}
	var directory, users, admins []Account
	for _, a := range r.Accounts {
		if !inDirectory(a) {
			continue
		}
		directory = append(directory, a)
		if !a.Enabled {
			continue
		}
		if r.kindOf(a) == KindMember {
			users = append(users, a)
		}
		if r.person(a) && r.admin(a) {
			admins = append(admins, a)
		}
	}
	hasMFA := func(a Account) bool { return r.MFAClass(a) != MFANone }
	strong := func(a Account) bool { return r.MFAClass(a) == MFAPhishingResistant }
	inactive := func(a Account) bool { return a.SignedInDaysAgo == nil || *a.SignedInDaysAgo > inactiveDays }

	v["/user_security/user_count"] = len(users)
	v["/user_security/mfa_user_count"] = count(users, hasMFA)
	v["/user_security/phishing_resistant_user_count"] = count(users, strong)
	v["/user_security/inactive_user_count"] = count(users, inactive)

	enabledApps := 0
	sso := 0
	for _, a := range r.Apps {
		if a.Enabled {
			enabledApps++
			if r.Terms.SSOModes[a.SSOMode] == SSO {
				sso++
			}
		}
	}
	v["/app_security/app_count"] = enabledApps
	v["/app_security/sso_app_count"] = sso

	// Eligible roles grant nothing until activated, and the roster's roles
	// are held at all times, so every admin is a standing admin.
	v["/privileged_access/privileged_users_count"] = len(admins)
	v["/privileged_access/super_admin_count"] = count(admins, r.superAdmin)
	v["/privileged_access/privileged_mfa_user_count"] = count(admins, hasMFA)
	v["/privileged_access/privileged_phishing_resistant_user_count"] = count(admins, strong)
	v["/privileged_access/standing_privileged_users_count"] = len(admins)
	v["/privileged_access/standing_privileged_users_present"] = len(admins) > 0

	v["/lifecycle/account_count"] = len(directory)
	v["/lifecycle/suspended_account_count"] = count(directory, func(a Account) bool { return !a.Enabled && r.stateOf(a) != AccountArchived })
	if r.Directory != nil {
		r.deriveDirectory(v, users, directory)
	}

	// Policies combine. A user is covered when the enforced policies that
	// include them and don't exclude them, between them, require MFA for or
	// block every sign-in to every app from every kind of client. Policies
	// that include everyone and name exceptions, such as a break-glass
	// account, still make mfa_required true.
	protects := func(p Policy) bool { return r.requiresMFA(p) || p.Blocks != "" }
	blocksLegacy := func(p Policy) bool { return r.Terms.Blocks[p.Blocks] == BlocksLegacyAuth }
	everyone := func(keep func(Policy) bool) []Policy {
		return r.policiesThat(func(p Policy) bool { return p.Include.All && keep(p) })
	}
	v["/policy/mfa_required"] = r.coversSignIns(everyone(protects), clientKinds)
	v["/policy/mfa_required_user_count"] = count(users, func(a Account) bool {
		return r.coversSignIns(r.policiesThat(func(p Policy) bool { return protects(p) && r.covers(p, a) }), clientKinds)
	})
	v["/policy/legacy_auth_blocked"] = r.coversSignIns(everyone(blocksLegacy), legacyClientKinds)
	if len(admins) > 0 {
		v["/policy/phishing_resistant_required_for_privileged"] = slices.ContainsFunc(r.Policies, func(p Policy) bool {
			return r.applies(p) && r.requires(p, RequiresPhishingResistantMFA) && r.includesAdmins(p, admins)
		})
	}

	device := func(p Policy) bool { return r.requires(p, RequiresManagedDevice) }
	v["/device_access/managed_device_required"] = slices.ContainsFunc(r.Policies, func(p Policy) bool {
		return r.applies(p) && p.Include.All && device(p)
	})
	if len(admins) > 0 {
		v["/device_access/managed_device_required_for_admins"] = slices.ContainsFunc(r.Policies, func(p Policy) bool {
			return r.applies(p) && device(p) && r.includesAdmins(p, admins)
		})
	}
	return v
}

func (r *Roster) admin(a Account) bool {
	return slices.ContainsFunc(r.HeldRoles(a), func(role string) bool {
		class := r.Terms.Roles[role]
		return class == RoleAdmin || class == RoleSuperAdmin
	})
}

func (r *Roster) superAdmin(a Account) bool {
	return slices.ContainsFunc(r.HeldRoles(a), func(role string) bool { return r.Terms.Roles[role] == RoleSuperAdmin })
}

// applies reports whether a policy is enforced on every sign-in to every
// app: it has no condition that limits it to some sign-ins, and leaves no
// app out.
func (r *Roster) applies(p Policy) bool {
	return r.Terms.PolicyStates[p.State] == StateEnforced && len(p.Conditions) == 0 && len(p.Apps) == 0 && len(p.ExcludeApps) == 0
}

// The parts of a sign-in a policy condition can limit, and the values each
// takes. Legacy mail sync and other legacy clients can't do MFA.
var (
	clientKinds       = []string{ClientBrowser, ClientApps, ClientMailSync, ClientLegacy}
	legacyClientKinds = []string{ClientMailSync, ClientLegacy}
	signInParts       = map[string][]string{
		PartClient:     clientKinds,
		PartPlatform:   {"android", "ios", "windows", "windows_phone", "macos", "linux", "other"},
		PartLocation:   {"trusted", "untrusted"},
		PartSignInRisk: {"none", "low", "medium", "high"},
		PartUserRisk:   {"none", "low", "medium", "high"},
	}
)

func (r *Roster) policiesThat(keep func(Policy) bool) []Policy {
	var out []Policy
	for _, p := range r.Policies {
		if keep(p) {
			out = append(out, p)
		}
	}
	return out
}

// coversSignIns reports whether the enforced policies among policies,
// between them, cover every sign-in to every app from each kind of client in
// kinds, whatever the sign-in's other parts. A sign-in is one value of each
// part some policy limits.
func (r *Roster) coversSignIns(policies []Policy, kinds []string) bool {
	type limited struct {
		policy Policy
		limits map[string][]string
	}
	var enforced []limited
	parts := map[string]bool{PartClient: true}
	for _, p := range policies {
		limits, ok := r.limits(p)
		if !ok || r.Terms.PolicyStates[p.State] != StateEnforced {
			continue
		}
		enforced = append(enforced, limited{p, limits})
		for part := range limits {
			parts[part] = true
		}
	}
	signIns := []map[string]string{{}}
	for _, part := range sortedKeys(parts) {
		values := signInParts[part]
		if part == PartClient {
			values = kinds
		}
		var next []map[string]string
		for _, in := range signIns {
			for _, v := range values {
				out := maps.Clone(in)
				out[part] = v
				next = append(next, out)
			}
		}
		signIns = next
	}
	for _, in := range signIns {
		var forSignIn []Policy
		for _, l := range enforced {
			allows := true
			for part, values := range l.limits {
				allows = allows && slices.Contains(values, in[part])
			}
			if allows {
				forSignIn = append(forSignIn, l.policy)
			}
		}
		if !coverEveryApp(forSignIn) {
			return false
		}
	}
	return true
}

// limits gives, for each part of a sign-in a policy's conditions limit, the
// values it covers. It reports false when a condition limits the policy in
// a way the terms don't say, such as a device filter. A policy that blocks
// legacy authentication covers legacy clients only.
func (r *Roster) limits(p Policy) (map[string][]string, bool) {
	out := map[string][]string{}
	if r.Terms.Blocks[p.Blocks] == BlocksLegacyAuth {
		out[PartClient] = legacyClientKinds
	}
	for _, c := range p.Conditions {
		limit, ok := r.Terms.Conditions[c]
		if !ok {
			return nil, false
		}
		for part, values := range limit {
			if prev, set := out[part]; set {
				values = slices.DeleteFunc(slices.Clone(prev), func(v string) bool { return !slices.Contains(values, v) })
			}
			out[part] = values
		}
	}
	return out, true
}

// coverEveryApp reports whether the policies, between them, cover every
// app. A policy with no app list covers every app but those it leaves out,
// and one with a list covers the apps on it. Each app that every policy
// without a list leaves out must be on another policy's list.
func coverEveryApp(policies []Policy) bool {
	var excluded []string
	all := false
	listed := map[string]bool{}
	for _, p := range policies {
		if len(p.Apps) > 0 {
			for _, app := range p.Apps {
				if !slices.Contains(p.ExcludeApps, app) {
					listed[app] = true
				}
			}
			continue
		}
		if !all {
			excluded, all = slices.Clone(p.ExcludeApps), true
			continue
		}
		excluded = slices.DeleteFunc(excluded, func(app string) bool { return !slices.Contains(p.ExcludeApps, app) })
	}
	return all && !slices.ContainsFunc(excluded, func(app string) bool { return !listed[app] })
}

func (r *Roster) requiresMFA(p Policy) bool {
	return r.requires(p, RequiresMFA, RequiresPhishingResistantMFA)
}

// requires reports whether a sign-in a policy covers must meet one of want.
// When all of the policy's requirements are due, one in want is enough. When
// any one of them will do, each must be in want.
func (r *Roster) requires(p Policy, want ...string) bool {
	in := func(req string) bool { return slices.Contains(want, r.Terms.Requirements[req]) }
	if p.RequireAny {
		return len(p.Requires) > 0 && !slices.ContainsFunc(p.Requires, func(req string) bool { return !in(req) })
	}
	return slices.ContainsFunc(p.Requires, in)
}

// covers reports whether a policy includes a and does not exclude it.
func (r *Roster) covers(p Policy, a Account) bool {
	return r.inAudience(p.Include, a) && !r.inAudience(p.Exclude, a)
}

func (r *Roster) inAudience(aud Audience, a Account) bool {
	if aud.All || slices.Contains(aud.Accounts, a.Key) {
		return true
	}
	if slices.ContainsFunc(r.HeldRoles(a), func(role string) bool { return slices.Contains(aud.Roles, role) }) {
		return true
	}
	return slices.ContainsFunc(r.Groups, func(g Group) bool {
		return slices.Contains(aud.Groups, g.Key) && slices.Contains(g.Members, a.Key)
	})
}

// includesAdmins reports whether a policy includes every admin, by
// including everyone or each admin role they hold. Exceptions it names
// don't change that, as for mfa_required.
func (r *Roster) includesAdmins(p Policy, admins []Account) bool {
	if p.Include.All {
		return true
	}
	for _, a := range admins {
		for _, role := range r.HeldRoles(a) {
			class := r.Terms.Roles[role]
			if (class == RoleAdmin || class == RoleSuperAdmin) && !slices.Contains(p.Include.Roles, role) {
				return false
			}
		}
	}
	return true
}

// field is a normalized schema field's percentage annotations, with the
// numerator, denominator and present flag as absolute pointers.
type field struct {
	numerator, denominator, present string
	rounding                        componentsdk.Rounding
	// all marks a boolean with a numerator and denominator: true when
	// every one counts, and null over none.
	all bool
}

// addPercentages adds each of schemaID's percentages whose numerator and
// denominator v holds, and the present flag of each, unless v has one. A
// percentage in a list is added for each entry v has.
func addPercentages(schemaID string, v map[string]any) error {
	fields, err := percentFields(schemaID)
	if err != nil {
		return err
	}
	for _, pattern := range sortedKeys(fields) {
		f := fields[pattern]
		for _, at := range bindings(f.numerator, v) {
			pointer, numerator, denominator, present := fill(pattern, at), fill(f.numerator, at), fill(f.denominator, at), fill(f.present, at)
			num, numOK := v[numerator].(int)
			den, denOK := v[denominator].(int)
			if !numOK || !denOK {
				continue
			}
			if num > den {
				return fmt.Errorf("%s: %s is %d, more than %s's %d", pointer, numerator, num, denominator, den)
			}
			switch {
			case f.all && den > 0:
				v[pointer] = num == den
			case f.all:
				v[pointer] = nil
			default:
				if p := componentsdk.Percent(num, den, f.rounding); p != nil {
					v[pointer] = *p
				} else {
					v[pointer] = nil
				}
			}
			if _, set := v[present]; present != "" && !set {
				v[present] = den > 0
			}
		}
	}
	return nil
}

// bindings lists, for each pointer in v that pattern matches, the indexes
// its *s stand for there.
func bindings(pattern string, v map[string]any) [][]string {
	want := strings.Split(pattern, "/")
	seen := map[string]bool{}
	var out [][]string
	for _, pointer := range sortedKeys(v) {
		got := strings.Split(pointer, "/")
		if len(got) != len(want) {
			continue
		}
		var at []string
		matches := true
		for i := range want {
			if want[i] == "*" && isIndex(got[i]) {
				at = append(at, got[i])
			} else if want[i] != got[i] {
				matches = false
				break
			}
		}
		if key := strings.Join(at, "/"); matches && !seen[key] {
			seen[key] = true
			out = append(out, at)
		}
	}
	return out
}

// fill puts the indexes at in place of pattern's *s, in order.
func fill(pattern string, at []string) string {
	tokens := strings.Split(pattern, "/")
	n := 0
	for i, t := range tokens {
		if t == "*" && n < len(at) {
			tokens[i] = at[n]
			n++
		}
	}
	return strings.Join(tokens, "/")
}

func isIndex(token string) bool {
	_, err := strconv.Atoi(token)
	return err == nil && token != "" && (token == "0" || token[0] != '0')
}

// percentFields reads the percentages from schemaID's SDK schema, by
// pointer.
func percentFields(schemaID string) (map[string]field, error) {
	raw := componentsdk.NormalizedSchemaJSON(schemaID)
	if raw == nil {
		return nil, fmt.Errorf("the SDK has no normalized schema %s", schemaID)
	}
	var root schemaNode
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("%s: %w", schemaID, err)
	}
	out := map[string]field{}
	if err := root.collect(&root, "", out); err != nil {
		return nil, fmt.Errorf("%s: %w", schemaID, err)
	}
	return out, nil
}

type schemaNode struct {
	Ref         string                `json:"$ref"`
	Defs        map[string]schemaNode `json:"$defs"`
	Properties  map[string]schemaNode `json:"properties"`
	Items       *schemaNode           `json:"items"`
	Numerator   string                `json:"x-epack-numerator"`
	Denominator string                `json:"x-epack-denominator"`
	Rounding    string                `json:"x-epack-rounding"`
	Present     string                `json:"x-epack-present"`
	Type        any                   `json:"type"`
}

// collect walks n's properties, and each list's items with * for the
// index.
func (n schemaNode) collect(root *schemaNode, parent string, out map[string]field) error {
	n = root.deref(n)
	if n.Items != nil {
		return n.Items.collect(root, parent+"/*", out)
	}
	for name, child := range n.Properties {
		pointer := parent + "/" + name
		if child.Numerator != "" {
			all := child.allowsBoolean()
			if child.Denominator == "" || (child.Rounding == "" && !all) {
				return fmt.Errorf("%s has a numerator but no denominator or rounding", pointer)
			}
			f := field{rounding: componentsdk.Rounding(child.Rounding), all: all}
			var ok bool
			if f.numerator, ok = resolve(parent, child.Numerator); !ok {
				return fmt.Errorf("%s: numerator %q leaves the document", pointer, child.Numerator)
			}
			if f.denominator, ok = resolve(parent, child.Denominator); !ok {
				return fmt.Errorf("%s: denominator %q leaves the document", pointer, child.Denominator)
			}
			if f.present, ok = resolve(parent, child.Present); !ok {
				return fmt.Errorf("%s: present %q leaves the document", pointer, child.Present)
			}
			out[pointer] = f
		}
		if err := child.collect(root, pointer, out); err != nil {
			return err
		}
	}
	return nil
}

// allowsBoolean reports whether n's type is boolean, alone or with null.
func (n schemaNode) allowsBoolean() bool {
	switch t := n.Type.(type) {
	case string:
		return t == "boolean"
	case []any:
		return slices.Contains(t, any("boolean"))
	}
	return false
}

// deref follows a node's $ref into the root's $defs, keeping the node's own
// annotations.
func (root *schemaNode) deref(n schemaNode) schemaNode {
	name, ok := strings.CutPrefix(n.Ref, "#/$defs/")
	if !ok {
		return n
	}
	def := root.deref(root.Defs[name])
	if n.Properties == nil {
		n.Properties = def.Properties
	}
	if n.Items == nil {
		n.Items = def.Items
	}
	n.Ref = ""
	return n
}

// resolve turns an annotation's reference into a pointer, as the SDK's
// output checks read it: a sibling's name, a pointer starting with /, or
// N/path, which goes up N levels from the object holding the value and
// then down path.
func resolve(parent, ref string) (string, bool) {
	if ref == "" || strings.HasPrefix(ref, "/") {
		return ref, true
	}
	digits := len(ref) - len(strings.TrimLeft(ref, "0123456789"))
	if digits == 0 || (ref[digits:] != "" && ref[digits] != '/') {
		return parent + "/" + ref, true
	}
	up, err := strconv.Atoi(ref[:digits])
	if err != nil {
		return "", false
	}
	tokens := strings.Split(parent, "/")[1:]
	if parent == "" {
		tokens = nil
	}
	if up > len(tokens) {
		return "", false
	}
	base := strings.Join(tokens[:len(tokens)-up], "/")
	if base != "" {
		base = "/" + base
	}
	return base + ref[digits:], true
}

func count[T any](items []T, keep func(T) bool) int {
	n := 0
	for _, it := range items {
		if keep(it) {
			n++
		}
	}
	return n
}
