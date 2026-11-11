package roster

import "slices"

// What enforced policies ask of a sign-in.
const (
	OutcomeBlocked = "blocked"
	OutcomeMFA     = "mfa"
	OutcomeNone    = "none"
)

// SignIn is one kind of sign-in by an account: to an app, with a value for
// each part of a sign-in a policy condition can limit.
type SignIn struct {
	// Apps names the app the sign-in is to and every group of apps it
	// belongs to, in the vendor's terms, such as an app's key and Office365.
	Apps []string
	// Parts holds the sign-in's value of each part, such as PartClient
	// ClientBrowser. A sign-in meets no limit on a part it leaves out.
	Parts map[string]string
}

// Applies reports whether policy p applies to a's sign-in s, whatever the
// policy's state: p includes a and doesn't exclude it, covers one of the
// sign-in's apps and excludes none of them, and each part its conditions
// limit takes a value they allow. A policy with a condition terms.conditions
// doesn't map applies to no sign-in, since nothing says which it limits.
func (r *Roster) Applies(p Policy, a Account, s SignIn) bool {
	if !r.covers(p, a) {
		return false
	}
	in := func(apps []string) func(string) bool {
		return func(app string) bool { return slices.Contains(apps, app) }
	}
	if len(p.Apps) > 0 && !slices.ContainsFunc(s.Apps, in(p.Apps)) {
		return false
	}
	if slices.ContainsFunc(s.Apps, in(p.ExcludeApps)) {
		return false
	}
	limits, ok := r.limits(p)
	if !ok {
		return false
	}
	for part, values := range limits {
		if !slices.Contains(values, s.Parts[part]) {
			return false
		}
	}
	return true
}

// Outcome returns what a sign-in must do under policies that apply to it,
// counting the enforced ones: be blocked if one blocks it, satisfy MFA if
// one requires it, or nothing.
func (r *Roster) Outcome(policies []Policy) string {
	enforced := func(p Policy) bool { return r.Terms.PolicyStates[p.State] == StateEnforced }
	switch {
	case slices.ContainsFunc(policies, func(p Policy) bool { return enforced(p) && p.Blocks != "" }):
		return OutcomeBlocked
	case slices.ContainsFunc(policies, func(p Policy) bool { return enforced(p) && r.requiresMFA(p) }):
		return OutcomeMFA
	}
	return OutcomeNone
}
