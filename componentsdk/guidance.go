package componentsdk

import (
	"strings"
	"unicode"
)

// Guidance is the collector's advice to the customer about a gap or a run
// warning. Fix, NoAction, and Choice appear at every level. Their text holds
// fixed wording plus permission, plan, and region names, and never a
// resource, person, or account. Scope can name an account, so it appears at
// the audit and internal levels only. A gap or warning holds at most one of
// Fix, NoAction, and Choice. When it holds none, it is shown as No known fix.
// Guidance never clears a gap or sets a control's result. Only a later run
// that collects the evidence can do that.
type Guidance struct {
	// Fix is a single instruction that repairs collection, such as "Allow
	// iam:ListSAMLProviders in the collector's IAM policy." It is a
	// suggestion for the customer, and the collector has not carried it out.
	Fix string `json:"fix,omitempty"`
	// NoAction means nothing needs to change now, such as for a report the
	// vendor updates a day late. It does not clear the gap.
	NoAction bool `json:"no_action,omitempty"`
	// Choice is a decision for the customer that has consequences, such as
	// adding a plan.
	Choice *Choice `json:"choice,omitempty"`
	// Scope is the account, tenant, or region affected. It appears at the
	// audit and internal levels only.
	Scope string `json:"scope,omitempty"`
}

// Choice is a decision for the customer about a gap or warning. It has a
// question and two or more options. Each option's consequence includes its
// cost and what stays Not collected.
type Choice struct {
	Question string         `json:"question"`
	Options  []ChoiceOption `json:"options"`
}

// ChoiceOption is one answer to a Choice.
type ChoiceOption struct {
	Label       string `json:"label"`
	Consequence string `json:"consequence"`
}

// maxGuidanceText is the maximum length in bytes of each guidance text.
const maxGuidanceText = 500

// guidanceText trims text, drops control characters, and caps its length.
func guidanceText(text string) string {
	text = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, text))
	if len(text) > maxGuidanceText {
		text = strings.TrimSpace(text[:maxGuidanceText])
	}
	return text
}

// advise sets the one piece of advice that a gap or warning may hold. It
// marks a second piece as a conflict, and the result reports the conflict as
// a check finding.
func (a *advice) advise(set func(*Guidance) bool) {
	g := &a.guidance
	if g.Fix != "" || g.NoAction || g.Choice != nil || !set(g) {
		a.conflict = true
	}
}

// Fix sets the instruction that repairs collection, such as "Allow
// iam:ListSAMLProviders in the collector's IAM policy." It appears at every
// level. A gap holds at most one of Fix, NoAction, and Decide. The SDK keeps
// the first one given and reports a later one as a guidance finding.
func Fix(instruction string) AdviceOption {
	return AdviceOption{apply: func(a *advice) {
		a.advise(func(gd *Guidance) bool {
			gd.Fix = guidanceText(instruction)
			return gd.Fix != ""
		})
	}}
}

// NoAction marks that nothing needs to change now, such as for a report the
// vendor updates a day late or a list the collector caps. The gap stays.
func NoAction() AdviceOption {
	return AdviceOption{apply: func(a *advice) {
		a.advise(func(gd *Guidance) bool {
			gd.NoAction = true
			return true
		})
	}}
}

// Decide gives the customer a choice that has consequences, such as whether
// to add a plan. Pass two or more options. Each option's consequence states
// its cost and what stays Not collected. A choice with fewer than two options
// is reported as a guidance finding.
func Decide(question string, options ...ChoiceOption) AdviceOption {
	return AdviceOption{apply: func(a *advice) {
		a.advise(func(gd *Guidance) bool {
			c := &Choice{Question: guidanceText(question)}
			for _, o := range options {
				c.Options = append(c.Options, ChoiceOption{Label: guidanceText(o.Label), Consequence: guidanceText(o.Consequence)})
			}
			if c.Question == "" || len(c.Options) < 2 {
				return false
			}
			gd.Choice = c
			return true
		})
	}}
}

// Scope sets the account, tenant, or region that a gap or warning affects.
// It appears at the audit and internal levels only.
func Scope(scope string) AdviceOption {
	return AdviceOption{apply: func(a *advice) { a.guidance.Scope = guidanceText(scope) }}
}

// RunWarning is a warning about the whole run, such as a list the collector
// caps. It also holds the advice on what to do about it. Message appears at
// the audit and internal levels only, like a gap's warning. MissingPermission
// and the advice appear at every level.
type RunWarning struct {
	Message           string `json:"message,omitempty"`
	MissingPermission string `json:"missing_permission,omitempty"`
	Guidance

	// guidanceConflict is true when the warning was given more than one of
	// Fix, NoAction, and Decide, or a Decide with fewer than two options.
	guidanceConflict bool
}

// maxRunWarnings is the most warnings a result lists.
const maxRunWarnings = 200

// Warn records a warning about the run in the collector result. The options
// Fix, NoAction, Decide, Scope, and MissingPermission set what to do about
// it. A warning does not leave out a value or clear a gap. Use NotCollected
// or Partial to record a value that is missing. A warning given twice is
// listed once.
func (r *Recorder) Warn(message string, opts ...AdviceOption) {
	a := adviceOf(opts)
	w := RunWarning{Message: guidanceText(message), MissingPermission: a.missingPermission, Guidance: a.guidance, guidanceConflict: a.conflict}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.warnings {
		if sameWarning(existing, w) {
			return
		}
	}
	if len(r.warnings) < maxRunWarnings {
		r.warnings = append(r.warnings, w)
	}
}

func sameWarning(a, b RunWarning) bool {
	same := a.Message == b.Message && a.MissingPermission == b.MissingPermission && a.Fix == b.Fix && a.NoAction == b.NoAction && a.Scope == b.Scope
	if !same || (a.Choice == nil) != (b.Choice == nil) {
		return false
	}
	return a.Choice == nil || a.Choice.Question == b.Choice.Question
}

// Warnings returns a copy of the run warnings recorded so far.
func (r *Recorder) Warnings() []RunWarning {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]RunWarning(nil), r.warnings...)
}
