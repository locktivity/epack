package collectortest

import (
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/internal/redact"
)

// The guidance check covers the advice in a gap's or warning's fix and
// choice. A collector writes that advice at every level, so it may hold only
// fixed wording and permission, plan, and region names. The check fails
// advice that names a resource, person, or account from the scenario's
// answers or config. Such a name belongs in the scope or the message, which
// the trust level leaves out. A value in the answers counts as a name when
// identifierField picks its field. It also counts when it is one of the
// fakes that scrubbing writes into a recording for an email address, GUID,
// or AWS account number, wherever the fake sits.

// minIdentifier is the length of the shortest value the check looks for,
// so that a short common word is not taken for a name.
const minIdentifier = 4

// identifierField reports whether an answer field holds the name of a
// resource, person, or account, going by the field's name. Fields for a
// status, type, region, role, plan, or permission are excluded, since advice
// may name those.
func identifierField(name string) bool {
	n := strings.ToLower(name)
	for _, allowed := range []string{"status", "state", "type", "kind", "region", "role", "plan", "sku", "scope", "permission", "action"} {
		if strings.Contains(n, allowed) {
			return false
		}
	}
	for _, suffix := range []string{"id", "arn", "email", "mail", "login", "name", "domain", "upn", "account", "owner", "bucket", "repository", "repo"} {
		if strings.HasSuffix(n, suffix) {
			return true
		}
	}
	return false
}

// identifiers returns the values in a scenario's answers and config that
// name a resource, person, or account, longest first. These are the values
// of answer fields that identifierField picks, the scrubber's fakes in the
// answers' URLs and bodies, and every value in the config.
func (k *kit) identifiers(sc Scenario) []string {
	seen := map[string]bool{}
	add := func(v string) {
		v = strings.TrimSpace(v)
		if len(v) >= minIdentifier {
			seen[v] = true
		}
	}
	for _, r := range sc.Responses {
		text := k.textOf(r.Operation, r)
		for _, s := range []string{r.URL, text} {
			for _, fake := range scrubbedFakes(s) {
				add(fake)
			}
		}
		parseAnswer(text).each(func(at place, v any) {
			if s, ok := v.(string); ok && identifierField(at.key) {
				add(s)
			}
		})
	}
	for key, value := range k.configFor(sc) {
		if key == "level" {
			continue
		}
		eachJSON(value, func(_ place, v any) {
			if s, ok := v.(string); ok {
				add(s)
			}
		})
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i]) != len(out[j]) {
			return len(out[i]) > len(out[j])
		}
		return out[i] < out[j]
	})
	return out
}

// regionLike matches cloud region names, such as us-east-1 or eastus2.
// Advice may name a region.
var regionLike = regexp.MustCompile(`^[a-z]{2,}(-[a-z]+)+-\d+$`)

// adviceAsWritten returns a run whose advice is as the collector wrote it.
// Below the audit level the SDK redacts the account's identifiers from
// advice. When it redacted any, the scenario runs again at the audit level,
// so the guidance check can name what the advice held.
func (k *kit) adviceAsWritten(label string, sc Scenario, res componentsdk.InProcessResult) componentsdk.InProcessResult {
	config := k.configFor(sc)
	if res.Result == nil || componentsdk.LevelOf(config).AtLeast(componentsdk.LevelAudit) || !adviceRedacted(res.Result) {
		return res
	}
	if config == nil {
		config = map[string]any{}
	}
	config["level"] = string(componentsdk.LevelAudit)
	audit, _ := k.runWith("guidance", label+"/audit", sc, nil, config)
	return audit
}

// adviceRedacted reports whether any advice in result holds the SDK's
// redaction placeholder.
func adviceRedacted(result *componentsdk.CollectorResult) bool {
	redacted := func(g componentsdk.Guidance) bool {
		texts := []string{g.Fix}
		if g.Choice != nil {
			texts = append(texts, g.Choice.Question)
			for _, o := range g.Choice.Options {
				texts = append(texts, o.Label, o.Consequence)
			}
		}
		return slices.ContainsFunc(texts, func(t string) bool { return strings.Contains(t, redact.Placeholder) })
	}
	for _, g := range result.Gaps {
		if redacted(g.Guidance) {
			return true
		}
	}
	return slices.ContainsFunc(result.Warnings, func(w componentsdk.RunWarning) bool { return redacted(w.Guidance) })
}

// checkGuidanceText reports a run's advice that names a value from its
// scenario.
func (k *kit) checkGuidanceText(label string, sc Scenario, res componentsdk.InProcessResult) {
	if res.Result == nil {
		return
	}
	var ids []string
	named := func(where, text, permission string) {
		if text == "" {
			return
		}
		if ids == nil {
			ids = k.identifiers(sc)
		}
		for _, id := range ids {
			if id == permission || regionLike.MatchString(id) || !strings.Contains(text, id) {
				continue
			}
			k.violate("guidance", label, "the advice %s names %q from the scenario. Advice appears at every level, so it may hold only fixed wording and permission, plan, and region names. "+
				"Name the resource, person, or account in Scope or the message, which the trust level leaves out", where, id)
			return
		}
	}
	advice := func(where string, g componentsdk.Guidance, permission string) {
		named(where, g.Fix, permission)
		if g.Choice != nil {
			named(where, g.Choice.Question, permission)
			for _, o := range g.Choice.Options {
				named(where, o.Label+" "+o.Consequence, permission)
			}
		}
	}
	for _, g := range res.Result.Gaps {
		advice("for the gap at "+g.Path+" "+pointerLabel(g.Pointer), g.Guidance, g.MissingPermission)
	}
	for _, w := range res.Result.Warnings {
		advice("of a run warning", w.Guidance, w.MissingPermission)
	}
}
