package surface

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// SectionHeading is the overview.md heading the rendered section replaces.
const SectionHeading = "## Not Collected"

var sectionStart = regexp.MustCompile(`(?mi)^## Not Collected[ \t]*$`)
var nextSection = regexp.MustCompile(`(?m)^## `)
var versionSegment = regexp.MustCompile(`^v\d+$`)

// Docs is what the renderers need to know about the collector's module.
type Docs struct {
	// Module is the Go module path, such as github.com/locktivity/epack-collector-okta.
	Module string
}

// ReferenceURL is where the published overview points readers for the
// coverage reference: cfg.Reference.URL, or the file on the main branch of
// the module's GitHub repository.
func (d Docs) ReferenceURL(cfg *Config) string {
	if cfg.Reference.URL != "" {
		return cfg.Reference.URL
	}
	parts := strings.Split(d.Module, "/")
	if len(parts) >= 3 && parts[0] == "github.com" {
		return "https://github.com/" + parts[1] + "/" + parts[2] + "/blob/main/" + cfg.Reference.File
	}
	return cfg.Reference.File
}

// RenderSection renders the Not Collected section of the collector's
// overview. With overview headlines, it shows those and points at the
// coverage reference for the rest; without them, it lists every
// not_collected item.
func RenderSection(cfg *Config, docs Docs) string {
	var b strings.Builder
	b.WriteString(SectionHeading + "\n\n")
	type bullet struct{ title, says string }
	var bullets []bullet
	if len(cfg.Overview) > 0 {
		for _, h := range cfg.Overview {
			says := h.Says
			if says == "" {
				if item := cfg.Item(h.Items[0]); item != nil {
					says = item.Says
				}
			}
			bullets = append(bullets, bullet{h.Title, says})
		}
	} else {
		for _, item := range cfg.NotCollected {
			bullets = append(bullets, bullet{item.Title, item.Says})
		}
	}
	if len(bullets) == 0 {
		fmt.Fprintf(&b, "The collector reads everything %s offers through its API that bears on security posture.\n", cfg.Vendor)
	} else {
		fmt.Fprintf(&b, "%s offers the following through its API, and the collector does not read them.\n\n", cfg.Vendor)
		for _, bl := range bullets {
			fmt.Fprintf(&b, "- **%s.** %s\n", strings.TrimSuffix(bl.title, "."), strings.TrimSpace(bl.says))
		}
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "The coverage reference lists what the collector reads of the %s API, and everything else the API offers with why it is left out, checked against %s's published API description: %s\n", cfg.Vendor, cfg.Vendor, docs.ReferenceURL(cfg))
	return b.String()
}

// RenderReference renders the coverage reference: what the collector
// reads, by area, then the full not_collected inventory, the calls the
// sandbox never exercises, what is left out as irrelevant, and the
// recorded calls outside the description.
func RenderReference(cfg *Config, r *Report, docs Docs) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s API coverage\n\n", cfg.Vendor)
	fmt.Fprintf(&b, "What the collector reads of the %s API, and what it leaves out", cfg.Vendor)
	if cfg.Spec.Source != "" {
		fmt.Fprintf(&b, ", checked against the %s API description", cfg.Vendor)
		if cfg.Spec.Revision != "" {
			fmt.Fprintf(&b, " at revision %s", cfg.Spec.Revision)
		}
		fmt.Fprintf(&b, ": %s", cfg.Spec.Source)
		if cfg.Spec.Path != "" {
			fmt.Fprintf(&b, ", %s", cfg.Spec.Path)
		}
	}
	b.WriteString(".\n\n")
	b.WriteString("| | Operations |\n|---|---|\n")
	fmt.Fprintf(&b, "| In the description | %d |\n", r.SpecOperations)
	fmt.Fprintf(&b, "| Read operations in scope | %d |\n", r.InScope)
	fmt.Fprintf(&b, "| Called by the collector | %d |\n", len(r.Exercised))
	fmt.Fprintf(&b, "| Not collected | %d, in %d items |\n", len(r.NotCollected), len(cfg.NotCollected))
	fmt.Fprintf(&b, "| Left out as irrelevant | %d |\n\n", len(r.Irrelevant))

	b.WriteString("## What the collector reads\n\n")
	if len(r.Exercised) == 0 {
		b.WriteString("No recording holds a call the description describes.\n\n")
	} else {
		byArea := map[string][]Exercised{}
		for _, e := range r.Exercised {
			byArea[Area(e.Op)] = append(byArea[Area(e.Op)], e)
		}
		for _, a := range sortedKeys(byArea) {
			ops := byArea[a]
			sort.Slice(ops, func(i, j int) bool {
				if ops[i].Op.Path != ops[j].Op.Path {
					return ops[i].Op.Path < ops[j].Op.Path
				}
				return ops[i].Op.Method < ops[j].Op.Method
			})
			fmt.Fprintf(&b, "- **%s:** ", a)
			for i, e := range ops {
				if i > 0 {
					b.WriteString("; ")
				}
				fmt.Fprintf(&b, "`%s` (%s %s)", e.Op.Key(), e.Op.Method, e.Op.Path)
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	b.WriteString("## Not collected\n\n")
	if len(cfg.NotCollected) == 0 {
		b.WriteString("Nothing in scope is left unread.\n\n")
	}
	for i := range cfg.NotCollected {
		item := &cfg.NotCollected[i]
		fmt.Fprintf(&b, "### %s\n\n%s\n", strings.TrimSuffix(item.Title, "."), strings.TrimSpace(item.Says))
		var ops []*Operation
		for _, v := range r.NotCollected {
			if v.Item == item {
				ops = append(ops, v.Op)
			}
		}
		if len(ops) > 0 {
			b.WriteString("\n")
			for _, op := range ops {
				fmt.Fprintf(&b, "- `%s` (%s %s)\n", op.Key(), op.Method, op.Path)
			}
		}
		b.WriteString("\n")
	}

	manualReads := 0
	for _, read := range cfg.Reads {
		if len(read.Operations) == 0 {
			manualReads++
		}
	}
	if len(r.Reads)+manualReads > 0 {
		b.WriteString("## Calls the sandbox never exercises\n\n")
		b.WriteString("The collector makes these calls when the tenant has something the sandbox lacks, so no recording holds them.\n\n")
		for _, g := range r.Reads {
			fmt.Fprintf(&b, "- `%s` (%s %s): %s, when %s.\n", g.Op.Key(), g.Op.Method, g.Op.Path, g.Read.Collector, strings.TrimSuffix(g.Read.When, "."))
		}
		for _, read := range cfg.Reads {
			if len(read.Operations) == 0 {
				fmt.Fprintf(&b, "- %s, when %s.\n", read.Collector, strings.TrimSuffix(read.When, "."))
			}
		}
		b.WriteString("\n")
	}

	if len(cfg.Irrelevant) > 0 {
		b.WriteString("## Left out as irrelevant\n\n")
		for i := range cfg.Irrelevant {
			item := &cfg.Irrelevant[i]
			var keys []string
			for _, v := range r.Irrelevant {
				if v.Item == item {
					keys = append(keys, "`"+v.Op.Key()+"`")
				}
			}
			if len(keys) == 0 {
				continue
			}
			fmt.Fprintf(&b, "- **%s.** %s\n", strings.TrimSuffix(item.Reason, "."), strings.Join(keys, ", "))
		}
		b.WriteString("\n")
	}

	if len(r.Acknowledged) > 0 {
		b.WriteString("## Outside the description\n\n")
		reasons := map[string]string{}
		for _, u := range cfg.Unmatched {
			reasons[u.Operation] = u.Reason
		}
		for _, c := range r.Acknowledged {
			fmt.Fprintf(&b, "- %s (%s %s): %s\n", c.Operation, c.Method, pathOf(c.URL), strings.TrimSuffix(reasons[c.Operation], "."))
		}
		b.WriteString("\n")
	}

	b.WriteString("Generated by `epack sdk surface` from `docs/surface.yaml` and the collector's recordings. Edit the verdicts there, then run `epack sdk surface --write`.\n")
	return b.String()
}

// Area groups operations for the reference: the description's category
// when it has one, else the first path segment after any api or version
// segments. Tags are not used, since vendors name them for their SDKs.
func Area(op *Operation) string {
	if op.Category != "" {
		return op.Category
	}
	for _, seg := range splitPath(op.Path) {
		if seg == "api" || versionSegment.MatchString(seg) || isParam(seg) {
			continue
		}
		return strings.TrimPrefix(seg, ".")
	}
	return "other"
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ReplaceSection puts the rendered section in place of the document's Not
// Collected section, or before its Use Cases section when it has none, or
// at the end.
func ReplaceSection(doc []byte, section string) []byte {
	text := string(doc)
	section = strings.TrimRight(section, "\n") + "\n"
	if loc := sectionStart.FindStringIndex(text); loc != nil {
		rest := text[loc[1]:]
		end := len(text)
		if next := nextSection.FindStringIndex(rest); next != nil {
			end = loc[1] + next[0]
		}
		return []byte(text[:loc[0]] + section + "\n" + strings.TrimLeft(text[end:], "\n"))
	}
	if loc := regexp.MustCompile(`(?m)^## Use Cases[ \t]*$`).FindStringIndex(text); loc != nil {
		return []byte(text[:loc[0]] + section + "\n" + text[loc[0]:])
	}
	return []byte(strings.TrimRight(text, "\n") + "\n\n" + section)
}

// CurrentSection returns the document's Not Collected section as written,
// or "" when it has none.
func CurrentSection(doc []byte) string {
	text := string(doc)
	loc := sectionStart.FindStringIndex(text)
	if loc == nil {
		return ""
	}
	rest := text[loc[1]:]
	end := len(text)
	if next := nextSection.FindStringIndex(rest); next != nil {
		end = loc[1] + next[0]
	}
	return strings.TrimRight(text[loc[0]:end], "\n") + "\n"
}
