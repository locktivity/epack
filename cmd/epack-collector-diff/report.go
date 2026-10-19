package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/locktivity/epack/pack/diff"
)

const (
	statusCompared = "compared"
	statusAdded    = "added"
	statusRemoved  = "removed"
)

// report is the full result, as --json writes it.
type report struct {
	Summary summary `json:"summary"`
	// ControlsCompared is true when a profile was given.
	ControlsCompared bool             `json:"controls_compared"`
	Profile          *profileInfo     `json:"profile,omitempty"`
	Scenarios        []scenarioReport `json:"scenarios"`
}

// summary counts scenarios by status, and the changes in the scenarios
// present in both trees.
type summary struct {
	Scenarios        int `json:"scenarios"`
	ChangedScenarios int `json:"changed_scenarios"`
	AddedScenarios   int `json:"added_scenarios"`
	RemovedScenarios int `json:"removed_scenarios"`
	Changes          int `json:"changes"`
	EvidenceChanges  int `json:"evidence_changes"`
	ControlChanges   int `json:"control_changes"`
}

// scenarioReport is one scenario. Status is "compared" when both trees have
// it, and otherwise "added" (head only) or "removed" (base only), with no
// changes listed.
type scenarioReport struct {
	Suite    string   `json:"suite"`
	Scenario string   `json:"scenario"`
	Status   string   `json:"status"`
	Changes  []change `json:"changes"`
}

func (sr scenarioReport) key() string { return sr.Suite + "/" + sr.Scenario }

func (r *report) summarize() {
	var s summary
	for _, sr := range r.Scenarios {
		switch sr.Status {
		case statusAdded:
			s.AddedScenarios++
		case statusRemoved:
			s.RemovedScenarios++
		default:
			s.Scenarios++
			if len(sr.Changes) > 0 {
				s.ChangedScenarios++
			}
			for _, c := range sr.Changes {
				s.Changes++
				if c.control() {
					s.ControlChanges++
				} else {
					s.EvidenceChanges++
				}
			}
		}
	}
	r.Summary = s
}

var changeLabels = map[string]string{
	kindArtifactAdded:   "Artifact added",
	kindArtifactRemoved: "Artifact removed",
	kindContentChanged:  "Content changed",
	kindValueChanged:    "Value changed",
	kindNewlyNull:       "Newly null",
	kindNewlyAbsent:     "Newly absent",
	kindFieldRemoved:    "Field removed",
	kindFieldAdded:      "Field added",
	kindItemRemoved:     "Item removed",
	kindItemAdded:       "Item added",
	kindStatusChanged:   "Status changed",
	kindSeverityChanged: "Severity changed",
}

// renderMarkdown writes a summary paragraph and a table of changes with at
// most maxRows rows. Control changes come first, so a cap never hides one
// behind evidence changes.
func renderMarkdown(r *report, maxRows int) string {
	var b strings.Builder
	b.WriteString(summaryText(r))
	b.WriteString("\n")
	var controls, evidence []string
	for _, sr := range r.Scenarios {
		for _, c := range sr.Changes {
			metric, base, head := cells(c)
			row := fmt.Sprintf("| %s | %s | %s | %s | %s |\n", text(sr.key()), metric, base, head, changeLabels[c.Kind])
			if c.control() {
				controls = append(controls, row)
			} else {
				evidence = append(evidence, row)
			}
		}
	}
	rows := append(controls, evidence...)
	shown := rows[:min(len(rows), maxRows)]
	if len(shown) > 0 {
		b.WriteString("\n| Scenario | Metric or control | Base | Head | Change |\n| --- | --- | --- | --- | --- |\n")
		for _, row := range shown {
			b.WriteString(row)
		}
		if len(shown) < len(rows) {
			fmt.Fprintf(&b, "\nThe table shows the first %d of %d changes.\n", len(shown), len(rows))
		}
	}
	return b.String()
}

func summaryText(r *report) string {
	s := r.Summary
	var parts []string
	switch {
	case s.Scenarios == 0:
		parts = append(parts, "No scenario is in both trees, so nothing was compared.")
	case s.Changes == 0:
		parts = append(parts, fmt.Sprintf("No changes in %s.", count(s.Scenarios, "scenario", "scenarios")))
	case r.ControlsCompared:
		parts = append(parts, fmt.Sprintf("%s in %d of %s: %d in evidence and %d in control outcomes.",
			count(s.Changes, "change", "changes"), s.ChangedScenarios, count(s.Scenarios, "scenario", "scenarios"),
			s.EvidenceChanges, s.ControlChanges))
	default:
		parts = append(parts, fmt.Sprintf("%s in %d of %s.",
			count(s.Changes, "change", "changes"), s.ChangedScenarios, count(s.Scenarios, "scenario", "scenarios")))
	}
	switch {
	case !r.ControlsCompared:
		parts = append(parts, "Control outcomes were not compared because no profile was given.")
	case r.Profile != nil:
		name := r.Profile.Name
		if name == "" {
			name = r.Profile.ID
		}
		if r.Profile.Version != "" {
			parts = append(parts, fmt.Sprintf("Control outcomes come from the %s profile, version %s.", text(name), text(r.Profile.Version)))
		} else {
			parts = append(parts, fmt.Sprintf("Control outcomes come from the %s profile.", text(name)))
		}
	}
	var added, removed []string
	for _, sr := range r.Scenarios {
		switch sr.Status {
		case statusAdded:
			added = append(added, sr.key())
		case statusRemoved:
			removed = append(removed, sr.key())
		}
	}
	if len(added) > 0 {
		parts = append(parts, "Scenarios only in the head: "+nameList(added)+".")
	}
	if len(removed) > 0 {
		parts = append(parts, "Scenarios only in the base: "+nameList(removed)+".")
	}
	return strings.Join(parts, " ")
}

func nameList(names []string) string {
	const most = 10
	if len(names) <= most {
		return text(strings.Join(names, ", "))
	}
	return text(strings.Join(names[:most], ", ")) + fmt.Sprintf(", and %d more", len(names)-most)
}

func count(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// cells returns a change's Metric or control, Base, and Head cells.
func cells(c change) (metric, base, head string) {
	switch c.Kind {
	case kindStatusChanged, kindSeverityChanged:
		return code(c.Requirement) + " " + text(c.Name), outcomeText(c.Base), outcomeText(c.Head)
	case kindArtifactAdded, kindArtifactRemoved, kindContentChanged:
		return code(c.Artifact), fileText(c.Base), fileText(c.Head)
	}
	target := c.Artifact
	if c.Pointer != "" {
		target += "#" + c.Pointer
	}
	return code(target), valueText(c.Base), valueText(c.Head)
}

func valueText(raw json.RawMessage) string {
	if raw == nil {
		return "absent"
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	_ = dec.Decode(&v)
	return code(truncate(diff.FormatJSONValue(v), 120))
}

// truncate shortens long strings, which the JSON report keeps whole, so one
// value cannot crowd the table.
func truncate(s string, most int) string {
	if r := []rune(s); len(r) > most {
		return string(r[:most-3]) + "..."
	}
	return s
}

func outcomeText(raw json.RawMessage) string {
	if raw == nil {
		return "absent"
	}
	var o outcome
	_ = json.Unmarshal(raw, &o)
	if o.Severity != "" {
		return text(o.Status + " (" + o.Severity + ")")
	}
	return text(o.Status)
}

func fileText(raw json.RawMessage) string {
	if raw == nil {
		return "absent"
	}
	var f struct {
		Bytes int `json:"bytes"`
	}
	_ = json.Unmarshal(raw, &f)
	return count(f.Bytes, "byte", "bytes")
}

// cell keeps s inside one table cell: a pipe would end the cell, and a line
// break the row.
func cell(s string) string {
	return strings.NewReplacer("|", `\|`, "\r", " ", "\n", " ").Replace(s)
}

func text(s string) string {
	return cell(strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s))
}

func code(s string) string {
	fence := "`"
	for strings.Contains(s, fence) {
		fence += "`"
	}
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") {
		s = " " + s + " "
	}
	return fence + cell(s) + fence
}
