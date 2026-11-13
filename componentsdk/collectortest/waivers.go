package collectortest

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/locktivity/epack/internal/tracemap"
)

// Waiver turns a check off or softens one, for a stated reason and until a
// date. Every check in the kit is on unless a waiver names it, so a suite
// that is green says what it does not test. The suite's trace carries its
// waivers, so the trace map and the build file report them, and the
// conformance harness and the registry can show them. From the day a waiver
// expires, the kit runs the check it covered and reports the waiver as a
// violation.
//
// Check names what is waived: a check from CheckNames, which the waiver
// turns off, or one of the softenings. WaiveFault leaves the fault Subject
// names out of the matrix. WaiveInsensitive marks the operation Subject
// names as one whose responses change no value, such as a token exchange,
// so the sensitivity and field_faults checks skip it and a fault on it need
// not leave a gap. WaiveCapped marks an operation that may leave a next page
// unread: a list the collector cuts short on purpose, with a partial gap
// where it stops, or a polling API that always offers another page.
// WaiveOrdered marks an operation whose answers come in an order the vendor
// documents, so the order check does not reverse them. WaiveIgnore names
// values that may change under a fault without a gap, as "<artifact path>
// <pointer prefix>", or a whole artifact as its path alone. WaiveIgnoredField
// names a state field the collector may ignore, as "<operation> <pattern>",
// written as the fields check reports it. WaiveRecording declares that the
// suite replays no recording of the sandbox or test account Subject names
// yet, such as before one exists; the conformance harness then passes its
// recording rule and reports the waiver, and the kit reports the waiver once
// the suite does replay a recording.
//
// Reason says why, in a sentence that names its source where there is one,
// such as the vendor's documentation. Expires is the date the waiver lapses,
// as YYYY-MM-DD, at most WaiverHorizon out. Renewing a waiver means reading
// its reason again and writing a new date.
type Waiver = tracemap.Waiver

// The softenings a Waiver.Check may name, besides a check from CheckNames.
const (
	WaiveFault        = "fault"
	WaiveInsensitive  = "insensitive"
	WaiveCapped       = "capped"
	WaiveOrdered      = "ordered"
	WaiveIgnore       = "ignore"
	WaiveIgnoredField = "ignored_field"
	WaiveRecording    = "recording"
)

// WaiverHorizon is the longest a waiver may run from the day the suite is
// checked, so every waiver is read again at least once a year.
const WaiverHorizon = 366 * 24 * time.Hour

// softenings lists the Waiver.Check values that are not checks.
var softenings = []string{WaiveFault, WaiveInsensitive, WaiveCapped, WaiveOrdered, WaiveIgnore, WaiveIgnoredField, WaiveRecording}

// waived is what the suite's current waivers turn off or soften, and the
// waivers that have expired, which the kit no longer applies.
type waived struct {
	checks, faults, insensitive, capped, ordered map[string]bool
	// recording holds the sandboxes the suite declares no recording of yet.
	recording map[string]bool
	// ignore holds pointer prefixes by artifact path, as the collector names
	// the path. ignoredFields holds state field patterns by operation.
	ignore, ignoredFields map[string][]string
	expired               []Waiver
}

// label names a waiver in messages: its check, and its subject when it has
// one.
func waiverLabel(w Waiver) string {
	if w.Subject == "" {
		return w.Check
	}
	return w.Check + " " + w.Subject
}

// validateWaivers returns an error for a waiver the kit cannot apply, and
// otherwise what the suite's waivers turn off or soften as of now.
func validateWaivers(waivers []Waiver, now time.Time) (waived, error) {
	w := waived{
		checks: map[string]bool{}, faults: map[string]bool{}, insensitive: map[string]bool{}, capped: map[string]bool{}, ordered: map[string]bool{},
		recording: map[string]bool{}, ignore: map[string][]string{}, ignoredFields: map[string][]string{},
	}
	seen := map[string]bool{}
	for _, wv := range waivers {
		label := waiverLabel(wv)
		if err := checkWaiverShape(wv); err != nil {
			return w, err
		}
		if seen[label] {
			return w, fmt.Errorf("Suite.Waivers lists %s twice", label)
		}
		seen[label] = true
		expires, err := time.Parse(tracemap.WaiverDate, wv.Expires)
		if err != nil {
			return w, fmt.Errorf("the waiver on %s expires %q; write the date as YYYY-MM-DD", label, wv.Expires)
		}
		if expires.After(now.Add(WaiverHorizon)) {
			return w, fmt.Errorf("the waiver on %s runs until %s, more than a year; a waiver expires within a year, so its reason is read again", label, wv.Expires)
		}
		if !now.Before(expires) {
			w.expired = append(w.expired, wv)
			continue
		}
		w.apply(wv)
	}
	return w, nil
}

// checkWaiverShape returns an error for a waiver with a field missing or a
// subject that does not fit its check.
func checkWaiverShape(wv Waiver) error {
	label := waiverLabel(wv)
	fields := strings.Fields(wv.Subject)
	switch {
	case wv.Check == "":
		return fmt.Errorf("a waiver names no check: %+v", wv)
	case wv.Check == "waivers":
		return fmt.Errorf("the waivers check cannot be waived")
	case strings.TrimSpace(wv.Reason) == "":
		return fmt.Errorf("the waiver on %s has no Reason; say why the check does not apply, and where that is documented", label)
	case wv.Expires == "":
		return fmt.Errorf("the waiver on %s has no Expires; give the date it lapses, as YYYY-MM-DD, within a year", label)
	case slices.Contains(CheckNames(), wv.Check):
		if wv.Subject != "" {
			return fmt.Errorf("the waiver on %s turns a whole check off, so it takes no Subject", label)
		}
	case !slices.Contains(softenings, wv.Check):
		return fmt.Errorf("the waiver on %s names no check: the checks are %s, and the softenings %s", label, strings.Join(CheckNames(), ", "), strings.Join(softenings, ", "))
	case wv.Check == WaiveIgnore && (len(fields) == 0 || len(fields) > 2 || (len(fields) == 2 && !strings.HasPrefix(fields[1], "/"))):
		return fmt.Errorf("the waiver on %s needs a Subject of an artifact path and a pointer prefix, such as %q, or the path alone for a whole artifact", label, "artifacts/demo.json /diagnostics")
	case wv.Check == WaiveIgnoredField && len(fields) != 2:
		return fmt.Errorf("the waiver on %s needs a Subject of an operation and a field pattern, such as %q, as the fields check reports them", label, "demo.users.list /*/status")
	case wv.Check != WaiveIgnore && wv.Check != WaiveIgnoredField && len(fields) != 1:
		return fmt.Errorf("the waiver on %s needs a Subject of one %s name", label, waiverSubject(wv.Check))
	}
	return nil
}

// waiverSubject says what a softening's subject names.
func waiverSubject(check string) string {
	switch check {
	case WaiveFault:
		return "fault"
	case WaiveRecording:
		return "sandbox"
	}
	return "operation"
}

// apply adds a current waiver to what the kit applies.
func (w *waived) apply(wv Waiver) {
	fields := strings.Fields(wv.Subject)
	switch wv.Check {
	case WaiveFault:
		w.faults[wv.Subject] = true
	case WaiveInsensitive:
		w.insensitive[wv.Subject] = true
	case WaiveCapped:
		w.capped[wv.Subject] = true
	case WaiveOrdered:
		w.ordered[wv.Subject] = true
	case WaiveRecording:
		w.recording[wv.Subject] = true
	case WaiveIgnore:
		prefix := ""
		if len(fields) == 2 {
			prefix = fields[1]
		}
		w.ignore[fields[0]] = append(w.ignore[fields[0]], prefix)
	case WaiveIgnoredField:
		w.ignoredFields[fields[0]] = append(w.ignoredFields[fields[0]], fields[1])
	default:
		w.checks[wv.Check] = true
	}
}

// sorted returns the keys of a set in order.
func sorted(set map[string]bool) []string {
	return slices.Sorted(maps.Keys(set))
}

// sortedWaivers returns a suite's waivers in the order the trace lists
// them.
func sortedWaivers(waivers []Waiver) []Waiver {
	out := slices.Clone(waivers)
	slices.SortFunc(out, tracemap.CompareWaivers)
	return out
}

// reportWaivers reports each waiver that has lapsed, whose check runs again
// from that day, and a recording waiver the suite has outgrown by replaying
// a recording.
func (k *kit) reportWaivers() {
	for _, wv := range k.waived.expired {
		k.violate("waivers", waiverLabel(wv), "the waiver on %s expired on %s, so the check runs again; fix what it waived, or renew it with a date within a year if its reason still holds: %s", waiverLabel(wv), wv.Expires, wv.Reason)
	}
	if n := k.recordings(); n > 0 {
		for _, sandbox := range sorted(k.waived.recording) {
			k.violate("waivers", WaiveRecording+" "+sandbox, "the suite waives the recording of %s but replays %d; remove the waiver", sandbox, n)
		}
	}
}

// recordings counts the suite's scenarios that LoadScenario loaded from a
// recording.
func (k *kit) recordings() int {
	n := 0
	for _, sc := range k.suite.Scenarios {
		if sc.source != "" {
			n++
		}
	}
	return n
}

// oldSuiteFields returns an error line for each suite field that waivers
// replace and the suite still sets, with the waiver that stands in for its
// first entry.
func oldSuiteFields(s Suite) []string {
	expires := time.Now().AddDate(0, 6, 0).Format(tracemap.WaiverDate)
	example := func(check, subject string) string {
		w := fmt.Sprintf("collectortest.Waiver{Check: %q", check)
		if subject != "" {
			w += fmt.Sprintf(", Subject: %q", subject)
		}
		return w + `, Reason: "...", Expires: "` + expires + `"}`
	}
	firstPair := func(m map[string][]string) string {
		for _, key := range slices.Sorted(maps.Keys(m)) {
			return strings.TrimSpace(key + " " + strings.Join(m[key][:min(1, len(m[key]))], ""))
		}
		return ""
	}
	var out []string
	add := func(field, check, subject string) {
		out = append(out, fmt.Sprintf("Suite.%s is no longer read; declare each entry as a waiver in Suite.Waivers, with a reason and an expiry, such as %s", field, example(check, subject)))
	}
	if len(s.SkipChecks) > 0 {
		add("SkipChecks", s.SkipChecks[0], "")
	}
	if len(s.SkipFaults) > 0 {
		add("SkipFaults", WaiveFault, s.SkipFaults[0])
	}
	if len(s.Insensitive) > 0 {
		add("Insensitive", WaiveInsensitive, s.Insensitive[0])
	}
	if len(s.Capped) > 0 {
		add("Capped", WaiveCapped, s.Capped[0])
	}
	if len(s.Ordered) > 0 {
		add("Ordered", WaiveOrdered, s.Ordered[0])
	}
	if len(s.Ignore) > 0 {
		add("Ignore", WaiveIgnore, firstPair(s.Ignore))
	}
	if len(s.IgnoredFields) > 0 {
		add("IgnoredFields", WaiveIgnoredField, firstPair(s.IgnoredFields))
	}
	return out
}
