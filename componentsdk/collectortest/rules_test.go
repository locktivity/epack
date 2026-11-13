package collectortest

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// alwaysOnChecks are the kit's checks that run on every suite and are not in
// CheckNames, as Violation.Check documents them.
var alwaysOnChecks = []string{"scenario", "secrets", "schema", "schema_unusable", "recording", "export"}

// rule is one row of the common or collector tables in
// docs/component-rules.md.
type rule struct {
	id, level, text, enforced string
	line                      int
}

// token is one backticked enforcement token of a rule's Enforced by cell.
type token struct{ kind, value string }

var (
	ruleRow     = regexp.MustCompile(`^\| ((?:C|COL)-\d+) \| (MUST NOT|MUST|SHOULD|MAY) \| (.*) \| (.*) \|$`)
	backticked  = regexp.MustCompile("`([^`]+)`")
	harnessID   = regexp.MustCompile(`"((?:C|COL)-\d{3})"`)
	requirement = regexp.MustCompile(`\{ID: "((?:C|COL)-\d+)", Level: Level(Must|Should|May),`)
	appendixRow = regexp.MustCompile(`^\| (MUST|SHOULD|MAY) \| (\d+) \| (.*) \|$`)
)

// TestRulesNameTheirChecks holds docs/component-rules.md to its Enforcement
// section: every common and collector rule names what enforces it, every
// MUST rule names a check or a backlog entry, every kit check is named
// against a rule, every name matches the code, and Appendix A agrees with
// the tables.
func TestRulesNameTheirChecks(t *testing.T) {
	root := filepath.Join("..", "..")
	doc := readFile(t, filepath.Join(root, "docs", "component-rules.md"))
	rules := collectorRules(t, doc)
	if len(rules) < 50 {
		t.Fatalf("parsed %d collector rules, want the common and collector tables", len(rules))
	}
	kitChecks := append(slices.Clone(CheckNames()), alwaysOnChecks...)
	harness := harnessIDs(t, root)
	sdk := sdkSource(t, root)

	named := map[string]bool{}
	byID := map[string]rule{}
	for _, r := range rules {
		byID[r.id] = r
		where := fmt.Sprintf("component-rules.md:%d %s", r.line, r.id)
		tokens, err := enforcementTokens(r.enforced)
		if err != nil {
			t.Errorf("%s: %v", where, err)
			continue
		}
		if len(tokens) == 0 {
			t.Errorf("%s: the Enforced by cell names no token; see the Enforcement section", where)
			continue
		}
		enforced, backlog, none := false, false, false
		for _, tk := range tokens {
			switch tk.kind {
			case "kit":
				enforced = true
				named[tk.value] = true
				if !slices.Contains(kitChecks, tk.value) {
					t.Errorf("%s: kit:%s names no check; CheckNames lists %s", where, tk.value, strings.Join(CheckNames(), ", "))
				}
			case "conformance":
				enforced = true
				id := tk.value
				if id == "" {
					id = r.id
				}
				if !harness[id] {
					t.Errorf("%s: the harness never reports %s; internal/componentconf passes, fails, or skips no such ID", where, id)
				}
			case "sdk":
				enforced = true
				if !regexp.MustCompile(`\b` + regexp.QuoteMeta(tk.value) + `\b`).MatchString(sdk) {
					t.Errorf("%s: sdk:%s names nothing in componentsdk", where, tk.value)
				}
			case "cli":
				enforced = true
				if !strings.HasPrefix(tk.value, "epack ") {
					t.Errorf("%s: cli:%s is not an epack command", where, tk.value)
				}
			case "backlog":
				backlog = true
				if strings.TrimSpace(strings.SplitN(r.enforced, "`backlog`", 2)[1]) == "" {
					t.Errorf("%s: backlog without a line on what the check would be", where)
				}
			case "none":
				none = true
			}
		}
		must := strings.HasPrefix(r.level, "MUST")
		switch {
		case must && none:
			t.Errorf("%s: a MUST rule cannot be `none`; name the check or mark it `backlog`", where)
		case must && !enforced && !backlog:
			t.Errorf("%s: a MUST rule names no check and carries no `backlog`", where)
		}
	}
	for _, name := range CheckNames() {
		if !named[name] {
			t.Errorf("the kit check %s is named against no rule; add a rule, or name it against the rule it enforces", name)
		}
	}

	// The harness's registry of collector rules is a subset of the tables,
	// at the same level.
	reqs := readFile(t, filepath.Join(root, "internal", "componentconf", "requirements.go"))
	for _, m := range requirement.FindAllStringSubmatch(reqs, -1) {
		r, ok := byID[m[1]]
		want := map[string]string{"Must": "MUST", "Should": "SHOULD", "May": "MAY"}[m[2]]
		switch {
		case !ok:
			t.Errorf("requirements.go lists %s, which component-rules.md does not", m[1])
		case strings.TrimSuffix(r.level, " NOT") != want:
			t.Errorf("requirements.go lists %s as %s, component-rules.md as %s", m[1], want, r.level)
		}
	}

	checkAppendix(t, doc, rules)
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// collectorRules parses the rows of the tables between the common and the
// tool sections, which are the rules that apply to collectors.
func collectorRules(t *testing.T, doc string) []rule {
	t.Helper()
	var out []rule
	in := false
	for i, line := range strings.Split(doc, "\n") {
		switch {
		case strings.HasPrefix(line, "## 1. Common Requirements"):
			in = true
		case strings.HasPrefix(line, "## 3. Tool Requirements"):
			in = false
		}
		if !in {
			continue
		}
		if m := ruleRow.FindStringSubmatch(line); m != nil {
			out = append(out, rule{id: m[1], level: m[2], text: m[3], enforced: m[4], line: i + 1})
		} else if strings.HasPrefix(line, "| C-") || strings.HasPrefix(line, "| COL-") {
			t.Errorf("component-rules.md:%d: a rule row without an Enforced by cell: %s", i+1, line)
		}
	}
	return out
}

// enforcementTokens returns the tokens of an Enforced by cell. A backticked
// span that names a token kind is a token; any other with a colon is a
// mistyped one.
func enforcementTokens(cell string) ([]token, error) {
	var out []token
	for _, m := range backticked.FindAllStringSubmatch(cell, -1) {
		span := m[1]
		switch {
		case span == "backlog", span == "none", span == "conformance":
			out = append(out, token{kind: span})
		case strings.HasPrefix(span, "kit:"), strings.HasPrefix(span, "sdk:"), strings.HasPrefix(span, "cli:"), strings.HasPrefix(span, "conformance:"):
			kind, value, _ := strings.Cut(span, ":")
			if value == "" {
				return nil, fmt.Errorf("the token `%s` names nothing", span)
			}
			out = append(out, token{kind: kind, value: value})
		case strings.Contains(span, ":") && !strings.Contains(span, " ") && !strings.Contains(span, "/"):
			return nil, fmt.Errorf("`%s` looks like a token but names no kind; the kinds are kit, conformance, sdk, and cli", span)
		}
	}
	return out, nil
}

// harnessIDs returns the requirement IDs the collector harness passes,
// fails, or skips, from the source of the checks themselves.
func harnessIDs(t *testing.T, root string) map[string]bool {
	t.Helper()
	ids := map[string]bool{}
	for _, name := range []string{"collector.go", "result.go", "runner.go"} {
		for _, m := range harnessID.FindAllStringSubmatch(readFile(t, filepath.Join(root, "internal", "componentconf", name)), -1) {
			ids[m[1]] = true
		}
	}
	return ids
}

// sdkSource returns the source of the componentsdk package, tests left out.
func sdkSource(t *testing.T, root string) string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(root, "componentsdk", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, f := range files {
		if !strings.HasSuffix(f, "_test.go") {
			b.WriteString(readFile(t, f))
		}
	}
	return b.String()
}

// checkAppendix compares the Collectors table of Appendix A with the rules.
func checkAppendix(t *testing.T, doc string, rules []rule) {
	t.Helper()
	want := map[string][]string{}
	for _, r := range rules {
		want[strings.TrimSuffix(r.level, " NOT")] = append(want[strings.TrimSuffix(r.level, " NOT")], r.id)
	}
	for _, ids := range want {
		sort.Slice(ids, func(i, j int) bool { return ruleLess(ids[i], ids[j]) })
	}
	start := strings.Index(doc, "### Collectors\n")
	end := strings.Index(doc, "### Tools\n")
	if start < 0 || end < start {
		t.Fatal("Appendix A has no Collectors table")
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(doc[start:end], "\n") {
		m := appendixRow.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		level := m[1]
		seen[level] = true
		got := strings.Split(m[3], ", ")
		if m[3] == "-" {
			got = nil
		}
		if !slices.Equal(got, want[level]) {
			t.Errorf("Appendix A lists the collectors' %s rules as %v, the tables give %v", level, got, want[level])
		}
		if n, _ := strconv.Atoi(m[2]); n != len(want[level]) {
			t.Errorf("Appendix A counts %d %s rules for collectors, the tables give %d", n, level, len(want[level]))
		}
	}
	for _, level := range []string{"MUST", "SHOULD", "MAY"} {
		if !seen[level] {
			t.Errorf("Appendix A has no %s row for collectors", level)
		}
	}
}

// ruleLess orders rule IDs by prefix, common rules first, then by number.
func ruleLess(a, b string) bool {
	pa, na, _ := strings.Cut(a, "-")
	pb, nb, _ := strings.Cut(b, "-")
	if pa != pb {
		return pa == "C"
	}
	ia, _ := strconv.Atoi(na)
	ib, _ := strconv.Atoi(nb)
	return ia < ib
}
