package surface

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Exercised is a description operation the recordings call, with the
// collector's own operation names for it and how many responses each has.
type Exercised struct {
	Op        *Operation
	Collector map[string]int
}

// Verdict is one in-scope operation the recordings never call, with the
// item that gives its verdict when one does.
type Verdict struct {
	Op   *Operation
	Item *Item
}

// ReadGap is an operation the collector reads that the sandbox never made
// it call.
type ReadGap struct {
	Op   *Operation
	Read *Read
}

// Report is what the surface check found.
type Report struct {
	SpecOperations int
	InScope        int
	Deprecated     int
	Exercised      []Exercised
	// Unmatched holds recorded requests no operation describes, one per
	// collector operation, method and path.
	Unmatched []Call
	// Acknowledged holds the unmatched requests surface.yaml accounts for.
	Acknowledged []Call
	NotCollected []Verdict
	Irrelevant   []Verdict
	// Reads holds in-scope operations the collector calls that no recording
	// holds, with the Read that says what the sandbox lacks.
	Reads []ReadGap
	// Unverdicted holds in-scope operations with no verdict.
	Unverdicted []*Operation
	// Problems are what --check fails on, one sentence each.
	Problems []string
}

// Analyze matches the recorded calls to the description and applies the
// verdicts in cfg.
func Analyze(spec *Spec, cfg *Config, calls []Call) *Report {
	r := &Report{SpecOperations: len(spec.Operations)}
	exercised := map[*Operation]map[string]int{}
	unmatched := map[string]Call{}
	acked := map[string]bool{}
	for _, u := range cfg.Unmatched {
		acked[u.Operation] = true
	}
	for _, call := range calls {
		op, ok := spec.MatchSpanning(call.Method, call.URL, cfg.Scope.SpanningParams)
		if !ok {
			key := call.Operation + " " + call.Method + " " + pathOf(call.URL)
			if _, seen := unmatched[key]; !seen {
				unmatched[key] = call
			}
			continue
		}
		if exercised[op] == nil {
			exercised[op] = map[string]int{}
		}
		exercised[op][call.Operation]++
	}
	for op, names := range exercised {
		r.Exercised = append(r.Exercised, Exercised{Op: op, Collector: names})
	}
	sort.Slice(r.Exercised, func(i, j int) bool { return r.Exercised[i].Op.Key() < r.Exercised[j].Op.Key() })
	for _, call := range unmatched {
		if acked[call.Operation] {
			r.Acknowledged = append(r.Acknowledged, call)
		} else {
			r.Unmatched = append(r.Unmatched, call)
		}
	}
	sortCalls(r.Unmatched)
	sortCalls(r.Acknowledged)
	for _, call := range r.Unmatched {
		r.Problems = append(r.Problems, fmt.Sprintf("the recordings call %s %s as %s, which the API description does not describe; add it to unmatched with a reason", call.Method, pathOf(call.URL), call.Operation))
	}
	for _, u := range cfg.Unmatched {
		found := false
		for _, call := range r.Acknowledged {
			if call.Operation == u.Operation {
				found = true
				break
			}
		}
		if !found {
			r.Problems = append(r.Problems, fmt.Sprintf("unmatched lists %s, which no recording calls outside the description", u.Operation))
		}
	}

	for _, op := range spec.Operations {
		if op.Deprecated {
			r.Deprecated++
		}
		if !cfg.Scope.InScope(op) {
			continue
		}
		r.InScope++
		if exercised[op] != nil {
			continue
		}
		if read := readFor(cfg, op); read != nil {
			r.Reads = append(r.Reads, ReadGap{Op: op, Read: read})
			continue
		}
		notCollected, ncLevel, ncTie := best(cfg.NotCollected, op)
		irrelevant, irLevel, irTie := best(cfg.Irrelevant, op)
		if ncTie != nil && (irrelevant == nil || ncLevel >= irLevel) {
			r.Problems = append(r.Problems, fmt.Sprintf("%s is covered equally by two not_collected items, %s and %s", op.Key(), notCollected.Label(), ncTie.Label()))
			continue
		}
		if irTie != nil && (notCollected == nil || irLevel >= ncLevel) {
			r.Problems = append(r.Problems, fmt.Sprintf("%s is covered equally by two irrelevant items, %s and %s", op.Key(), irrelevant.Label(), irTie.Label()))
			continue
		}
		switch {
		case notCollected != nil && irrelevant != nil && ncLevel == irLevel:
			r.Problems = append(r.Problems, fmt.Sprintf("%s is both not collected (%s) and irrelevant (%s)", op.Key(), notCollected.Label(), irrelevant.Label()))
		case notCollected != nil && (irrelevant == nil || ncLevel > irLevel):
			r.NotCollected = append(r.NotCollected, Verdict{Op: op, Item: notCollected})
		case irrelevant != nil:
			r.Irrelevant = append(r.Irrelevant, Verdict{Op: op, Item: irrelevant})
		default:
			r.Unverdicted = append(r.Unverdicted, op)
		}
	}
	for _, op := range r.Unverdicted {
		r.Problems = append(r.Problems, fmt.Sprintf("%s (%s %s) has no verdict", op.Key(), op.Method, op.Path))
	}

	for _, read := range cfg.Reads {
		for _, name := range read.Operations {
			op, ok := spec.Lookup(name)
			if !ok {
				r.Problems = append(r.Problems, fmt.Sprintf("reads names %s, which the API description does not describe", name))
			} else if exercised[op] != nil {
				r.Problems = append(r.Problems, fmt.Sprintf("reads names %s, which the recordings now call; move it out of reads", name))
			}
		}
	}
	items := append(append([]Item{}, cfg.NotCollected...), cfg.Irrelevant...)
	for _, item := range items {
		for _, name := range item.Operations {
			op, ok := spec.Lookup(name)
			if !ok {
				r.Problems = append(r.Problems, fmt.Sprintf("%s names %s, which the API description does not describe", item.Label(), name))
				continue
			}
			if exercised[op] != nil {
				r.Problems = append(r.Problems, fmt.Sprintf("%s names %s, which the recordings call", item.Label(), name))
			}
		}
	}
	return r
}

func readFor(cfg *Config, op *Operation) *Read {
	for i := range cfg.Reads {
		for _, name := range cfg.Reads[i].Operations {
			if name == op.Key() || strings.EqualFold(name, op.Method+" "+op.Path) {
				return &cfg.Reads[i]
			}
		}
	}
	return nil
}

// best finds the item that covers op most specifically, and a second item
// that covers it equally when there is one. An item's priority counts
// before its specificity.
func best(items []Item, op *Operation) (*Item, int, *Item) {
	var found, tie *Item
	level := 0
	for i := range items {
		l := items[i].Specificity(op)
		if l == 0 {
			continue
		}
		l += items[i].Priority << 24
		switch {
		case l > level:
			found, level, tie = &items[i], l, nil
		case l == level:
			tie = &items[i]
		}
	}
	return found, level, tie
}

func pathOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Path
}

func sortCalls(calls []Call) {
	sort.Slice(calls, func(i, j int) bool {
		if calls[i].Operation != calls[j].Operation {
			return calls[i].Operation < calls[j].Operation
		}
		return calls[i].URL < calls[j].URL
	})
}

// CollectorNames lists the collector's operation names for an exercised
// description operation, most frequent first.
func (e Exercised) CollectorNames() string {
	names := make([]string, 0, len(e.Collector))
	for name := range e.Collector {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		if e.Collector[names[i]] != e.Collector[names[j]] {
			return e.Collector[names[i]] > e.Collector[names[j]]
		}
		return names[i] < names[j]
	})
	return strings.Join(names, ", ")
}
