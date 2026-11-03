package componentsdk

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"
)

// Vocabulary is the set of values a vendor's field can take, as listed in
// the vendor's own catalog. Examples are Okta's System Log event types and
// Microsoft Graph's authentication method types. A collector keeps the
// vocabulary in a file refreshed from that catalog. It checks its own
// constants and the values the vendor sends against the vocabulary. A
// misspelled constant then fails before the collector ships, and a value
// the vendor added later shows up in the collector result.
type Vocabulary struct {
	// Name identifies the vocabulary in the collector result, such as
	// "okta.event_types".
	Name string `json:"name"`
	// Source is where the values come from, such as the URL of the vendor's
	// catalog.
	Source string `json:"source"`
	// FetchedAt is when the values were read from the source.
	FetchedAt string `json:"fetched_at,omitempty"`
	// Values lists the values.
	Values []string `json:"values"`

	known map[string]bool
}

// LoadVocabulary reads a vocabulary file, such as one a collector embeds with
// the go:embed directive. The file is a JSON object with name, source,
// fetched_at, and values.
func LoadVocabulary(raw []byte) (*Vocabulary, error) {
	var v Vocabulary
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("vocabulary: %w", err)
	}
	switch {
	case v.Name == "":
		return nil, errors.New("vocabulary: name is required")
	case v.Source == "":
		return nil, fmt.Errorf("vocabulary %s: source is required", v.Name)
	case len(v.Values) == 0:
		return nil, fmt.Errorf("vocabulary %s: values are required", v.Name)
	}
	v.known = make(map[string]bool, len(v.Values))
	for _, value := range v.Values {
		v.known[value] = true
	}
	return &v, nil
}

// MustLoadVocabulary is like LoadVocabulary but panics when the file cannot
// be read, as regexp.MustCompile does. Use it for a file embedded in the
// collector.
func MustLoadVocabulary(raw []byte) *Vocabulary {
	v, err := LoadVocabulary(raw)
	if err != nil {
		panic(err)
	}
	return v
}

// Has reports whether value is in the vocabulary.
func (v *Vocabulary) Has(value string) bool { return v.known[value] }

// Must returns values. It panics, as regexp.MustCompile does, when one of
// them is not in the vocabulary. Such a value is a constant that the
// collector compares vendor values with but that the vendor never sends,
// such as a misspelled event type. Call Must where the constants are
// declared, so that any test of the collector fails on a bad constant.
func (v *Vocabulary) Must(values ...string) []string {
	var missing []string
	for _, value := range values {
		if !v.Has(value) {
			missing = append(missing, value)
		}
	}
	if len(missing) > 0 {
		panic(fmt.Sprintf("vocabulary %s from %s lacks %q", v.Name, v.Source, missing))
	}
	return values
}

// Seen reports whether value, read from the vendor, is in the vocabulary.
// When it is not, Seen records the value in the collector result. The result
// then shows that the vendor sends values the collector does not handle.
func (v *Vocabulary) Seen(ctx CollectorContext, value string) bool {
	if v.Has(value) {
		return true
	}
	if r := runOf(ctx); r != nil {
		r.unrecognized.add(v.Name, value)
	}
	return false
}

// maxUnrecognized is the most values the result lists for one vocabulary.
const maxUnrecognized = 50

// unrecognizedLog holds the values a run read that are not in its
// vocabularies.
type unrecognizedLog struct {
	mu     sync.Mutex
	values map[string][]string
	counts map[string]int
}

func (l *unrecognizedLog) add(vocabulary, value string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.values == nil {
		l.values, l.counts = map[string][]string{}, map[string]int{}
	}
	if slices.Contains(l.values[vocabulary], value) {
		return
	}
	l.counts[vocabulary]++
	if len(l.values[vocabulary]) < maxUnrecognized {
		l.values[vocabulary] = append(l.values[vocabulary], value)
	}
}

// Unrecognized lists the values the run read that are not in one
// vocabulary.
type Unrecognized struct {
	Vocabulary string `json:"vocabulary"`
	// Count is the number of distinct values. It appears at every level.
	Count int `json:"count"`
	// Values lists the first 50 values, sorted. It appears at the audit and
	// internal levels only, because a vocabulary applied to the wrong field
	// could hold a name.
	Values []string `json:"values,omitempty"`
}

// list returns the log's vocabularies and their values, each sorted.
func (l *unrecognizedLog) list() []Unrecognized {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []Unrecognized
	for name, count := range l.counts {
		u := Unrecognized{Vocabulary: name, Count: count, Values: slices.Clone(l.values[name])}
		sort.Strings(u.Values)
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Vocabulary < out[j].Vocabulary })
	return out
}
