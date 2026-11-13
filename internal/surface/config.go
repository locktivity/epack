package surface

import (
	"fmt"
	"slices"
	"strings"

	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/safefile"
	"github.com/locktivity/epack/internal/safeyaml"
)

// DefaultConfigFile is where a collector keeps its surface verdicts.
const DefaultConfigFile = "docs/surface.yaml"

// DefaultRecordingsDir is where the collectortest kit keeps recordings.
const DefaultRecordingsDir = "internal/collector/testdata/recordings"

// Config is a collector's surface.yaml: which vendor API description it is
// checked against, which of its operations are in scope, and a verdict for
// each in-scope operation the recordings never exercise.
type Config struct {
	// Vendor names the vendor in the rendered documentation, such as Okta.
	Vendor string `yaml:"vendor"`
	// Spec pins the one description the verdicts were made against, or
	// Specs pins several, such as Microsoft Graph and the Azure resource
	// providers. With several, --spec takes one file per entry, in order.
	Spec  SpecRef   `yaml:"spec"`
	Specs []SpecRef `yaml:"specs"`
	Scope Scope     `yaml:"scope"`
	// Overview picks what the Not Collected section of the overview says:
	// a few headlines, each folding one or more not_collected items into
	// one sentence a buyer needs. Everything else stays in the coverage
	// reference. With no headlines, the section lists every item.
	Overview []Headline `yaml:"overview"`
	// Reference says where the coverage reference is rendered.
	Reference ReferenceRef `yaml:"reference"`
	// NotCollected is the inventory of what the vendor offers that the
	// collector leaves out. Each item is a section of the coverage
	// reference.
	NotCollected []Item `yaml:"not_collected"`
	// Irrelevant lists operations that bear no security posture, with the
	// reason. They stay out of the documentation.
	Irrelevant []Item `yaml:"irrelevant"`
	// Reads lists operations the collector calls only when the tenant has
	// something the sandbox lacks, so no recording holds them. They are
	// sandbox gaps the report shows, not verdicts.
	Reads []Read `yaml:"reads"`
	// Unmatched acknowledges recorded operations outside the description,
	// such as a token endpoint or a GraphQL query.
	Unmatched []Unmatched `yaml:"unmatched"`
}

// Headline is one bullet of the overview's Not Collected section. Items
// names the not_collected items it stands for, by title. Says defaults to
// the item's own sentence when there is one item.
type Headline struct {
	Title string   `yaml:"title"`
	Says  string   `yaml:"says"`
	Items []string `yaml:"items"`
}

// ReferenceRef locates the coverage reference.
type ReferenceRef struct {
	// File is the reference's path, relative to the module root.
	File string `yaml:"file"`
	// URL is where readers of the published overview find the reference.
	// It defaults to the file on the main branch of the module's GitHub
	// repository, since the registry resolves relative links wrongly.
	URL string `yaml:"url"`
}

// DefaultReferenceFile is where the coverage reference is rendered.
const DefaultReferenceFile = "docs/coverage.md"

// Read is an operation the collector calls that no recording holds.
type Read struct {
	Operations []string `yaml:"operations"`
	// Collector is the collector's own name for the call.
	Collector string `yaml:"collector"`
	// When says what the tenant must have for the collector to make the
	// call, which is what the sandbox lacks.
	When string `yaml:"when"`
}

// SpecRef pins the API description the verdicts were made against.
type SpecRef struct {
	// Name says which description this is in the rendered documents, such
	// as "Microsoft Graph". It defaults to Path.
	Name string `yaml:"name"`
	// Source is the repository or site the description comes from.
	Source string `yaml:"source"`
	// Path is the description's path within Source.
	Path string `yaml:"path"`
	// Revision is the commit or version of Source the verdicts match.
	Revision string `yaml:"revision"`
	// SHA256 is the digest of the description file, when pinned.
	SHA256 string `yaml:"sha256"`
	// File is a local copy of the description, relative to the module root.
	// The --spec flag overrides it.
	File string `yaml:"file"`
}

// Scope decides which operations need a verdict. Only GET operations are
// in scope unless Methods says otherwise, since collectors read.
type Scope struct {
	Methods      []string `yaml:"methods"`
	Tags         []string `yaml:"tags"`
	ExcludeTags  []string `yaml:"exclude_tags"`
	Deprecated   bool     `yaml:"deprecated"`
	PathPrefixes []string `yaml:"path_prefixes"`
	// SpanningParams names more path parameters that may span several
	// segments, besides {path}.
	SpanningParams []string `yaml:"spanning_params"`
}

// Item is one verdict, covering the operations it names directly, every
// operation with one of its tags or categories, every operation under one
// of its paths, where a path ending in * is a prefix, and every operation
// whose path contains one of its path_contains strings, compared without
// regard to case, such as an Azure resource provider's namespace.
type Item struct {
	Title        string   `yaml:"title"`
	Says         string   `yaml:"says"`
	Reason       string   `yaml:"reason"`
	Operations   []string `yaml:"operations"`
	Tags         []string `yaml:"tags"`
	Categories   []string `yaml:"categories"`
	Paths        []string `yaml:"paths"`
	PathContains []string `yaml:"path_contains"`
	// In limits the item to operations of the named descriptions, by the
	// name each entry of specs gives, when several descriptions share path
	// shapes, such as Graph's /subscriptions and Azure's.
	In []string `yaml:"in"`
	// Priority lets an item win over others that cover an operation more
	// specifically, such as a verdict on capacity and usage operations
	// across every Azure resource provider. Higher wins; the default is 0.
	Priority int `yaml:"priority"`
}

// Unmatched acknowledges a recorded operation the description does not
// describe.
type Unmatched struct {
	Operation string `yaml:"operation"`
	Reason    string `yaml:"reason"`
}

// LoadConfig reads surface.yaml beneath root.
func LoadConfig(root, rel string) (*Config, error) {
	data, err := safefile.ReadFileBeneath(root, rel, limits.ConfigFile)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := safeyaml.UnmarshalStrict(data, limits.ConfigFile, &cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", rel, err)
	}
	if cfg.Vendor == "" {
		return nil, fmt.Errorf("%s: vendor is required", rel)
	}
	for i, item := range cfg.NotCollected {
		if item.Title == "" || item.Says == "" {
			return nil, fmt.Errorf("%s: not_collected item %d needs a title and a says sentence", rel, i+1)
		}
	}
	for i, item := range cfg.Irrelevant {
		if item.Reason == "" {
			return nil, fmt.Errorf("%s: irrelevant item %d needs a reason", rel, i+1)
		}
	}
	titles := map[string]bool{}
	for _, item := range cfg.NotCollected {
		if titles[item.Title] {
			return nil, fmt.Errorf("%s: two not_collected items are titled %q", rel, item.Title)
		}
		titles[item.Title] = true
	}
	for i, h := range cfg.Overview {
		if h.Title == "" || len(h.Items) == 0 {
			return nil, fmt.Errorf("%s: overview headline %d needs a title and at least one item", rel, i+1)
		}
		if h.Says == "" && len(h.Items) > 1 {
			return nil, fmt.Errorf("%s: overview headline %q folds %d items, so it needs its own says sentence", rel, h.Title, len(h.Items))
		}
		for _, name := range h.Items {
			if !titles[name] {
				return nil, fmt.Errorf("%s: overview headline %q names item %q, which not_collected does not have", rel, h.Title, name)
			}
		}
	}
	if cfg.Reference.File == "" {
		cfg.Reference.File = DefaultReferenceFile
	}
	if len(cfg.Specs) > 0 && cfg.Spec != (SpecRef{}) {
		return nil, fmt.Errorf("%s: give spec or specs, not both", rel)
	}
	return &cfg, nil
}

// InScope reports whether an operation needs a verdict.
func (sc Scope) InScope(op *Operation) bool {
	methods := sc.Methods
	if len(methods) == 0 {
		methods = []string{"GET"}
	}
	if !containsFold(methods, op.Method) {
		return false
	}
	if op.Deprecated && !sc.Deprecated {
		return false
	}
	if len(sc.Tags) > 0 && !intersects(sc.Tags, op.Tags) {
		return false
	}
	if intersects(sc.ExcludeTags, op.Tags) {
		return false
	}
	if len(sc.PathPrefixes) > 0 {
		found := false
		for _, prefix := range sc.PathPrefixes {
			if strings.HasPrefix(op.Path, prefix) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Covers reports whether the item's verdict applies to an operation.
func (it Item) Covers(op *Operation) bool {
	return it.Specificity(op) > 0
}

// Specificity says how closely an item covers an operation, and 0 when it
// does not. Naming the operation is most specific, then its exact path,
// then the longest path prefix or contained string that covers it, with a
// longer one winning over a shorter, then a tag or category. The most
// specific item gives the verdict; two items covering an operation equally
// is a conflict.
func (it Item) Specificity(op *Operation) int {
	if len(it.In) > 0 && !slices.Contains(it.In, op.Description()) {
		return 0
	}
	for _, name := range it.Operations {
		if name == op.Key() || strings.EqualFold(name, op.Method+" "+op.Path) {
			return 1 << 20
		}
	}
	best := 0
	for _, path := range it.Paths {
		if prefix, ok := strings.CutSuffix(path, "*"); ok {
			if strings.HasPrefix(op.Path, prefix) {
				best = max(best, 2+len(prefix))
			}
		} else if path == op.Path {
			best = max(best, 1<<19)
		}
	}
	for _, part := range it.PathContains {
		if strings.Contains(strings.ToLower(op.Path), strings.ToLower(part)) {
			best = max(best, 2+len(part))
		}
	}
	if best > 0 {
		return best
	}
	if intersects(it.Tags, op.Tags) {
		return 1
	}
	for _, category := range it.Categories {
		if category == op.Category || (op.Subcategory != "" && category == op.Category+"/"+op.Subcategory) {
			return 1
		}
	}
	return 0
}

// Descriptions lists the pinned descriptions: Specs, or Spec alone.
func (c *Config) Descriptions() []SpecRef {
	if len(c.Specs) > 0 {
		return c.Specs
	}
	if c.Spec == (SpecRef{}) {
		return nil
	}
	return []SpecRef{c.Spec}
}

// Label names a description in the rendered documents.
func (r SpecRef) Label() string {
	if r.Name != "" {
		return r.Name
	}
	if r.Path != "" {
		return r.Path
	}
	return r.Source
}

// Item finds a not_collected item by title.
func (c *Config) Item(title string) *Item {
	for i := range c.NotCollected {
		if c.NotCollected[i].Title == title {
			return &c.NotCollected[i]
		}
	}
	return nil
}

// Label names the item in reports: its title, or its reason.
func (it Item) Label() string {
	if it.Title != "" {
		return it.Title
	}
	return it.Reason
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

func intersects(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}
