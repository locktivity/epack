package secrets

import (
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/component/config"
)

const baseConfig = `stream: northwind/production
collectors:
  microsoft-cloud:
    source: locktivity/epack-collector-microsoft-cloud@^0.1
    config:
      tenant: northwind.example
    secrets: [AZURE_CLIENT_SECRET]
  okta:
    source: locktivity/epack-collector-okta@^0.1
    secrets: [OKTA_PRIVATE_KEY, {name: SENTRY_AUTH_TOKEN, optional: true}]
`

func parseConfig(t *testing.T, text string) *Configuration {
	t.Helper()
	cfg, err := config.Parse([]byte(text))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return &Configuration{Config: cfg, Raw: []byte(text)}
}

func TestReadersOf_ListsPublishersAndDigests(t *testing.T) {
	conf := parseConfig(t, baseConfig)
	readers := ReadersOf(conf.Config, "AZURE_CLIENT_SECRET")
	if len(readers) != 1 || readers[0].Name != "microsoft-cloud" || readers[0].Kind != "collector" || readers[0].Publisher != "github.com/locktivity" || readers[0].EntryDigest == "" {
		t.Fatalf("readers = %+v", readers)
	}
	changed := parseConfig(t, strings.Replace(baseConfig, "northwind.example", "contoso.example", 1))
	if ReadersOf(changed.Config, "AZURE_CLIENT_SECRET")[0].EntryDigest == readers[0].EntryDigest {
		t.Error("a settings change must change the entry digest")
	}
	if ReadersOf(conf.Config, "NOT_LISTED") != nil {
		t.Error("an unlisted name has no readers")
	}
	listed := listedSecrets(conf.Config)
	if len(listed) != 3 || listed[0].name != "AZURE_CLIENT_SECRET" || !listed[2].optional || listed[1].optional {
		t.Errorf("listed = %+v", listed)
	}
}

func TestNeedsApproval(t *testing.T) {
	conf := parseConfig(t, baseConfig)
	readers := ReadersOf(conf.Config, "AZURE_CLIENT_SECRET")
	if needed, _ := needsApproval(nil, readers); !needed {
		t.Error("nothing approved yet needs approval")
	}
	approved := &Approval{Readers: readers}
	if needed, _ := needsApproval(approved, readers); needed {
		t.Error("unchanged readers need nothing")
	}
	if needed, _ := needsApproval(approved, nil); needed {
		t.Error("a removed reader needs nothing")
	}
	changed := parseConfig(t, strings.Replace(baseConfig, "northwind.example", "contoso.example", 1))
	needed, reason := needsApproval(approved, ReadersOf(changed.Config, "AZURE_CLIENT_SECRET"))
	if !needed || reason != "microsoft-cloud changed since you approved it" {
		t.Errorf("changed entry: needed=%v reason=%q", needed, reason)
	}
	added := parseConfig(t, baseConfig+"  github:\n    source: locktivity/epack-collector-github@^0.1\n    secrets: [AZURE_CLIENT_SECRET]\n")
	needed, reason = needsApproval(approved, ReadersOf(added.Config, "AZURE_CLIENT_SECRET"))
	if !needed || reason != "github now reads it too" {
		t.Errorf("added reader: needed=%v reason=%q", needed, reason)
	}
}

func TestOutstanding_DescribesTheChange(t *testing.T) {
	before := parseConfig(t, baseConfig)
	approved := &Approval{Revision: 4, Readers: ReadersOf(before.Config, "AZURE_CLIENT_SECRET")}

	settings := parseConfig(t, strings.Replace(baseConfig, "northwind.example", "contoso.example", 1))
	changes := outstanding(approved, before.Config, settings.Config, "AZURE_CLIENT_SECRET")
	if len(changes) != 1 || changes[0].Kind != "settings" || !strings.Contains(changes[0].Summary, "settings changed") {
		t.Fatalf("settings change = %+v", changes)
	}
	joined := strings.Join(changes[0].Lines, "\n")
	if !strings.Contains(joined, "-") || !strings.Contains(joined, "contoso.example") || !strings.Contains(joined, "northwind.example") {
		t.Errorf("diff lines should show both tenants:\n%s", joined)
	}

	publisher := parseConfig(t, strings.Replace(baseConfig, "locktivity/epack-collector-microsoft-cloud", "someone/epack-collector-microsoft-cloud", 1))
	changes = outstanding(approved, before.Config, publisher.Config, "AZURE_CLIENT_SECRET")
	if len(changes) != 1 || changes[0].Kind != "publisher" || !strings.Contains(changes[0].Summary, "github.com/someone") {
		t.Fatalf("publisher change = %+v", changes)
	}

	rangeChange := parseConfig(t, strings.Replace(baseConfig, "microsoft-cloud@^0.1", "microsoft-cloud@^0.2", 1))
	changes = outstanding(approved, before.Config, rangeChange.Config, "AZURE_CLIENT_SECRET")
	if len(changes) != 1 || changes[0].Kind != "range" {
		t.Fatalf("range change = %+v", changes)
	}

	added := parseConfig(t, baseConfig+"  github:\n    source: locktivity/epack-collector-github@^0.1\n    secrets: [AZURE_CLIENT_SECRET]\n")
	changes = outstanding(approved, before.Config, added.Config, "AZURE_CLIENT_SECRET")
	if len(changes) != 1 || changes[0].Kind != "added" || changes[0].Summary != "github (github.com/locktivity) will also read it" {
		t.Fatalf("added reader = %+v", changes)
	}

	if changes := outstanding(nil, nil, before.Config, "AZURE_CLIENT_SECRET"); len(changes) != 1 || changes[0].Kind != "unapproved" {
		t.Fatalf("unapproved = %+v", changes)
	}
	if changes := outstanding(approved, nil, settings.Config, "AZURE_CLIENT_SECRET"); len(changes) != 1 || changes[0].Kind != "changed" || len(changes[0].Lines) != 0 {
		t.Fatalf("without a snapshot the change is generic: %+v", changes)
	}
}

func TestDiffLines(t *testing.T) {
	got := diffLines([]string{"a", "b", "c"}, []string{"a", "x", "c", "d"})
	want := " a\n-b\n+x\n c\n+d"
	if strings.Join(got, "\n") != want {
		t.Errorf("diff = %q, want %q", strings.Join(got, "\n"), want)
	}
}
