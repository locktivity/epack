package secrets

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/github"
	"github.com/locktivity/epack/internal/yamlutil"
)

// Change is one reason a stored secret needs approval again, with the
// sentence a person reads and the changed lines of the reader's entry.
type Change struct {
	Reader  Reader   `json:"reader"`
	Kind    string   `json:"kind"`
	Summary string   `json:"summary"`
	Lines   []string `json:"lines,omitempty"`
}

// needsApproval compares the readers a secret was approved for with the
// readers it has now. A reader that was added or whose entry changed needs
// a fresh approval; a removed reader needs nothing.
func needsApproval(approved *Approval, readers []Reader) (bool, string) {
	if approved == nil {
		return true, "nothing is approved yet"
	}
	previous := map[string]Reader{}
	for _, reader := range approved.Readers {
		previous[reader.key()] = reader
	}
	for _, reader := range readers {
		old, ok := previous[reader.key()]
		switch {
		case !ok:
			return true, reader.Name + " now reads it too"
		case old.EntryDigest != reader.EntryDigest:
			return true, reader.Name + " changed since you approved it"
		}
	}
	return false, ""
}

// outstanding describes every change behind needsApproval, with the lines
// that changed when the approved snapshot is available.
func outstanding(approved *Approval, snapshot, cfg *config.JobConfig, name string) []Change {
	readers := ReadersOf(cfg, name)
	if approved == nil {
		changes := make([]Change, 0, len(readers))
		for _, reader := range readers {
			changes = append(changes, Change{Reader: reader, Kind: "unapproved", Summary: reader.Label() + " reads it and nothing is approved yet"})
		}
		return changes
	}
	previous := map[string]Reader{}
	for _, reader := range approved.Readers {
		previous[reader.key()] = reader
	}
	var changes []Change
	for _, reader := range readers {
		old, ok := previous[reader.key()]
		if !ok {
			changes = append(changes, Change{Reader: reader, Kind: "added", Summary: reader.Label() + " will also read it"})
			continue
		}
		if old.EntryDigest == reader.EntryDigest {
			continue
		}
		changes = append(changes, describeChange(reader, snapshot, cfg))
	}
	return changes
}

// entry is a reader's configuration in the shape the comparison needs.
type entry struct {
	raw         any
	source      string
	binary      string
	settings    map[string]any
	secrets     []string
	credentials []string
}

func entryOf(cfg *config.JobConfig, reader Reader) (entry, bool) {
	if cfg == nil {
		return entry{}, false
	}
	switch reader.Kind {
	case "collector":
		c, ok := cfg.Collectors[reader.Name]
		if !ok {
			return entry{}, false
		}
		return entry{raw: c, source: c.Source, binary: c.Binary, settings: c.Config, secrets: c.Secrets.Names(), credentials: c.Credentials}, true
	case "tool":
		t, ok := cfg.Tools[reader.Name]
		if !ok {
			return entry{}, false
		}
		return entry{raw: t, source: t.Source, binary: t.Binary, settings: t.Config, secrets: t.Secrets.Names(), credentials: t.Credentials}, true
	case "remote":
		r, ok := cfg.Remotes[reader.Name]
		if !ok {
			return entry{}, false
		}
		return entry{raw: r, source: r.Source, binary: r.Binary, settings: r.Extensions, secrets: r.Secrets.Names(), credentials: r.Credentials}, true
	}
	return entry{}, false
}

func describeChange(reader Reader, snapshot, cfg *config.JobConfig) Change {
	change := Change{Reader: reader, Kind: "changed", Summary: reader.Label() + " changed since you approved it"}
	before, okBefore := entryOf(snapshot, reader)
	after, okAfter := entryOf(cfg, reader)
	if !okBefore || !okAfter {
		return change
	}
	change.Lines = diffLines(entryLines(before.raw), entryLines(after.raw))
	switch {
	case before.source != after.source:
		change.Kind, change.Summary = sourceChange(reader, before.source, after.source)
	case before.binary != after.binary:
		change.Kind = "binary"
		change.Summary = reader.Name + " now runs a different local binary"
	case !reflect.DeepEqual(before.settings, after.settings):
		change.Kind = "settings"
		change.Summary = reader.Name + "'s settings changed, which may change where the credential is sent"
	case strings.Join(before.secrets, ",") != strings.Join(after.secrets, ","):
		change.Kind = "variables"
		change.Summary = reader.Name + " reads a different set of variables"
	case strings.Join(before.credentials, ",") != strings.Join(after.credentials, ","):
		change.Kind = "credentials"
		change.Summary = reader.Name + " uses different managed credentials"
	}
	return change
}

func sourceChange(reader Reader, before, after string) (string, string) {
	oldOwner, oldRepo, oldRange, errOld := github.ParseSource(before)
	newOwner, newRepo, newRange, errNew := github.ParseSource(after)
	if errOld != nil || errNew != nil {
		return "source", fmt.Sprintf("%s now comes from %s instead of %s", reader.Name, after, before)
	}
	switch {
	case !strings.EqualFold(oldOwner, newOwner):
		return "publisher", fmt.Sprintf("%s now comes from a different publisher (github.com/%s to github.com/%s)", reader.Name, strings.ToLower(oldOwner), strings.ToLower(newOwner))
	case oldRepo != newRepo:
		return "repository", fmt.Sprintf("%s now comes from a different repository (%s to %s)", reader.Name, oldRepo, newRepo)
	default:
		return "range", fmt.Sprintf("%s's version range changed from %s to %s", reader.Name, oldRange, newRange)
	}
}

func entryLines(raw any) []string {
	data, err := yamlutil.MarshalDeterministic(raw)
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n")
}
