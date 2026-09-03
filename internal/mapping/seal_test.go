package mapping

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

type fakeSink struct {
	added map[string][]byte
}

func (s *fakeSink) Add(path string, data []byte) error {
	s.added[path] = data
	return nil
}

func (s *fakeSink) ArtifactPaths() map[string]bool {
	paths := make(map[string]bool, len(s.added))
	for path := range s.added {
		paths[path] = true
	}
	return paths
}

func sealWarnings(warnings *[]string) func(string, ...any) {
	return func(format string, args ...any) {
		*warnings = append(*warnings, strings.TrimSpace(fmt.Sprintf(format, args...)))
	}
}

func TestSealAllSealsResolvableMappingWithoutWarnings(t *testing.T) {
	doc := `schema_version: "1.0.0"
profile:
  id: soc2
mappings:
  - requirement: VCS-004
    evidence:
      artifact: artifacts/github.json
`
	sink := &fakeSink{added: map[string][]byte{"artifacts/github.json": nil}}
	var warnings []string

	err := SealAll(sink, []SealSource{{
		Key:  "mappings/controls.yaml",
		Load: func() ([]byte, error) { return []byte(doc), nil },
	}}, SealOpts{Warnf: sealWarnings(&warnings)})
	if err != nil {
		t.Fatalf("SealAll() error = %v", err)
	}

	sealed, ok := sink.added["artifacts/controls.json"]
	if !ok {
		t.Fatalf("sealed artifact not added; have %v", sink.ArtifactPaths())
	}
	var tree map[string]any
	if err := json.Unmarshal(sealed, &tree); err != nil {
		t.Fatalf("sealed artifact is not valid JSON: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
}

func TestSealAllWarnsOnUnresolvedArtifactAndStaleProfileDigest(t *testing.T) {
	doc := `schema_version: "1.0.0"
profile:
  id: soc2
  digest: sha256:aaaa
mappings:
  - requirement: VCS-004
    evidence:
      artifact: artifacts/missing.json
`
	sink := &fakeSink{added: map[string][]byte{}}
	var warnings []string

	err := SealAll(sink, []SealSource{{
		Key:  "controls.yaml",
		Load: func() ([]byte, error) { return []byte(doc), nil },
	}}, SealOpts{
		ProfileDigests:      []string{"sha256:bbbb"},
		CheckProfileDigests: true,
		Warnf:               sealWarnings(&warnings),
	})
	if err != nil {
		t.Fatalf("SealAll() error = %v", err)
	}

	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "does not carry") {
		t.Errorf("expected unresolved artifact warning, got: %v", warnings)
	}
	if !strings.Contains(joined, "matches no locked profile") {
		t.Errorf("expected stale profile digest warning, got: %v", warnings)
	}
}

func TestSealAllReturnsLoaderErrorsUnwrapped(t *testing.T) {
	loadErr := fmt.Errorf("reading mapping controls.yaml: boom")
	err := SealAll(&fakeSink{added: map[string][]byte{}}, []SealSource{{
		Key:  "controls.yaml",
		Load: func() ([]byte, error) { return nil, loadErr },
	}}, SealOpts{})
	if err != loadErr {
		t.Fatalf("SealAll() error = %v, want loader error unwrapped", err)
	}
}
