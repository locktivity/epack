package mapping

import "fmt"

// SealSource is one mapping file to seal: its config key (or CLI path) and a
// loader that reads the bytes under the caller's own path policy, so the
// collect path keeps workDir containment and the build CLI keeps plain reads.
type SealSource struct {
	Key  string
	Load func() ([]byte, error)
}

// SealSink receives sealed mapping artifacts and reports the staged artifact
// paths for cross-checking. Callers adapt their pack builder to it, keeping
// this package free of builder dependencies.
type SealSink interface {
	Add(path string, data []byte) error
	ArtifactPaths() map[string]bool
}

// SealOpts adjusts sealing per call site.
type SealOpts struct {
	// ProfileDigests are locked profile digests to check pinned mapping
	// digests against. When CheckProfileDigests is false the check is
	// skipped entirely: the core build path has no lockfile context, and an
	// empty digest list would turn every pinned mapping into a warning.
	ProfileDigests      []string
	CheckProfileDigests bool

	// Warnf receives content warnings; nil discards them.
	Warnf func(format string, args ...any)
}

// SealAll loads, checks, emits, and adds each source as a control mapping
// artifact, then cross-checks artifact references once everything is staged.
// Content problems and unresolved references go to Warnf, never errors:
// mappings are publisher assertions with no verdict semantics. Loader errors
// are returned as-is so callers keep their own error wrapping.
func SealAll(sink SealSink, sources []SealSource, opts SealOpts) error {
	warnf := opts.Warnf
	if warnf == nil {
		warnf = func(string, ...any) {}
	}

	type loadedMapping struct {
		key string
		doc *Document
	}
	loaded := make([]loadedMapping, 0, len(sources))

	for _, source := range sources {
		data, err := source.Load()
		if err != nil {
			return err
		}
		doc, err := Parse(data)
		if err != nil {
			return fmt.Errorf("mapping %s: %w", source.Key, err)
		}
		loaded = append(loaded, loadedMapping{key: source.Key, doc: doc})

		for _, warning := range doc.Check() {
			warnf("warning: mapping %s: %s\n", source.Key, warning)
		}
		if opts.CheckProfileDigests {
			for _, warning := range doc.CheckProfileDigest(opts.ProfileDigests) {
				warnf("warning: mapping %s: %s\n", source.Key, warning)
			}
		}

		emitted, err := EmitJSON(data)
		if err != nil {
			return fmt.Errorf("mapping %s: %w", source.Key, err)
		}
		if err := sink.Add(ArtifactPath(source.Key), emitted); err != nil {
			return fmt.Errorf("adding mapping %s: %w", source.Key, err)
		}
	}

	// Cross-check artifact references once every artifact, mappings included,
	// is staged. Document references are left to validators, which can read
	// the pack's document index.
	packPaths := sink.ArtifactPaths()
	for _, entry := range loaded {
		for _, warning := range entry.doc.CheckArtifactRefs(packPaths) {
			warnf("warning: mapping %s: %s\n", entry.key, warning)
		}
	}
	return nil
}
