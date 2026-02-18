// Package builder creates evidence packs from artifacts.
//
// The Builder type provides a fluent interface for adding files and
// writing the resulting pack:
//
//	b := builder.New("myorg/stream")
//	b.AddFile("./config.json")
//	b.AddFile("./data.json")
//	if err := b.Write("evidence.pack"); err != nil {
//	    log.Fatal(err)
//	}
//
// Files are automatically digested using SHA-256 and stored in the
// artifacts/ directory within the pack. The builder generates a
// manifest.json with all artifact metadata.
//
// Artifacts are sorted by path in the manifest for deterministic output.
package builder
