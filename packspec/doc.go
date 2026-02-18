// Package packspec defines the canonical types for evidence pack manifests.
//
// This package contains only type definitions with zero external dependencies,
// making it safe to import from both the full pack/ library and the lightweight
// componentsdk/ package without pulling in Sigstore or other heavy dependencies.
//
// # Type Hierarchy
//
//	Manifest
//	├── Sources []Source
//	├── Artifacts []Artifact
//	└── Provenance
//	    └── SourcePacks []SourcePack
//	        └── EmbeddedAttestations []EmbeddedAttestation
//
// # Usage
//
// The pack/ package re-exports these types for backwards compatibility:
//
//	import "github.com/locktivity/epack/pack"
//	var m pack.Manifest // works as before
//
// The componentsdk/ package also uses these types:
//
//	import "github.com/locktivity/epack/componentsdk"
//	m := p.Manifest() // returns *packspec.Manifest
//
// # Validation
//
// This package contains only type definitions, not validation logic.
// Use pack.ParseManifest() for parsing and validating manifest JSON.
// The validation logic requires internal packages and stays in pack/.
package packspec
