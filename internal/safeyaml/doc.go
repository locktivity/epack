// Package safeyaml provides secure YAML parsing with mandatory pre-validation.
//
// # Security Boundary
//
// This package is the ONLY authorized entry point for YAML parsing in the codebase.
// Direct use of gopkg.in/yaml.v3 is prohibited except in this package and the
// yamlpolicy package (which provides the validation logic).
//
// An import guard test enforces this boundary by scanning all Go files for
// direct yaml.v3 imports.
//
// # Why This Exists
//
// YAML parsing is a known attack vector:
//
//   - Alias bombs: Small YAML files can expand to huge in-memory structures
//     via anchor/alias references (similar to XML billion-laughs attacks)
//
//   - Memory exhaustion: Large YAML files can consume excessive memory
//     during parsing before any application-level size checks
//
// By centralizing YAML parsing through this package, we ensure:
//
//  1. Size limits are enforced BEFORE parsing begins
//  2. Alias bomb detection runs BEFORE the parser expands references
//  3. Consistent error handling across all YAML parsing
//
// # Usage
//
//	import (
//	    "github.com/locktivity/epack/internal/limits"
//	    "github.com/locktivity/epack/internal/safeyaml"
//	)
//
//	var config MyConfig
//	if err := safeyaml.Unmarshal(data, limits.ConfigFile, &config); err != nil {
//	    return err
//	}
package safeyaml
