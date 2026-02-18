// Package config provides configuration parsing for epack.yaml files.
//
// This package handles the job configuration file format which declares:
//   - Collectors: evidence gathering binaries
//   - Tools: pack processing binaries (e.g., epack-tool-ai)
//   - Signing: pack signing configuration
//   - Registry: component resolution settings
//
// Configuration files are validated for:
//   - YAML alias bomb attacks (pre-parse)
//   - Size limits (DoS prevention)
//   - Structural validity (mutual exclusivity, required fields)
//   - Security (secret name validation)
package config
