// Package toolcap provides capability probing for epack tools.
//
// This package provides a single, canonical implementation for querying
// --capabilities from tool binaries. It consolidates duplicate implementations
// from internal/tool/probe.go and internal/dispatch/executor.go.
//
// SECURITY:
//   - Uses restricted environment to prevent secret exfiltration during probes
//   - Uses bounded output capture to prevent OOM from malicious tools
//   - Validates JSON for duplicate keys to prevent ambiguous overrides
//   - Uses BuildRestrictedEnvSafe to strip proxy credentials
package toolcap
