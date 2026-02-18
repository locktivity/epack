// Package yamlpolicy provides security-focused YAML parsing primitives.
//
// This package centralizes YAML security checks that must be applied consistently
// across all YAML parsing in the codebase (config files, lockfiles, etc.).
//
// # Security Properties
//
//   - Alias bomb detection: Prevents exponential expansion attacks
//   - Size limits: Enforces maximum input size before parsing
//   - Consistent enforcement: Single source of truth for YAML security policy
//
// # Usage
//
//	// Check for alias bombs before parsing
//	if err := yamlpolicy.CheckAliasAbuse(data); err != nil {
//	    return err
//	}
//
//	// Or use the combined check
//	if err := yamlpolicy.ValidateBeforeParse(data, limits.ConfigFile.Bytes()); err != nil {
//	    return err
//	}
//
// # YAML Alias Bombs
//
// YAML alias bombs exploit the alias/anchor feature to cause exponential expansion:
//
//	a: &a ["x","x"]
//	b: &b [*a,*a]      # 4 elements
//	c: &c [*b,*b]      # 8 elements
//	d: &d [*c,*c]      # 16 elements
//
// This package detects such patterns by counting aliases vs anchors BEFORE
// the YAML is expanded during unmarshaling.
package yamlpolicy
