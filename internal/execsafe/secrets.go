package execsafe

import (
	"fmt"
	"sort"
	"strings"
)

// DeniedSecretPrefixes blocks variables that would compromise epack's execution.
// - EPACK_*: Protocol namespace (run_id, pack_path, etc.)
// - LD_*/DYLD_*: Dynamic linker hijacking
// - _*: Reserved by shells/runtimes
var DeniedSecretPrefixes = []string{"EPACK_", "LD_", "DYLD_", "_"}

// ValidateSecretName returns an error if the name is a denied prefix.
func ValidateSecretName(name string) error {
	if name == "" {
		return fmt.Errorf("secret name cannot be empty")
	}

	upper := strings.ToUpper(name)
	for _, prefix := range DeniedSecretPrefixes {
		if strings.HasPrefix(upper, prefix) {
			return fmt.Errorf("secret %q uses reserved prefix %q", name, prefix)
		}
	}
	return nil
}

// ValidateSecretNames validates a list of secret names.
func ValidateSecretNames(names []string) error {
	var invalid []string
	for _, name := range names {
		if err := ValidateSecretName(name); err != nil {
			invalid = append(invalid, name)
		}
	}
	if len(invalid) > 0 {
		return fmt.Errorf("reserved secret names: %s", strings.Join(invalid, ", "))
	}
	return nil
}

// FilterValidSecrets returns only secrets that pass validation.
func FilterValidSecrets(secrets []string) []string {
	var valid []string
	for _, name := range secrets {
		if ValidateSecretName(name) == nil {
			valid = append(valid, name)
		}
	}
	return valid
}

// AppendAllowedSecrets appends allowed secrets from the environment to dst.
// Only secrets that pass validation and have non-empty values are appended.
// The getenv function is typically os.Getenv but can be mocked for testing.
//
// SECURITY: This is the canonical way to pass secrets to subprocesses.
// It filters reserved prefixes and only passes explicitly configured secrets.
func AppendAllowedSecrets(dst []string, names []string, getenv func(string) string) []string {
	for _, name := range names {
		if ValidateSecretName(name) != nil {
			continue
		}
		if value := getenv(name); value != "" {
			dst = append(dst, name+"="+value)
		}
	}
	return dst
}

// AppendExplicitEnv appends a trusted env bundle directly to dst.
// Keys are sorted for deterministic output in tests.
func AppendExplicitEnv(dst []string, env map[string]string) []string {
	if len(env) == 0 {
		return dst
	}
	keys := make([]string, 0, len(env))
	for key, value := range env {
		if key == "" || value == "" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if value := env[key]; value != "" {
			dst = append(dst, key+"="+value)
		}
	}
	return dst
}
