package config

import (
	"strings"
	"testing"
)

// FuzzValidateCollectorName tests collector name validation with fuzzed inputs.
// SECURITY: Collector names are used in filesystem paths, so path traversal
// and other injection attacks must be prevented.
func FuzzValidateCollectorName(f *testing.F) {
	// Valid names
	f.Add("audit")
	f.Add("my-collector")
	f.Add("collector_v2")
	f.Add("a")
	f.Add("1collector")
	f.Add("collector.test")

	// Path traversal attempts
	f.Add("..")
	f.Add("../etc/passwd")
	f.Add("..\\windows\\system32")
	f.Add("foo/../bar")
	f.Add("foo/bar")
	f.Add("foo\\bar")

	// Special characters
	f.Add(".")
	f.Add("...")
	f.Add("collector\x00evil")
	f.Add("collector\nevil")
	f.Add("collector\revil")

	// Length edge cases
	f.Add("")
	f.Add(strings.Repeat("a", 64))  // at limit
	f.Add(strings.Repeat("a", 65))  // over limit
	f.Add(strings.Repeat("a", 256)) // way over

	// Unicode and encoding
	f.Add("コレクター")
	f.Add("collector%2F..%2Fetc")
	f.Add("collector%00evil")

	// Leading/trailing special chars
	f.Add("-collector")
	f.Add("_collector")
	f.Add(".collector")
	f.Add("collector-")
	f.Add("collector_")
	f.Add("collector.")

	f.Fuzz(func(t *testing.T, name string) {
		err := ValidateCollectorName(name)

		if err == nil {
			// If validation passed, verify security invariants

			// SECURITY: Must not contain path traversal sequences
			if strings.Contains(name, "..") {
				t.Errorf("SECURITY: accepted name with path traversal: %q", name)
			}

			// SECURITY: Must not contain path separators
			if strings.Contains(name, "/") || strings.Contains(name, "\\") {
				t.Errorf("SECURITY: accepted name with path separator: %q", name)
			}

			// SECURITY: Must not be empty
			if name == "" {
				t.Error("SECURITY: accepted empty name")
			}

			// SECURITY: Must not contain null bytes
			if strings.Contains(name, "\x00") {
				t.Errorf("SECURITY: accepted name with null byte: %q", name)
			}

			// SECURITY: Must not contain newlines (log injection)
			if strings.ContainsAny(name, "\r\n") {
				t.Errorf("SECURITY: accepted name with newline: %q", name)
			}

			// SECURITY: Must not exceed max length
			if len(name) > 64 {
				t.Errorf("SECURITY: accepted name exceeding max length: len=%d", len(name))
			}

			// SECURITY: Must start with lowercase alphanumeric
			if len(name) > 0 {
				first := name[0]
				if (first < 'a' || first > 'z') && (first < '0' || first > '9') {
					t.Errorf("SECURITY: accepted name not starting with lowercase alphanumeric: %q", name)
				}
			}
		}
	})
}

// FuzzValidateToolName tests tool name validation with fuzzed inputs.
// SECURITY: Tool names are used in filesystem paths and command execution,
// so injection attacks must be prevented.
func FuzzValidateToolName(f *testing.F) {
	// Valid names
	f.Add("ask")
	f.Add("policy-check")
	f.Add("tool_v2")
	f.Add("a")

	// Path traversal attempts (same as collector)
	f.Add("..")
	f.Add("../bin/sh")
	f.Add("..\\cmd.exe")
	f.Add("foo/../bar")

	// Command injection attempts
	f.Add("tool;rm -rf")
	f.Add("tool|cat /etc/passwd")
	f.Add("tool`whoami`")
	f.Add("tool$(id)")
	f.Add("tool&calc")

	// Null byte injection
	f.Add("tool\x00.exe")

	f.Fuzz(func(t *testing.T, name string) {
		err := ValidateToolName(name)

		if err == nil {
			// If validation passed, verify security invariants

			// SECURITY: Must not contain path traversal sequences
			if strings.Contains(name, "..") {
				t.Errorf("SECURITY: accepted name with path traversal: %q", name)
			}

			// SECURITY: Must not contain path separators
			if strings.Contains(name, "/") || strings.Contains(name, "\\") {
				t.Errorf("SECURITY: accepted name with path separator: %q", name)
			}

			// SECURITY: Must not contain shell metacharacters
			shellChars := ";|&`$(){}[]<>"
			for _, c := range shellChars {
				if strings.ContainsRune(name, c) {
					t.Errorf("SECURITY: accepted name with shell metachar %q: %q", string(c), name)
				}
			}

			// SECURITY: Must not contain null bytes
			if strings.Contains(name, "\x00") {
				t.Errorf("SECURITY: accepted name with null byte: %q", name)
			}

			// SECURITY: Must not exceed max length
			if len(name) > 64 {
				t.Errorf("SECURITY: accepted name exceeding max length: len=%d", len(name))
			}
		}
	})
}

// FuzzValidateVersion tests version string validation with fuzzed inputs.
// SECURITY: Versions are used in filesystem paths and GitHub API URLs,
// so path traversal and URL injection must be prevented.
func FuzzValidateVersion(f *testing.F) {
	// Valid versions
	f.Add("v1.0.0")
	f.Add("v1.2.3")
	f.Add("1.0.0")
	f.Add("v1.0.0-alpha")
	f.Add("v1.0.0-beta.1")
	f.Add("v1.0.0-rc1")

	// Path traversal attempts
	f.Add("..")
	f.Add("../../../etc/passwd")
	f.Add("v1.0.0/../../../etc")
	f.Add("v1/../../etc")
	f.Add("..\\windows")

	// URL injection attempts (used in GitHub API)
	f.Add("v1.0.0?token=secret")
	f.Add("v1.0.0#fragment")
	f.Add("v1.0.0%2F..%2F..%2Fetc")
	f.Add("v1.0.0/../../etc")

	// Null byte injection
	f.Add("v1.0.0\x00evil")

	// Length edge cases
	f.Add("")
	f.Add(strings.Repeat("v", 128))  // at limit
	f.Add(strings.Repeat("v", 129))  // over limit
	f.Add(strings.Repeat("v", 1000)) // way over

	// Format edge cases
	f.Add("v")
	f.Add("v1")
	f.Add("v1.0")
	f.Add("v1.0.0.0")
	f.Add("va.b.c")
	f.Add("-1.0.0")
	f.Add("v-1.0.0")

	f.Fuzz(func(t *testing.T, version string) {
		err := ValidateVersion(version)

		if err == nil {
			// If validation passed, verify security invariants

			// SECURITY: Must not contain path traversal sequences
			if strings.Contains(version, "..") {
				t.Errorf("SECURITY: accepted version with path traversal: %q", version)
			}

			// SECURITY: Must not contain path separators
			if strings.Contains(version, "/") || strings.Contains(version, "\\") {
				t.Errorf("SECURITY: accepted version with path separator: %q", version)
			}

			// SECURITY: Must not contain URL-unsafe characters that could enable injection
			urlUnsafe := "?#%"
			for _, c := range urlUnsafe {
				if strings.ContainsRune(version, c) {
					t.Errorf("SECURITY: accepted version with URL-unsafe char %q: %q", string(c), version)
				}
			}

			// SECURITY: Must not contain null bytes
			if strings.Contains(version, "\x00") {
				t.Errorf("SECURITY: accepted version with null byte: %q", version)
			}

			// SECURITY: Must not be empty
			if version == "" {
				t.Error("SECURITY: accepted empty version")
			}

			// SECURITY: Must not exceed max length
			if len(version) > 128 {
				t.Errorf("SECURITY: accepted version exceeding max length: len=%d", len(version))
			}
		}
	})
}

// FuzzValidatePlatform tests platform string validation with fuzzed inputs.
// SECURITY: Platforms are used in filesystem paths, so injection must be prevented.
func FuzzValidatePlatform(f *testing.F) {
	// Valid platforms
	f.Add("linux/amd64")
	f.Add("darwin/arm64")
	f.Add("windows/amd64")
	f.Add("linux/arm64")

	// Path traversal attempts
	f.Add("../etc/amd64")
	f.Add("linux/../../../etc")
	f.Add("..\\windows\\amd64")

	// Invalid formats
	f.Add("")
	f.Add("linux")
	f.Add("linux/")
	f.Add("/amd64")
	f.Add("linux/amd64/extra")
	f.Add("LINUX/AMD64") // uppercase

	// Special characters
	f.Add("linux\x00evil/amd64")
	f.Add("linux/amd64\x00evil")

	f.Fuzz(func(t *testing.T, platform string) {
		err := ValidatePlatform(platform)

		if err == nil {
			// If validation passed, verify security invariants

			// SECURITY: Must be in os/arch format
			parts := strings.Split(platform, "/")
			if len(parts) != 2 {
				t.Errorf("SECURITY: accepted platform not in os/arch format: %q", platform)
			}

			// SECURITY: Must not contain path traversal
			if strings.Contains(platform, "..") {
				t.Errorf("SECURITY: accepted platform with path traversal: %q", platform)
			}

			// SECURITY: Must not contain backslash
			if strings.Contains(platform, "\\") {
				t.Errorf("SECURITY: accepted platform with backslash: %q", platform)
			}

			// SECURITY: Must not contain null bytes
			if strings.Contains(platform, "\x00") {
				t.Errorf("SECURITY: accepted platform with null byte: %q", platform)
			}

			// SECURITY: Must be lowercase only
			if platform != strings.ToLower(platform) {
				t.Errorf("SECURITY: accepted platform with uppercase: %q", platform)
			}
		}
	})
}
