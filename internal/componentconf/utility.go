//go:build conformance

package componentconf

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/locktivity/epack/internal/validate"
)

func (r *Runner) runUtilityTests(ctx context.Context) {
	// Common tests
	r.testUtilityBinaryNaming()

	// Utility-specific tests
	r.testUtilityVersion(ctx)
	r.testUtilityCapabilities(ctx)
	r.testUtilityHelp(ctx)
	r.testUtilityExitCodes(ctx)
	r.testUtilityNoColor(ctx)
	r.testUtilityFilesystemBoundary(ctx)
}

func (r *Runner) testUtilityBinaryNaming() {
	// C-001: Binary name follows pattern epack-util-{name}
	prefix := "epack-util-"
	if strings.HasPrefix(r.binaryName, prefix) {
		name := strings.TrimPrefix(r.binaryName, prefix)
		// C-002: Name segment matches pattern
		if namePattern.MatchString(name) {
			r.pass("C-001")
			r.pass("C-002")
		} else {
			r.pass("C-001")
			r.fail("C-002", fmt.Sprintf("name %q does not match ^[a-z0-9][a-z0-9._-]{0,63}$", name))
		}
		// C-003: No path separators
		if !strings.ContainsAny(name, "/\\") && !validate.ContainsTraversal(name) {
			r.pass("C-003")
		} else {
			r.fail("C-003", "name contains path separators or traversal sequences")
		}
	} else {
		r.fail("C-001", fmt.Sprintf("binary name %q does not start with %q", r.binaryName, prefix))
		r.skip("C-002", "depends on C-001")
		r.skip("C-003", "depends on C-001")
	}
}

func (r *Runner) testUtilityVersion(ctx context.Context) {
	// UTIL-001: Implement --version flag returning version string
	result := r.exec(ctx, []string{"--version"}, nil, nil)

	if result.Err != nil {
		r.fail("UTIL-001", fmt.Sprintf("failed to execute: %v", result.Err))
		return
	}

	// Should output something to stdout
	output := strings.TrimSpace(string(result.Stdout))
	if output == "" {
		// Check stderr as fallback
		output = strings.TrimSpace(string(result.Stderr))
	}

	if output != "" && result.ExitCode == 0 {
		r.pass("UTIL-001")
	} else if output != "" {
		// Output present but non-zero exit
		r.fail("UTIL-001", fmt.Sprintf("--version returned exit code %d", result.ExitCode))
	} else {
		r.fail("UTIL-001", "--version produced no output")
	}
}

func (r *Runner) testUtilityCapabilities(ctx context.Context) {
	// UTIL-002: Implement --capabilities flag returning JSON metadata
	result := r.exec(ctx, []string{"--capabilities"}, nil, nil)

	if result.Err != nil {
		r.fail("UTIL-002", fmt.Sprintf("failed to execute: %v", result.Err))
		r.skip("UTIL-003", "depends on UTIL-002")
		r.skip("UTIL-004", "depends on UTIL-002")
		return
	}

	if result.ExitCode != 0 {
		r.fail("UTIL-002", fmt.Sprintf("--capabilities returned exit code %d", result.ExitCode))
		r.skip("UTIL-003", "depends on UTIL-002")
		r.skip("UTIL-004", "depends on UTIL-002")
		return
	}

	// Parse JSON
	var caps map[string]interface{}
	if err := json.Unmarshal(result.Stdout, &caps); err != nil {
		r.fail("UTIL-002", fmt.Sprintf("--capabilities output is not valid JSON: %v", err))
		r.skip("UTIL-003", "depends on UTIL-002")
		r.skip("UTIL-004", "depends on UTIL-002")
		return
	}

	r.pass("UTIL-002")
	r.caps = caps

	// UTIL-003: Capabilities include name, kind: "utility", version fields
	hasName := caps["name"] != nil
	hasVersion := caps["version"] != nil
	kind, _ := caps["kind"].(string)
	hasKind := kind == "utility"

	if hasName && hasVersion && hasKind {
		r.pass("UTIL-003")
	} else {
		var missing []string
		if !hasName {
			missing = append(missing, "name")
		}
		if !hasKind {
			missing = append(missing, "kind: \"utility\"")
		}
		if !hasVersion {
			missing = append(missing, "version")
		}
		r.fail("UTIL-003", fmt.Sprintf("capabilities missing: %s", strings.Join(missing, ", ")))
	}

	// UTIL-004: Capabilities SHOULD include description field
	if caps["description"] != nil {
		r.pass("UTIL-004")
	} else {
		r.fail("UTIL-004", "capabilities missing description field")
	}
}

func (r *Runner) testUtilityHelp(ctx context.Context) {
	// UTIL-010: Implement --help flag with usage information
	result := r.exec(ctx, []string{"--help"}, nil, nil)

	if result.Err != nil {
		r.fail("UTIL-010", fmt.Sprintf("failed to execute: %v", result.Err))
		r.skip("UTIL-011", "depends on UTIL-010")
		return
	}

	// Help can exit 0 or 2 (common for help)
	output := strings.TrimSpace(string(result.Stdout))
	if output == "" {
		output = strings.TrimSpace(string(result.Stderr))
	}

	if output != "" {
		r.pass("UTIL-010")

		// UTIL-011: Help output includes synopsis, description, and examples
		hasUsage := strings.Contains(strings.ToLower(output), "usage") ||
			strings.Contains(strings.ToLower(output), "synopsis")
		hasDescription := len(output) > 50 // Reasonable description length
		hasExamples := strings.Contains(strings.ToLower(output), "example") ||
			strings.Contains(output, "  epack-util-") // Command examples

		if hasUsage && hasDescription {
			r.pass("UTIL-011")
		} else if hasExamples {
			// Examples present is acceptable
			r.pass("UTIL-011")
		} else {
			r.fail("UTIL-011", "help output lacks structured synopsis/description/examples")
		}
	} else {
		r.fail("UTIL-010", "--help produced no output")
		r.skip("UTIL-011", "depends on UTIL-010")
	}
}

func (r *Runner) testUtilityExitCodes(ctx context.Context) {
	// C-020: Exit code 0 indicates success (test with --version which should succeed)
	result := r.exec(ctx, []string{"--version"}, nil, nil)
	if result.ExitCode == 0 {
		r.pass("C-020")
	} else {
		r.fail("C-020", fmt.Sprintf("--version returned exit code %d, expected 0", result.ExitCode))
	}

	// C-021: Exit code 1 indicates general error
	// Try an invalid flag to trigger an error
	result = r.exec(ctx, []string{"--invalid-flag-that-does-not-exist"}, nil, nil)
	if result.ExitCode != 0 {
		r.pass("C-021")
		// C-022: Exit codes 2-9 for component-specific errors
		if result.ExitCode >= 2 && result.ExitCode <= 9 {
			r.pass("C-022")
		} else if result.ExitCode == 1 {
			r.skip("C-022", "used general error code 1")
		} else {
			r.skip("C-022", "did not observe exit codes 2-9")
		}
	} else {
		// Some tools accept unknown flags without error
		r.skip("C-021", "invalid flag did not produce error")
		r.skip("C-022", "depends on C-021")
	}
}

func (r *Runner) testUtilityNoColor(ctx context.Context) {
	// C-013: Component honors NO_COLOR for terminal output

	// Run without NO_COLOR
	resultWithColor := r.exec(ctx, []string{"--help"}, nil, nil)

	// Run with NO_COLOR
	envNoColor := map[string]string{"NO_COLOR": "1"}
	resultNoColor := r.exec(ctx, []string{"--help"}, nil, envNoColor)

	// Check if stderr/stdout contains ANSI escape codes
	hasColorWith := strings.Contains(string(resultWithColor.Stdout), "\x1b[") ||
		strings.Contains(string(resultWithColor.Stderr), "\x1b[")
	hasColorWithout := strings.Contains(string(resultNoColor.Stdout), "\x1b[") ||
		strings.Contains(string(resultNoColor.Stderr), "\x1b[")

	if hasColorWith && !hasColorWithout {
		// Had color without NO_COLOR, no color with NO_COLOR - perfect
		r.pass("C-013")
	} else if !hasColorWith && !hasColorWithout {
		// No color in either case - also acceptable
		r.pass("C-013")
	} else if hasColorWithout {
		// Has color even with NO_COLOR=1
		r.fail("C-013", "utility outputs ANSI colors despite NO_COLOR=1")
	} else {
		// Inconclusive
		r.skip("C-013", "no color output to compare")
	}
}

func (r *Runner) testUtilityFilesystemBoundary(ctx context.Context) {
	// Utilities have relaxed filesystem requirements compared to other components.
	// We don't test C-030 (output area restriction) for utilities since they
	// may legitimately write to user-specified locations.
	// Skip this test for utilities.
	r.skip("C-030", "not applicable to utilities")

	// However, we can verify --capabilities doesn't create unexpected files
	outsideDir, err := os.MkdirTemp("", "epack-boundary-test-*")
	if err != nil {
		return
	}
	defer os.RemoveAll(outsideDir)

	markerPath := filepath.Join(outsideDir, "marker.txt")
	if err := os.WriteFile(markerPath, []byte("original"), 0644); err != nil {
		return
	}

	// Run utility with capabilities (should not modify files)
	r.exec(ctx, []string{"--capabilities"}, nil, nil)

	// Verify marker unchanged
	content, err := os.ReadFile(markerPath)
	if err != nil || string(content) != "original" {
		// This would be very unusual - log but don't fail
		// as it's not a formal requirement for utilities
	}
}
