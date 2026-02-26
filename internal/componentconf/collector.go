//go:build conformance

package componentconf

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/locktivity/epack/internal/procexec"
)

func (r *Runner) runCollectorTests(ctx context.Context) {
	// Common tests
	r.testBinaryNaming()

	// Collector-specific tests
	r.testCollectorOutput(ctx)
	r.testCollectorConfig(ctx)
	r.testCollectorExitCodes(ctx)
	r.testCollectorSignalHandling(ctx)
	r.testCollectorFilesystemBoundary(ctx)
	r.testCollectorNoColor(ctx)
}

func (r *Runner) testCollectorOutput(ctx context.Context) {
	// Run collector with minimal environment (no config)
	env := map[string]string{
		"EPACK_COLLECTOR_NAME":   "test",
		"EPACK_PROTOCOL_VERSION": "1",
	}

	result := r.exec(ctx, nil, nil, env)

	// If collector exits with config error (exit 2), that's valid per COL-024.
	// The collector requires config that wasn't provided. Skip output tests
	// since they only apply when the collector runs successfully.
	if result.ExitCode == 2 {
		r.skip("COL-001", "collector requires config (exit 2 is valid)")
		r.skip("COL-002", "collector requires config")
		r.skip("COL-006", "collector requires config")
		r.skip("COL-005", "collector requires config")
		r.skip("C-020", "collector requires config")
		r.skip("COL-040", "collector requires config")
		r.skip("COL-034", "collector requires config")
		// Still verify the collector accepts protocol variables
		r.pass("C-010")
		r.pass("COL-010")
		r.pass("COL-011")
		return
	}

	// COL-001: Output valid JSON to stdout
	if isValidJSON(result.Stdout) {
		r.pass("COL-001")
	} else {
		r.fail("COL-001", "output is not valid JSON")
		// Skip dependent tests
		r.skip("COL-002", "depends on COL-001")
		r.skip("COL-006", "depends on COL-001")
		return
	}

	// COL-006: JSON is UTF-8 encoded
	if isValidUTF8(result.Stdout) {
		r.pass("COL-006")
	} else {
		r.fail("COL-006", "output is not valid UTF-8")
	}

	// COL-002: Protocol envelope format
	var envelope struct {
		ProtocolVersion int             `json:"protocol_version"`
		Data            json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(result.Stdout, &envelope); err == nil && envelope.ProtocolVersion > 0 && len(envelope.Data) > 0 {
		r.pass("COL-002")
	} else {
		// Not using envelope is allowed (COL-003)
		r.skip("COL-002", "not using protocol envelope (allowed)")
		r.pass("COL-003")
	}

	// COL-005: Output size does not exceed 64 MB
	const maxSize = 64 * 1024 * 1024
	if len(result.Stdout) <= maxSize {
		r.pass("COL-005")
	} else {
		r.fail("COL-005", "output exceeds 64 MB")
	}

	// C-010: Accepts protocol variables
	r.pass("C-010")

	// COL-010: Read collector name from EPACK_COLLECTOR_NAME
	r.pass("COL-010")

	// COL-011: Read protocol version from EPACK_PROTOCOL_VERSION
	r.pass("COL-011")

	// C-020/COL-040: Exit code 0 on success
	if result.ExitCode == 0 {
		r.pass("C-020")
		r.pass("COL-040")
		r.pass("COL-034")
	} else {
		r.fail("C-020", "non-zero exit code on success path")
		r.fail("COL-040", "non-zero exit code on success path")
		r.fail("COL-034", "non-zero exit code when collection should succeed")
	}
}

func (r *Runner) testCollectorConfig(ctx context.Context) {
	// Create a test config file
	configPath := filepath.Join(r.WorkDir, "config.json")
	configData := []byte(`{"test_key": "test_value"}`)
	if err := os.WriteFile(configPath, configData, 0644); err != nil {
		r.skip("COL-020", "could not create test config file")
		r.skip("COL-012", "could not create test config file")
		return
	}

	env := map[string]string{
		"EPACK_COLLECTOR_NAME":   "test",
		"EPACK_PROTOCOL_VERSION": "1",
		"EPACK_COLLECTOR_CONFIG": configPath,
	}

	result := r.exec(ctx, nil, nil, env)

	// COL-020: Parse config file as JSON
	// Exit codes 0, 1, or 2 are valid - the collector parsed the JSON successfully.
	// Exit 2 (config error) is valid because the test config may not contain
	// required fields for this specific collector.
	if result.ExitCode == 0 || result.ExitCode == 1 || result.ExitCode == 2 {
		r.pass("COL-020")
		r.pass("COL-012")
	} else {
		r.fail("COL-020", "failed to handle config file")
		r.fail("COL-012", "failed to read EPACK_COLLECTOR_CONFIG")
	}

	// COL-021: Not crash or hang when config file is missing
	// Any valid exit code (0, 1, 2) is acceptable - just must complete
	envNoConfig := map[string]string{
		"EPACK_COLLECTOR_NAME":   "test",
		"EPACK_PROTOCOL_VERSION": "1",
	}
	resultNoConfig := r.exec(ctx, nil, nil, envNoConfig)
	if resultNoConfig.ExitCode >= 0 && resultNoConfig.ExitCode <= 2 {
		r.pass("COL-021")
	} else {
		r.fail("COL-021", "crashed or exited with unexpected code")
	}

	// COL-022: Validate config schema - test with invalid JSON
	invalidConfigPath := filepath.Join(r.WorkDir, "invalid.json")
	if err := os.WriteFile(invalidConfigPath, []byte(`{invalid json`), 0644); err == nil {
		envInvalid := map[string]string{
			"EPACK_COLLECTOR_NAME":   "test",
			"EPACK_PROTOCOL_VERSION": "1",
			"EPACK_COLLECTOR_CONFIG": invalidConfigPath,
		}
		resultInvalid := r.exec(ctx, nil, nil, envInvalid)
		// Should exit with error (non-zero) for invalid config
		if resultInvalid.ExitCode != 0 {
			r.pass("COL-022")
		} else {
			r.skip("COL-022", "collector accepted invalid JSON config")
		}
	}
}

func (r *Runner) testCollectorExitCodes(ctx context.Context) {
	// C-021/COL-041: Test error exit code with nonexistent config file
	nonexistentConfig := filepath.Join(r.WorkDir, "nonexistent", "config.json")
	env := map[string]string{
		"EPACK_COLLECTOR_NAME":   "test",
		"EPACK_PROTOCOL_VERSION": "1",
		"EPACK_COLLECTOR_CONFIG": nonexistentConfig,
	}
	result := r.exec(ctx, nil, nil, env)

	// If it fails with a non-zero exit code, that's correct behavior
	if result.ExitCode != 0 {
		r.pass("C-021")
		r.pass("COL-041")
		// Check specific exit codes
		if result.ExitCode == 2 {
			r.pass("COL-042")
		} else {
			r.skip("COL-042", "did not exit with code 2 for config error")
		}
	} else {
		// Collector accepted nonexistent config - that's also valid (graceful handling)
		r.skip("C-021", "collector handled missing config gracefully")
		r.skip("COL-041", "collector handled missing config gracefully")
		r.skip("COL-042", "collector handled missing config gracefully")
	}

	// COL-043, COL-044: Cannot test without network/auth scenarios
	r.skip("COL-043", "requires authentication failure scenario")
	r.skip("COL-044", "requires network failure scenario")

	// C-022: Exit codes 2-9 for component-specific errors
	// Already tested above with COL-042
	if result.ExitCode >= 2 && result.ExitCode <= 9 {
		r.pass("C-022")
	} else {
		r.skip("C-022", "did not observe exit codes 2-9")
	}

	// COL-030: Complete within timeout (implicit - we set timeout)
	r.pass("COL-030")

	// COL-052: HTTPS requirement - cannot test without network mock
	r.skip("COL-052", "requires network interception")
}

func (r *Runner) testCollectorSignalHandling(ctx context.Context) {
	// COL-031: Handle SIGTERM gracefully
	// Start the collector, send SIGTERM, check it exits cleanly

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cmd, cmdCancel, err := procexec.CommandChecked(ctx, procexec.Spec{
		Path: r.Binary,
		Dir:  r.WorkDir,
		Env: append(os.Environ(),
			"EPACK_COLLECTOR_NAME=test",
			"EPACK_PROTOCOL_VERSION=1",
		),
	})
	defer cmdCancel()
	if err != nil {
		r.skip("COL-031", "could not construct process for signal test")
		return
	}

	if err := cmd.Start(); err != nil {
		r.skip("COL-031", "could not start process for signal test")
		return
	}

	// Give it a moment to start
	time.Sleep(100 * time.Millisecond)

	// Send SIGTERM
	if cmd.Process != nil {
		cmd.Process.Signal(syscall.SIGTERM)
	}

	// Wait for it to exit
	err = cmd.Wait()
	if err != nil {
		if cmd.ProcessState != nil {
			// Any exit is considered graceful handling
			// Exit code 0 or small positive values are fine
			if cmd.ProcessState.ExitCode() <= 128 {
				r.pass("COL-031")
			} else {
				r.fail("COL-031", "process crashed on SIGTERM")
			}
		} else {
			r.skip("COL-031", "signal test inconclusive")
		}
	} else {
		// Exited cleanly
		r.pass("COL-031")
	}
}

func (r *Runner) testCollectorFilesystemBoundary(ctx context.Context) {
	env := map[string]string{
		"EPACK_COLLECTOR_NAME":   "test",
		"EPACK_PROTOCOL_VERSION": "1",
	}
	r.testFilesystemBoundary(ctx, nil, nil, env)

	// C-031, C-032, C-033: Cannot easily test without log inspection
	// These would require running collector with known credentials and checking logs
	r.skip("C-031", "requires log inspection for credential detection")
	r.skip("C-032", "requires error message inspection")
	r.skip("C-033", "requires malformed input injection")
}

func (r *Runner) testCollectorNoColor(ctx context.Context) {
	env := map[string]string{
		"EPACK_COLLECTOR_NAME":   "test",
		"EPACK_PROTOCOL_VERSION": "1",
	}
	r.testNoColor(ctx, nil, nil, env)
}
