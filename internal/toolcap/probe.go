package toolcap

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"time"

	"github.com/locktivity/epack/internal/execsafe"
	"github.com/locktivity/epack/internal/jsonutil"
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/procexec"
	"github.com/locktivity/epack/internal/toolprotocol"
)

// Timeout is the maximum time to wait for --capabilities response.
const Timeout = 5 * time.Second

// MaxResponseBytes is the maximum size of --capabilities response (64KB).
// This prevents untrusted tool binaries from causing OOM by returning huge responses.
const MaxResponseBytes = 64 * 1024

// Probe runs --capabilities on a tool binary and parses the JSON response.
// Sets EPACK_MODE=capabilities to signal the tool that this is a probe, not execution.
//
// SECURITY:
//   - Uses restricted environment to prevent secret exfiltration during probes
//   - Uses bounded output capture to prevent OOM from malicious tools
//   - Uses BuildRestrictedEnvSafe to strip proxy credentials from untrusted binaries
//   - Validates JSON for duplicate keys to prevent ambiguous capability overrides
func Probe(ctx context.Context, binaryPath string) (*toolprotocol.Capabilities, error) {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()

	// SECURITY: Use restricted environment with stripped proxy credentials for probes.
	// Probed binaries may be untrusted (from PATH) - they should not receive sensitive
	// environment variables like AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN, or proxy credentials.
	// Only pass minimal safe env vars plus EPACK_MODE to signal probe mode.
	env := append(execsafe.BuildRestrictedEnvSafe(os.Environ(), false), "EPACK_MODE=capabilities")
	cmd, cancel, err := procexec.CommandChecked(ctx, procexec.Spec{
		Path:                binaryPath,
		Args:                []string{"--capabilities"},
		Env:                 env,
		EnforceEnvAllowlist: true,
		AllowedEnv:          append(append([]string{}, execsafe.AllowedEnvVars...), "PATH"),
		AllowedEnvPrefixes:  []string{"EPACK_"},
	})
	if err != nil {
		return nil, err
	}
	defer cancel()

	// SECURITY: Use bounded writers to prevent OOM from malicious tools
	// that might return gigabytes of data in their --capabilities response.
	var stdout, stderr bytes.Buffer
	stdoutLimited := limits.NewLimitedWriter(&stdout, MaxResponseBytes)
	stderrLimited := limits.NewLimitedWriter(&stderr, MaxResponseBytes)
	cmd.Stdout = stdoutLimited
	cmd.Stderr = stderrLimited

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("timeout after %v", Timeout)
		}
		// Guard against nil ProcessState (e.g., if command failed to start)
		if cmd.ProcessState != nil {
			return nil, fmt.Errorf("exit code %d", cmd.ProcessState.ExitCode())
		}
		return nil, fmt.Errorf("running --capabilities for %q: %w", binaryPath, err)
	}

	// Check if output was truncated (indicates malicious or buggy tool)
	if stdoutLimited.Truncated() {
		return nil, fmt.Errorf("capabilities response exceeded %d bytes limit", MaxResponseBytes)
	}

	// SECURITY: Use DecodeNoDup to validate no duplicate keys.
	// A malicious tool could use duplicate keys to ambiguously override capabilities,
	// e.g., setting "requires_pack": false then "requires_pack": true.
	caps, err := jsonutil.DecodeNoDup[toolprotocol.Capabilities](stdout.Bytes())
	if err != nil {
		return nil, fmt.Errorf("parsing capabilities JSON: %w", err)
	}

	return &caps, nil
}

// ProbeWithBackground is a convenience wrapper that uses context.Background().
func ProbeWithBackground(binaryPath string) (*toolprotocol.Capabilities, error) {
	return Probe(context.Background(), binaryPath)
}
