package dispatch

import (
	"context"
	"os"
	"os/exec"
	"time"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/execsafe"
	"github.com/locktivity/epack/internal/toolcap"
	"github.com/locktivity/epack/internal/toolprotocol"
	"github.com/locktivity/epack/internal/version"
)

// queryCapabilitiesWithTimeout runs --capabilities on a tool binary with timeout.
// Sets EPACK_MODE=capabilities to signal the tool that this is a probe, not execution.
// SECURITY: See toolcap.Probe for security properties.
func queryCapabilitiesWithTimeout(binaryPath string) (*toolprotocol.Capabilities, error) {
	return toolcap.ProbeWithBackground(binaryPath)
}

// execToolWithProtocol executes a tool with protocol mode, capturing exit code.
// This does NOT replace the process - we need to process result.json after the tool exits.
// Tool always uses os.Stdin/Stdout/Stderr directly for interactive operation.
//
// The context enables cancellation of long-running or hung tools. When the context
// is cancelled, the subprocess is terminated via SIGKILL (on Unix) or TerminateProcess
// (on Windows).
func execToolWithProtocol(ctx context.Context, binaryPath, binaryName string, args []string, env []string, runDir string) (int, error) {
	cmd := exec.CommandContext(ctx, binaryPath, args...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Dir = runDir // Run in the run directory

	err := cmd.Run()
	if err != nil {
		// Check if this was a context cancellation
		if ctx.Err() != nil {
			return -1, ctx.Err()
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), nil
		}
		return -1, err // Tool never ran
	}
	return 0, nil
}

// buildProtocolEnv builds the environment for protocol mode execution.
// SECURITY: Uses BuildRestrictedEnvSafe to strip proxy credentials from untrusted tools.
func buildProtocolEnv(toolName, runID, runDir, packPath, packDigest string, startedAt time.Time, toolCfg config.ToolConfig, configFilePath string, flags WrapperFlags) []string {
	// Start with restricted base environment with proxy credentials stripped
	// SECURITY: Tools are untrusted code and should not receive credentials embedded in proxy URLs.
	env := execsafe.BuildRestrictedEnvSafe(os.Environ(), false)

	// Add protocol environment variables
	env = append(env,
		"EPACK_RUN_ID="+runID,
		"EPACK_RUN_DIR="+runDir,
		"EPACK_STARTED_AT="+toolprotocol.FormatTimestamp(startedAt),
		"EPACK_TOOL_NAME="+toolName,
		"EPACK_PROTOCOL_VERSION=1",
		"EPACK_WRAPPER_VERSION="+version.Version,
	)

	// Add pack-related env vars only if pack is provided
	if packPath != "" {
		env = append(env, "EPACK_PACK_PATH="+packPath)
		if packDigest != "" {
			env = append(env, "EPACK_PACK_DIGEST="+packDigest)
		}
	}

	// Add config file path if config exists
	// This is the primary config mechanism - tools read JSON from this file
	if configFilePath != "" {
		env = append(env, "EPACK_TOOL_CONFIG="+configFilePath)
	}

	// Propagate wrapper flags to tool environment
	if flags.JSONMode {
		env = append(env, "EPACK_JSON=true")
	}
	if flags.QuietMode {
		env = append(env, "EPACK_QUIET=true")
	}

	// Pass through EPACK_IDENTITY if set (for authenticated/CI contexts)
	if identity := os.Getenv("EPACK_IDENTITY"); identity != "" {
		env = append(env, "EPACK_IDENTITY="+identity)
	}

	// Pass through secrets listed in epack.yaml.
	// Only explicitly configured secrets are passed to tools.
	// Reserved prefixes (EPACK_, LD_, DYLD_, _) are blocked.
	env = execsafe.AppendAllowedSecrets(env, toolCfg.Secrets, os.Getenv)

	return env
}

// writeToolConfig writes tool config to a temporary JSON file.
// Returns the file path and a cleanup function.
//
// SECURITY: Uses execsafe.WriteSecureConfigFile which creates the temp directory
// with umask 0077, eliminating the race condition between MkdirTemp and Chmod.
func writeToolConfig(toolCfg config.ToolConfig) (string, func(), error) {
	return execsafe.WriteSecureConfigFile(toolCfg.Config, "epack-tool-config-*")
}

