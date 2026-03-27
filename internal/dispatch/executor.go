package dispatch

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/execsafe"
	"github.com/locktivity/epack/internal/procexec"
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
	err := procexec.Run(ctx, procexec.Spec{
		Path:   binaryPath,
		Args:   args,
		Dir:    runDir, // Run in the run directory.
		Env:    env,
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	})
	if err != nil {
		// Check if this was a context cancellation
		if ctx.Err() != nil {
			return -1, ctx.Err()
		}
		var exitErr interface{ ExitCode() int }
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode(), nil
		}
		return -1, err // Tool never ran
	}
	return 0, nil
}

// buildProtocolEnv builds the environment for protocol mode execution.
// SECURITY: Uses BuildRestrictedEnvSafe to strip proxy credentials from untrusted tools.
func buildProtocolEnv(in protocolEnvInput) []string {
	// Start with restricted base environment with proxy credentials stripped
	// SECURITY: Tools are untrusted code and should not receive credentials embedded in proxy URLs.
	env := execsafe.BuildRestrictedEnvSafe(os.Environ(), false)

	// Add protocol environment variables
	env = append(env,
		"EPACK_RUN_ID="+in.runID,
		"EPACK_RUN_DIR="+in.runDir,
		"EPACK_STARTED_AT="+toolprotocol.FormatTimestamp(in.startedAt),
		"EPACK_TOOL_NAME="+in.toolName,
		"EPACK_PROTOCOL_VERSION=1",
		"EPACK_WRAPPER_VERSION="+version.Version,
	)

	// Add project root for profile path resolution
	if in.projectRoot != "" {
		env = append(env, "EPACK_PROJECT_ROOT="+in.projectRoot)
	}

	// Add pack-related env vars only if pack is provided
	if in.packPath != "" {
		env = append(env, "EPACK_PACK_PATH="+in.packPath)
		if in.packDigest != "" {
			env = append(env, "EPACK_PACK_DIGEST="+in.packDigest)
		}
	}

	// Add config file path if config exists
	// This is the primary config mechanism - tools read JSON from this file
	if in.configFilePath != "" {
		env = append(env, "EPACK_TOOL_CONFIG="+in.configFilePath)
	}

	// Propagate wrapper flags to tool environment
	if in.flags.JSONMode {
		env = append(env, "EPACK_JSON=true")
	}
	if in.flags.QuietMode {
		env = append(env, "EPACK_QUIET=true")
	}

	// Pass through EPACK_IDENTITY if set (for authenticated/CI contexts)
	if identity := os.Getenv("EPACK_IDENTITY"); identity != "" {
		env = append(env, "EPACK_IDENTITY="+identity)
	}

	// Pass through secrets listed in epack.yaml.
	// Only explicitly configured secrets are passed to tools.
	// Reserved prefixes (EPACK_, LD_, DYLD_, _) are blocked.
	env = execsafe.AppendAllowedSecrets(env, in.toolCfg.Secrets, os.Getenv)
	env = execsafe.AppendExplicitEnv(env, in.managedEnv)

	return env
}

type protocolEnvInput struct {
	toolName       string
	runID          string
	runDir         string
	packPath       string
	packDigest     string
	projectRoot    string
	startedAt      time.Time
	toolCfg        config.ToolConfig
	managedEnv     map[string]string
	configFilePath string
	flags          WrapperFlags
}

// writeToolConfig writes tool config to a temporary JSON file.
// Returns the file path and a cleanup function.
//
// SECURITY: Uses execsafe.WriteSecureConfigFile which creates the temp directory
// with umask 0077, eliminating the race condition between MkdirTemp and Chmod.
func writeToolConfig(toolCfg config.ToolConfig) (string, func(), error) {
	return execsafe.WriteSecureConfigFile(toolCfg.Config, "epack-tool-config-*")
}
