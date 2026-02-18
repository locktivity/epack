package dispatch

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/component/sync"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/execsafe"
	"github.com/locktivity/epack/internal/platform"
	"github.com/locktivity/epack/internal/platformpath"
	"github.com/locktivity/epack/internal/toolprotocol"
	"github.com/locktivity/epack/pack"
)

// Output provides an interface for writing dispatch output/errors.
// For warning/error messages, Stderr() is used.
// For tool execution, the actual tool process uses os.Stdout/os.Stderr directly.
type Output interface {
	Stderr() interface{ Write([]byte) (int, error) }
}

// StdOutput is the default Output implementation using os.Stderr.
type StdOutput struct{}

func (StdOutput) Stderr() interface{ Write([]byte) (int, error) } { return os.Stderr }


// Tool executes an external tool binary with security verification.
// This is a convenience wrapper that parses args internally.
// For CLI usage where flags are parsed in the command layer, use ToolWithFlags instead.
//
// SECURITY: Tools get the same supply chain security as collectors:
// - Sigstore signature verification (at sync time)
// - Digest pinning in lockfile
// - TOCTOU-safe execution (copy-while-hash)
// - Restricted environment
func Tool(ctx context.Context, out Output, toolName string, args []string) error {
	flags, toolArgs, err := ParseWrapperArgs(args)
	if err != nil {
		return err
	}
	return ToolWithFlags(ctx, out, toolName, toolArgs, flags)
}

// ToolWithFlags executes a tool with pre-parsed wrapper flags.
// This is the preferred entry point when the CLI layer handles flag parsing.
//
// The context enables cancellation of long-running or hung tools. When the context
// is cancelled, the subprocess is terminated.
//
// SECURITY: Tools get the same supply chain security as collectors:
// - Sigstore signature verification (at sync time)
// - Digest pinning in lockfile
// - TOCTOU-safe execution (copy-while-hash)
// - Restricted environment
func ToolWithFlags(ctx context.Context, out Output, toolName string, toolArgs []string, flags WrapperFlags) error {
	// Validate tool name using config package validation
	if err := config.ValidateToolName(toolName); err != nil {
		return fmt.Errorf("invalid tool name: %w", err)
	}

	// Try to load config and lockfile for verified execution
	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("getting working directory: %w", err)
	}

	toolCfg, lf, loadErr := loadToolConfig(workDir, toolName)
	if loadErr != nil {
		// Distinguish between "config not found" vs "config/lockfile parse error"
		if cfgErr, ok := loadErr.(*configLoadError); ok && cfgErr.notFound {
			// No epack.yaml found - tools must be configured (matching collector model)
			return failWrapper(out, toolName, flags, "", "",
				componenttypes.ExitLockfileMissing, componenttypes.ErrCodeLockfileError,
				fmt.Sprintf("tool %q not found (no epack.yaml found)\n\nConfigure the tool in epack.yaml with source: or binary:", toolName))
		}
		// Config/lockfile exists but has errors - create run record with failure
		return handleConfigError(out, toolName, flags, loadErr)
	}

	// Tool is configured - use verified execution with full protocol
	return dispatchVerifiedTool(ctx, out, toolName, toolArgs, workDir, toolCfg, lf, flags)
}

// dispatchVerifiedTool executes a tool with TOCTOU-safe digest verification
// and full Tool Protocol v1 support.
func dispatchVerifiedTool(ctx context.Context, out Output, toolName string, toolArgs []string, workDir string, toolCfg config.ToolConfig, lf *lockfile.LockFile, flags WrapperFlags) error {
	platform := platform.Key(runtime.GOOS, runtime.GOARCH)

	// Determine base directory for run output FIRST so we can create run records for failures
	// We need to know the pack path before we can determine the base dir
	packPath := flags.PackPath
	var absPackPath string
	var err error
	if packPath != "" {
		absPackPath, err = filepath.Abs(packPath)
		if err != nil {
			// Can't even resolve pack path - use packless dir for error record
			return failWrapper(out, toolName, flags, "", "",
				componenttypes.ExitPackVerifyFailed, componenttypes.ErrCodePackVerifyFailed,
				fmt.Sprintf("invalid pack path: %v", err))
		}
	}

	baseDir, withPack, err := determineBaseDir(flags, absPackPath)
	if err != nil {
		return failWrapper(out, toolName, flags, "", "",
			componenttypes.ExitRunDirFailed, componenttypes.ErrCodeRunDirFailed,
			fmt.Sprintf("determining packless run directory: %v", err))
	}

	// Create run directory FIRST so all failures produce run records
	runID, runDir, err := toolprotocol.CreateRunDir(baseDir, toolName, withPack)
	if err != nil {
		// Can't use failWrapper here since we need to create the run dir first
		// This is a true fatal error - output to stderr and return exit code
		_, _ = fmt.Fprintf(out.Stderr(), "Error: creating run directory: %v\n", err)
		return &errors.Error{Code: errors.InvalidInput, Exit: componenttypes.ExitRunDirFailed, Message: err.Error()}
	}

	// Get locked tool info from lockfile
	locked, ok := lf.GetTool(toolName)
	if !ok {
		return writePreExecFailure(out, toolName, runID, runDir, absPackPath, "",
			componenttypes.ExitLockfileMissing, componenttypes.ErrCodeNotInLockfile,
			fmt.Sprintf("tool %q not found in lockfile", toolName))
	}

	platformEntry, ok := locked.Platforms[platform]
	if !ok {
		return writePreExecFailure(out, toolName, runID, runDir, absPackPath, locked.Version,
			componenttypes.ExitLockfileMissing, componenttypes.ErrCodePlatformNotInLockfile,
			fmt.Sprintf("tool %q missing platform %s in lockfile", toolName, platform))
	}

	// Check for missing digest - require unless --insecure-allow-unpinned
	if platformEntry.Digest == "" && !flags.InsecureAllowUnpinned {
		return writePreExecFailure(out, toolName, runID, runDir, absPackPath, locked.Version,
			componenttypes.ExitLockfileMissing, componenttypes.ErrCodeDigestMissing,
			fmt.Sprintf("tool %q missing digest in lockfile\n\nRun 'epack lock' to compute digest, or use --insecure-allow-unpinned", toolName))
	}

	// Resolve binary path
	binaryPath, err := sync.ResolveToolBinaryPath(filepath.Join(workDir, ".epack"), toolName, toolCfg, lf)
	if err != nil {
		return writePreExecFailure(out, toolName, runID, runDir, absPackPath, locked.Version,
			componenttypes.ExitComponentNotFound, componenttypes.ErrCodeComponentNotFound,
			fmt.Sprintf("resolving tool binary: %v", err))
	}

	// Determine execution path based on verification mode
	var execPath string
	var cleanup func()

	if platformEntry.Digest != "" && !flags.InsecureAllowUnpinned {
		// TOCTOU-safe execution: verify digest and get safe exec path
		execPath, cleanup, err = execsafe.VerifiedBinaryFD(binaryPath, platformEntry.Digest)
		if err != nil {
			return writePreExecFailure(out, toolName, runID, runDir, absPackPath, locked.Version,
				componenttypes.ExitVerifyFailed, componenttypes.ErrCodeVerifyFailed,
				fmt.Sprintf("verification failed: %v (binary may have been modified, run 'epack sync' to reinstall)", err))
		}
		if cleanup != nil {
			defer cleanup()
		}
	} else {
		// Unverified execution (--insecure-allow-unpinned mode)
		execPath = binaryPath
		if !flags.QuietMode {
			componenttypes.WarnUnpinnedExecution(out.Stderr(), componenttypes.KindTool, toolName, binaryPath, false)
		}
	}

	// Query capabilities to check requires_pack
	// Fail-safe: if capabilities query fails, default to requires_pack=true
	caps, capsErr := queryCapabilitiesWithTimeout(execPath)
	requiresPack := true // Default to true for safety
	if capsErr == nil {
		requiresPack = caps.RequiresPack
	}

	// Get version from capabilities if available (for result.json), fallback to lockfile
	toolVersion := locked.Version
	if caps != nil && caps.Version != "" {
		toolVersion = caps.Version
	}

	// Check runtime dependencies before execution
	// Only check if we have a pack (packless runs skip dependency checking)
	if absPackPath != "" && caps != nil {
		packSidecar := absPackPath + ".epack"
		if errs := toolprotocol.CheckDependencies(caps, packSidecar); len(errs) > 0 {
			return writePreExecFailure(out, toolName, runID, runDir, absPackPath, toolVersion,
				componenttypes.ExitDependencyMissing, componenttypes.ErrCodeDependencyMissing,
				toolprotocol.FormatDependencyErrors(errs))
		}
	}

	// Verify pack exists if provided
	if packPath != "" {
		if _, err := os.Stat(absPackPath); os.IsNotExist(err) {
			return writePreExecFailure(out, toolName, runID, runDir, "", toolVersion,
				componenttypes.ExitPackVerifyFailed, componenttypes.ErrCodePackVerifyFailed,
				fmt.Sprintf("pack not found: %s", packPath))
		}
	}

	// Verify pack integrity and get digest if we have a pack
	var packDigest string
	if packPath != "" {
		packDigest, err = verifyAndGetPackDigest(absPackPath)
		if err != nil {
			return writePreExecFailure(out, toolName, runID, runDir, absPackPath, toolVersion,
				componenttypes.ExitPackVerifyFailed, componenttypes.ErrCodePackVerifyFailed,
				fmt.Sprintf("pack verification failed: %v", err))
		}
	}

	// Enforce requires_pack - write result.json with failure before returning
	if requiresPack && packPath == "" {
		return writePreExecFailure(out, toolName, runID, runDir, "", toolVersion,
			componenttypes.ExitPackRequired, componenttypes.ErrCodePackRequired, "pack required but not provided")
	}

	// Record start time BEFORE execution
	startedAt := time.Now().UTC()

	// Write config file if tool has config
	configFilePath, configCleanup, err := writeToolConfig(toolCfg)
	if err != nil {
		return writePreExecFailure(out, toolName, runID, runDir, absPackPath, toolVersion,
			componenttypes.ExitConfigFailed, componenttypes.ErrCodeConfigFailed,
			fmt.Sprintf("writing tool config: %v", err))
	}
	if configCleanup != nil {
		defer configCleanup()
	}

	// Build protocol environment
	env := buildProtocolEnv(toolName, runID, runDir, absPackPath, packDigest, startedAt, toolCfg, configFilePath, flags)

	// Build tool arguments: if --pack was used, prepend absolute path
	finalToolArgs := toolArgs
	if flags.PackPath != "" && absPackPath != "" {
		finalToolArgs = append([]string{absPackPath}, toolArgs...)
	}

	// Execute tool and capture exit code
	binaryName := componenttypes.BinaryName(componenttypes.KindTool, toolName)
	toolExitCode, execErr := execToolWithProtocol(ctx, execPath, binaryName, finalToolArgs, env, runDir)

	// Record completion time
	completedAt := time.Now().UTC()

	// Process result.json (validate or backfill)
	// Use toolVersion from capabilities (with fallback to locked.Version set above)
	wrapperExitCode := processToolResult(out, toolName, runID, runDir, absPackPath, startedAt, completedAt, toolExitCode, toolVersion, execErr)

	if wrapperExitCode != 0 {
		return &errors.Error{Code: errors.InvalidInput, Exit: wrapperExitCode, Message: fmt.Sprintf("tool exited with code %d", wrapperExitCode)}
	}
	return nil
}

// verifyAndGetPackDigest opens a pack, verifies its integrity, and returns the digest.
// This ensures tools only receive valid, verified packs per the spec.
func verifyAndGetPackDigest(packPath string) (string, error) {
	p, err := pack.Open(packPath)
	if err != nil {
		return "", fmt.Errorf("opening pack: %w", err)
	}
	defer func() { _ = p.Close() }()

	// Verify pack integrity (manifest digest + all artifact digests)
	if err := p.VerifyIntegrity(); err != nil {
		return "", fmt.Errorf("integrity check failed: %w", err)
	}

	return p.Manifest().PackDigest, nil
}

// determineBaseDir determines the base directory for run output.
// Returns (baseDir, withPack, error).
func determineBaseDir(flags WrapperFlags, absPackPath string) (string, bool, error) {
	if flags.OutputDir != "" {
		return flags.OutputDir, absPackPath != "", nil
	}
	if absPackPath != "" {
		return absPackPath + ".epack", true, nil
	}
	baseDir, err := getPacklessRunDir()
	if err != nil {
		return "", false, err
	}
	return baseDir, false, nil
}

// getPacklessRunDir returns the platform-appropriate directory for packless runs.
func getPacklessRunDir() (string, error) {
	// XDG_STATE_HOME takes precedence on all Unix-like systems (including macOS)
	// This allows consistent behavior when users set XDG vars
	if runtime.GOOS != "windows" {
		if stateHome := os.Getenv("XDG_STATE_HOME"); stateHome != "" {
			return filepath.Join(stateHome, "epack"), nil
		}
	}

	// Platform-specific defaults
	switch runtime.GOOS {
	case "darwin":
		// macOS default: ~/Library/Application Support/epack
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, "Library", "Application Support", "epack"), nil
	case "windows":
		// Windows: %LOCALAPPDATA%\epack
		localAppData := os.Getenv("LOCALAPPDATA")
		// SECURITY: Validate LOCALAPPDATA is a safe local path.
		// Reject UNC paths (\\server\share) which could cause file operations on remote shares.
		// An attacker controlling LOCALAPPDATA could redirect writes to a malicious server.
		if localAppData == "" || !isLocalWindowsPath(localAppData) {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			localAppData = filepath.Join(home, "AppData", "Local")
		}
		return filepath.Join(localAppData, "epack"), nil
	default:
		// Linux and others: ~/.local/state/epack (XDG default)
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".local", "state", "epack"), nil
	}
}

// isLocalWindowsPath checks if a path is a local Windows path (not UNC or otherwise unsafe).
// Returns true for paths like "C:\Users\..." and false for UNC paths like "\\server\share".
func isLocalWindowsPath(path string) bool {
	return platformpath.IsLocalWindowsPath(path)
}

// failWrapper is the unified entry point for all wrapper pre-execution failures.
// It creates a run directory (best-effort), writes result.json, and returns an ExitError.
//
// This ensures ALL wrapper failures produce run records per the spec:
// - Tool not found -> ExitToolNotFound (10)
// - Tool verification failed -> ExitToolVerifyFailed (11)
// - Pack verification failed -> ExitPackVerifyFailed (12)
// - Lockfile missing/invalid -> ExitLockfileMissing (13)
// - Run directory creation failed -> ExitRunDirFailed (14)
// - Config file write failed -> ExitConfigFileFailed (15)
// - Pack required but not provided -> ExitPackRequired (16)
func failWrapper(out Output, toolName string, flags WrapperFlags, maybePackPath, toolVersion string, exitCode int, errCode, errMsg string) error {
	// Determine base directory for run output
	baseDir, withPack, err := determineBaseDir(flags, maybePackPath)
	if err != nil {
		// Can't determine run dir - fall back to simple error output
		_, _ = fmt.Fprintf(out.Stderr(), "Error: %s\n", errMsg)
		return &errors.Error{Code: errors.InvalidInput, Exit: exitCode, Message: errMsg}
	}

	// Create run directory
	runID, runDir, err := toolprotocol.CreateRunDir(baseDir, toolName, withPack)
	if err != nil {
		// Can't create run dir - fall back to simple error output
		_, _ = fmt.Fprintf(out.Stderr(), "Error: %s\n", errMsg)
		return &errors.Error{Code: errors.InvalidInput, Exit: exitCode, Message: errMsg}
	}

	// Write result.json with error
	return writePreExecFailure(out, toolName, runID, runDir, maybePackPath, toolVersion, exitCode, errCode, errMsg)
}

// handleConfigError creates a run record for config/lockfile errors.
// Uses failWrapper for consistent handling.
func handleConfigError(out Output, toolName string, flags WrapperFlags, configErr error) error {
	return failWrapper(out, toolName, flags, "", "",
		componenttypes.ExitLockfileMissing, componenttypes.ErrCodeLockfileError, configErr.Error())
}
