//go:build components

package utilitycmd

import (
	"context"
	"fmt"
	"os"

	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/execsafe"
	"github.com/locktivity/epack/internal/exitcode"
	"github.com/locktivity/epack/internal/procexec"
	"github.com/locktivity/epack/internal/userconfig"
	"github.com/spf13/cobra"
)

// Exit codes are centralized in componenttypes package.
// Use componenttypes.ExitComponentNotFound, componenttypes.ExitVerifyFailed, etc.

// dispatchUtility executes an installed utility with TOCTOU-safe verification.
//
// Security guarantees (when insecureAllowUnpinned is false):
//  1. TOCTOU-safe: Binary is copied while hashing (execsafe.VerifiedBinaryFD)
//  2. Digest verification: Must match utilities.lock entry
//  3. Restricted environment: Only allowed env vars passed through
//  4. Safe PATH: Uses minimal deterministic PATH
//  5. No symlink following: O_NOFOLLOW on binary open
//
// When insecureAllowUnpinned is true:
//   - Skips digest verification (for development/testing)
//
// Note: Utilities must be installed via 'epack utility install'. There is no
// PATH discovery fallback (matching the collector model).
func dispatchUtility(cmd *cobra.Command, utilityName string, args []string, insecureAllowUnpinned bool) error {
	ctx := cmd.Context()

	// Validate utility name to prevent path traversal
	if err := validateUtilityName(utilityName); err != nil {
		return &exitError{
			Exit:    exitcode.General,
			Message: fmt.Sprintf("invalid utility name: %v", err),
		}
	}

	// Load utilities lockfile
	lf, err := userconfig.LoadUtilitiesLock()
	if err != nil {
		return &exitError{
			Exit:    exitcode.General,
			Message: fmt.Sprintf("loading utilities lock: %v", err),
		}
	}

	// Get utility entry - must be installed
	utility, ok := lf.GetUtility(utilityName)
	if !ok {
		return &exitError{
			Exit:    componenttypes.ExitComponentNotFound,
			Message: fmt.Sprintf("utility %q not installed\n\nInstall with: epack utility install %s", utilityName, utilityName),
		}
	}

	// Get digest and path
	expectedDigest, _ := lf.UtilityDigest(utilityName)
	binaryPath, _ := userconfig.UtilityInstallPath(utilityName, utility.Version)

	// Verify binary exists
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		return &exitError{
			Exit:    componenttypes.ExitComponentNotFound,
			Message: fmt.Sprintf("utility %q binary not found at %s\n\nReinstall with: epack utility install %s", utilityName, binaryPath, utilityName),
		}
	}

	// Check for missing digest
	if expectedDigest == "" && !insecureAllowUnpinned {
		return &exitError{
			Exit:    componenttypes.ExitVerifyFailed,
			Message: fmt.Sprintf("utility %q missing digest in lockfile\n\nReinstall with: epack utility install %s", utilityName, utilityName),
		}
	}

	// Determine execution path
	var execPath string
	var cleanup func()

	if expectedDigest != "" && !insecureAllowUnpinned {
		// TOCTOU-safe verification: copy while hashing
		execPath, cleanup, err = execsafe.VerifiedBinaryFD(binaryPath, expectedDigest)
		if err != nil {
			return &exitError{
				Exit:    componenttypes.ExitVerifyFailed,
				Message: fmt.Sprintf("verifying utility %q: %v\n\nThe binary may have been modified. Reinstall with: epack utility install %s", utilityName, err, utilityName),
			}
		}
		defer cleanup()
	} else {
		// Unverified execution (insecure mode)
		execPath = binaryPath
		componenttypes.WarnUnpinnedExecution(os.Stderr, componenttypes.KindUtility, utilityName, binaryPath, false)
	}

	// Execute the binary
	exitCode, err := executeUtility(ctx, execPath, args)
	if err != nil {
		return &exitError{
			Exit:    exitcode.General,
			Message: fmt.Sprintf("executing utility: %v", err),
		}
	}

	// Pass through utility exit code
	if exitCode != 0 {
		os.Exit(exitCode)
	}

	return nil
}

// executeUtility runs the verified binary with restricted environment.
func executeUtility(ctx context.Context, execPath string, args []string) (int, error) {
	// Build restricted environment (no PATH inheritance for security)
	env := execsafe.BuildRestrictedEnvSafe(os.Environ(), false)

	cmd, cancel, err := procexec.CommandChecked(ctx, procexec.Spec{
		Path:                execPath,
		Args:                args,
		Env:                 env,
		Stdin:               os.Stdin,
		Stdout:              os.Stdout,
		Stderr:              os.Stderr,
		EnforceEnvAllowlist: true,
		AllowedEnv:          append(append([]string{}, execsafe.AllowedEnvVars...), "PATH"),
	})
	if err != nil {
		return 1, err
	}
	defer cancel()

	// Run and capture exit code
	err = cmd.Run()
	if err != nil {
		if cmd.ProcessState != nil {
			return cmd.ProcessState.ExitCode(), nil
		}
		return 1, err
	}

	return 0, nil
}

// exitError represents an error with a specific exit code.
type exitError struct {
	Exit    int
	Message string
}

func (e *exitError) Error() string {
	return e.Message
}

func (e *exitError) ExitCode() int {
	return e.Exit
}
