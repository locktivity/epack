//go:build components

package dispatch

import (
	"context"

	"github.com/locktivity/epack/internal/toolprotocol"
)

// Executor abstracts tool binary execution for testability.
// The default implementation uses exec.Command with context support.
type Executor interface {
	// Exec runs a binary with the given arguments and environment.
	// The context enables cancellation of long-running tools.
	// Returns the exit code and any execution error (nil if tool ran, even with non-zero exit).
	Exec(ctx context.Context, binaryPath string, args, env []string, runDir string) (exitCode int, err error)
}

// CapabilitiesProber abstracts tool capabilities querying for testability.
type CapabilitiesProber interface {
	// Probe queries a tool's capabilities via --capabilities flag.
	// Returns nil capabilities and error if probe fails.
	Probe(binaryPath string) (*toolprotocol.Capabilities, error)
}

// PackVerifier abstracts pack integrity verification for testability.
type PackVerifier interface {
	// Verify opens a pack, verifies integrity, and returns its digest.
	// Returns error if pack is invalid or verification fails.
	Verify(packPath string) (digest string, err error)
}

// BinaryVerifier abstracts TOCTOU-safe binary verification for testability.
type BinaryVerifier interface {
	// VerifyBinary verifies a binary's digest and returns a safe execution path.
	// The cleanup function should be called after execution completes.
	// Returns error if digest doesn't match or verification fails.
	VerifyBinary(binaryPath, expectedDigest string) (execPath string, cleanup func(), err error)
}

// DefaultExecutor is the production Executor using exec.Command.
type DefaultExecutor struct{}

// Exec implements Executor using execToolWithProtocol.
func (DefaultExecutor) Exec(ctx context.Context, binaryPath string, args, env []string, runDir string) (int, error) {
	// Extract binary name from path for logging
	binaryName := binaryPath
	return execToolWithProtocol(ctx, binaryPath, binaryName, args, env, runDir)
}

// DefaultCapabilitiesProber is the production CapabilitiesProber.
type DefaultCapabilitiesProber struct{}

// Probe implements CapabilitiesProber using queryCapabilitiesWithTimeout.
func (DefaultCapabilitiesProber) Probe(binaryPath string) (*toolprotocol.Capabilities, error) {
	return queryCapabilitiesWithTimeout(binaryPath)
}

// DefaultPackVerifier is the production PackVerifier.
type DefaultPackVerifier struct{}

// Verify implements PackVerifier using verifyAndGetPackDigest.
func (DefaultPackVerifier) Verify(packPath string) (string, error) {
	return verifyAndGetPackDigest(packPath)
}
