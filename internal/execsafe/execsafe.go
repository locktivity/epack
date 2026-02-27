// Package execsafe provides TOCTOU-safe binary execution primitives.
// These are used by both collector and tool execution to ensure
// cryptographic verification of binaries before execution.
package execsafe

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/locktivity/epack/internal/digest"
	"golang.org/x/sys/unix"
)

// AllowedEnvVars is the allowlist of environment variables passed to
// collectors and tools. This prevents credential exfiltration via
// malicious/compromised binaries.
// NOTE: PATH is handled separately via SafePATH() - it is NOT in this list.
var AllowedEnvVars = []string{
	// User identity
	"HOME",
	"USER",

	// Locale
	"LANG",
	"LC_ALL",
	"LC_CTYPE",

	// Timezone
	"TZ",

	// Temp directories
	"TMPDIR",
	"TEMP",
	"TMP",

	// Terminal
	"TERM",
	"NO_COLOR",
	"CLICOLOR",
	"CLICOLOR_FORCE",

	// SSL/TLS certificates (needed for tools that make HTTPS requests)
	"SSL_CERT_FILE",
	"SSL_CERT_DIR",

	// Proxy settings (tools may need these for network access)
	"HTTP_PROXY",
	"HTTPS_PROXY",
	"NO_PROXY",
	"http_proxy",
	"https_proxy",
	"no_proxy",

	// XDG directories (for config/cache/state location)
	"XDG_CONFIG_HOME",
	"XDG_CACHE_HOME",
	"XDG_DATA_HOME",
	"XDG_STATE_HOME",
	"XDG_RUNTIME_DIR",
}

// SafePATH returns a deterministic, minimal PATH for binary execution.
// This prevents PATH injection attacks where a malicious interpreter is placed
// earlier in PATH than the legitimate one.
//
// SECURITY: On Windows, we use hardcoded paths rather than environment variables.
// The SystemRoot env var can be controlled by attackers. We use the standard
// Windows directory path. If Windows is installed elsewhere, the PATH will be
// wrong but the operation will fail safely (command not found) rather than
// executing attacker binaries.
func SafePATH() string {
	if runtime.GOOS == "windows" {
		// SECURITY: Hardcode Windows paths instead of trusting SystemRoot env var.
		return `C:\Windows\System32;C:\Windows`
	}
	// Unix: Minimal safe PATH with standard locations
	// Order matters - prefer /usr/bin over /usr/local/bin to avoid user-writable paths
	return "/usr/bin:/bin:/usr/sbin:/sbin"
}

// VerifiedBinaryFD creates a verified, sealed copy of a binary for execution.
// This eliminates TOCTOU races by hashing bytes AS they are copied to the
// sealed temp file - we execute exactly the bytes we verified.
//
// SECURITY: The critical invariant is that we never execute bytes we didn't hash.
// Previous approaches that hash-then-copy or hash-then-exec-fd are vulnerable
// to race conditions where the source file is modified between operations.
//
// The approach:
// 1. Open the source binary with O_RDONLY | O_NOFOLLOW (prevents symlink following)
// 2. Create a sealed temp file in a temp directory
// 3. Copy bytes through a TeeReader that simultaneously hashes and writes
// 4. Verify the hash matches AFTER the copy completes
// 5. Seal the temp directory and return the path to the verified copy
//
// This is race-free because the bytes written to the temp file ARE the bytes
// that were hashed - there's no window for modification.
func VerifiedBinaryFD(binaryPath, expectedDigest string) (execPath string, cleanup func(), err error) {
	srcFile, err := openVerifiedSourceFile(binaryPath)
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = srcFile.Close() }()
	tmpDir, cleanup, err := SecureTempDir("epack-exec-*")
	if err != nil {
		return "", nil, err
	}
	defer func() {
		if err != nil && cleanup != nil {
			cleanup()
		}
	}()

	tmpPath := filepath.Join(tmpDir, filepath.Base(binaryPath))
	hasher, err := copyAndHashBinary(srcFile, tmpPath)
	if err != nil {
		return "", nil, err
	}
	if err := verifyExpectedDigest(binaryPath, expectedDigest, hasher.Digest()); err != nil {
		return "", nil, err
	}
	if err := os.Chmod(tmpDir, 0500); err != nil {
		return "", nil, fmt.Errorf("sealing temp dir: %w", err)
	}
	return tmpPath, cleanup, nil
}

func openVerifiedSourceFile(binaryPath string) (*os.File, error) {
	fd, err := unix.Open(binaryPath, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		if err == unix.ELOOP {
			return nil, fmt.Errorf("refusing to execute symlink: %s", binaryPath)
		}
		return nil, fmt.Errorf("opening binary: %w", err)
	}
	return os.NewFile(uintptr(fd), binaryPath), nil
}

func copyAndHashBinary(srcFile *os.File, tmpPath string) (*digest.Hasher, error) {
	dstFile, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0500)
	if err != nil {
		return nil, fmt.Errorf("creating temp file: %w", err)
	}

	hasher := digest.NewHasher()
	if _, err := io.Copy(dstFile, io.TeeReader(srcFile, hasher)); err != nil {
		_ = dstFile.Close()
		return nil, fmt.Errorf("copying binary: %w", err)
	}
	if err := dstFile.Sync(); err != nil {
		_ = dstFile.Close()
		return nil, fmt.Errorf("syncing temp file: %w", err)
	}
	if err := dstFile.Close(); err != nil {
		return nil, fmt.Errorf("closing temp file: %w", err)
	}
	return hasher, nil
}

func verifyExpectedDigest(binaryPath, expectedDigest string, computedDigest digest.Digest) error {
	expectedDigestParsed, err := digest.Parse(expectedDigest)
	if err != nil {
		return fmt.Errorf("invalid expected digest format: %w", err)
	}
	if computedDigest.Equal(expectedDigestParsed) {
		return nil
	}
	return fmt.Errorf("digest mismatch for %s: binary does not match expected %s", filepath.Base(binaryPath), expectedDigest)
}

// VerifyDigestFromFD verifies a file's digest by reading from an already-open fd.
// This is used for TOCTOU-safe verification where the caller already has an open fd.
func VerifyDigestFromFD(fd int, expectedDigest string) error {
	file := os.NewFile(uintptr(fd), "")
	defer func() { _ = file.Close() }()

	// Reset to beginning
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seeking file: %w", err)
	}

	computedDigest, err := digest.FromReader(file)
	if err != nil {
		return fmt.Errorf("hashing file: %w", err)
	}

	// SECURITY: Uses constant-time comparison via digest.Equal to prevent timing attacks.
	expectedDigestParsed, err := digest.Parse(expectedDigest)
	if err != nil {
		return fmt.Errorf("invalid expected digest format: %w", err)
	}
	if !computedDigest.Equal(expectedDigestParsed) {
		// SECURITY: Only expose the expected digest in error messages, not the computed one.
		// Exposing computed digests could theoretically assist attackers in understanding
		// binary contents. The expected digest is already known to the attacker (from lockfile).
		return fmt.Errorf("digest mismatch: binary does not match expected %s", expectedDigest)
	}

	return nil
}

// OpenBinaryNoFollow opens a binary with O_NOFOLLOW to prevent symlink attacks.
// Returns the fd and an error.
func OpenBinaryNoFollow(path string) (int, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		if err == unix.ELOOP {
			return -1, fmt.Errorf("refusing to open symlink: %s", path)
		}
		return -1, err
	}
	return fd, nil
}

// FstatInode returns the inode of a file descriptor.
func FstatInode(fd int) (uint64, error) {
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return 0, err
	}
	return stat.Ino, nil
}

// BuildRestrictedEnv builds a restricted environment for binary execution.
// SECURITY: By default, PATH is set to a safe, deterministic value to prevent
// PATH injection attacks. Only with inheritPath=true is the ambient
// PATH inherited (which may contain attacker-controlled directories).
func BuildRestrictedEnv(environ []string, inheritPath bool) []string {
	filtered := FilterEnv(environ, AllowedEnvVars)

	// Add PATH - either safe or inherited
	if inheritPath {
		// INSECURE: Inherit PATH from environment
		for _, env := range environ {
			if strings.HasPrefix(strings.ToUpper(env), "PATH=") {
				filtered = append(filtered, env)
				break
			}
		}
	} else {
		// SECURE: Use deterministic safe PATH
		filtered = append(filtered, "PATH="+SafePATH())
	}

	return filtered
}

// FilterEnv returns only the allowed environment variables.
func FilterEnv(environ []string, allowed []string) []string {
	allowedMap := make(map[string]bool)
	for _, key := range allowed {
		allowedMap[strings.ToUpper(key)] = true
	}

	var filtered []string
	for _, env := range environ {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 && allowedMap[strings.ToUpper(parts[0])] {
			filtered = append(filtered, env)
		}
	}
	return filtered
}

// proxyEnvVars lists environment variables that may contain proxy URLs with credentials.
var proxyEnvVars = map[string]bool{
	"HTTP_PROXY":  true,
	"HTTPS_PROXY": true,
	"http_proxy":  true,
	"https_proxy": true,
}

// StripProxyCredentials removes username:password from proxy environment variables.
// This prevents credential leakage to untrusted binaries while still allowing
// proxy connectivity.
//
// SECURITY: Proxy URLs can contain embedded credentials like:
//
//	http://user:password@proxy.example.com:8080
//
// These credentials would be visible to any executed binary. This function
// strips credentials while preserving the proxy host:port for connectivity.
//
// Returns the sanitized environment variables.
func StripProxyCredentials(environ []string) []string {
	result := make([]string, 0, len(environ))
	for _, env := range environ {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			result = append(result, env)
			continue
		}

		key, value := parts[0], parts[1]
		if !proxyEnvVars[key] {
			result = append(result, env)
			continue
		}

		// Try to parse as URL and strip credentials
		sanitized := stripURLCredentials(value)
		result = append(result, key+"="+sanitized)
	}
	return result
}

// stripURLCredentials removes userinfo (user:pass@) from a URL string.
// Returns the original string if parsing fails (fail-safe: don't break non-URL values).
func stripURLCredentials(rawURL string) string {
	// Handle empty or obviously non-URL values
	if rawURL == "" {
		return rawURL
	}

	// Parse the URL
	u, err := url.Parse(rawURL)
	if err != nil {
		// Can't parse - return original to avoid breaking things
		return rawURL
	}

	// If no userinfo, nothing to strip
	if u.User == nil {
		return rawURL
	}

	// Clear the userinfo and reconstruct
	u.User = nil
	return u.String()
}

// BuildRestrictedEnvSafe builds a restricted environment with proxy credentials stripped.
// This is the recommended function for executing untrusted binaries.
//
// SECURITY: This function:
// 1. Filters to only allowed environment variables
// 2. Strips credentials from proxy URLs
// 3. Sets a safe, deterministic PATH (unless inheritPath is true)
func BuildRestrictedEnvSafe(environ []string, inheritPath bool) []string {
	filtered := FilterEnv(environ, AllowedEnvVars)
	sanitized := StripProxyCredentials(filtered)

	// Add PATH - either safe or inherited
	if inheritPath {
		// INSECURE: Inherit PATH from environment
		for _, env := range environ {
			if strings.HasPrefix(strings.ToUpper(env), "PATH=") {
				sanitized = append(sanitized, env)
				break
			}
		}
	} else {
		// SECURE: Use deterministic safe PATH
		sanitized = append(sanitized, "PATH="+SafePATH())
	}

	return sanitized
}

// CommandOptions configures how a restricted command is built.
type CommandOptions struct {
	// InheritPath uses the ambient PATH instead of SafePATH.
	// SECURITY WARNING: Only use this for trusted binaries where PATH
	// injection is not a concern (e.g., system tools during build).
	InheritPath bool

	// StripProxyCredentials removes username:password from proxy env vars.
	// Defaults to true for untrusted binaries.
	StripProxyCredentials bool

	// AdditionalEnv adds extra environment variables to the base restricted set.
	// These are added AFTER filtering, so they can include any variables.
	// SECURITY: The caller must validate these do not contain secrets.
	AdditionalEnv []string

	// Secrets is a list of environment variable names to pass through.
	// Each name is validated against DeniedSecretPrefixes before lookup.
	// Only secrets that exist in the environment AND pass validation are included.
	Secrets []string

	// WorkDir sets the working directory for command execution.
	WorkDir string
}

// DefaultCommandOptions returns secure defaults for command construction.
func DefaultCommandOptions() CommandOptions {
	return CommandOptions{
		InheritPath:           false, // Use SafePATH
		StripProxyCredentials: true,  // Strip proxy credentials
	}
}

// RestrictedCommand holds a prepared command with security-validated environment.
// Use NewRestrictedCommand to create instances.
type RestrictedCommand struct {
	// Path is the executable path (may be a verified copy from VerifiedBinaryFD).
	Path string

	// Args is the argument list (Args[0] should be the command name).
	Args []string

	// Env is the security-filtered environment.
	Env []string

	// Dir is the working directory (empty means current directory).
	Dir string

	// cleanup is called after command execution to clean up temp files.
	cleanup func()
}

// Cleanup releases resources associated with this command.
// Safe to call multiple times or on nil.
func (c *RestrictedCommand) Cleanup() {
	if c != nil && c.cleanup != nil {
		c.cleanup()
		c.cleanup = nil
	}
}

// NewRestrictedCommand creates a command with security-hardened environment.
// This is the REQUIRED entry point for executing collectors and tools.
//
// SECURITY: This function centralizes all security checks for command execution:
//   - Environment filtering to AllowedEnvVars only
//   - Safe PATH (no user-controlled directories)
//   - Secret name validation (blocks EPACK_*, LD_*, DYLD_*, _*)
//   - Optional proxy credential stripping
//
// Example usage:
//
//	cmd, err := execsafe.NewRestrictedCommand(binaryPath, args, execsafe.DefaultCommandOptions())
//	if err != nil {
//	    return err
//	}
//	defer cmd.Cleanup()
//
//	execCmd := exec.Command(cmd.Path, cmd.Args[1:]...)
//	execCmd.Env = cmd.Env
//	execCmd.Dir = cmd.Dir
//	return execCmd.Run()
func NewRestrictedCommand(binaryPath string, args []string, opts CommandOptions) (*RestrictedCommand, error) {
	// Build base restricted environment
	var env []string
	if opts.StripProxyCredentials {
		env = BuildRestrictedEnvSafe(os.Environ(), opts.InheritPath)
	} else {
		env = BuildRestrictedEnv(os.Environ(), opts.InheritPath)
	}

	// Add additional environment variables
	env = append(env, opts.AdditionalEnv...)

	// Process secrets - validate and add if present in environment
	for _, secretName := range opts.Secrets {
		// Validate secret name
		if err := ValidateSecretName(secretName); err != nil {
			// Skip invalid secrets (defense in depth - should be caught at config time)
			continue
		}

		// Only pass through if the secret exists in the environment
		if value := os.Getenv(secretName); value != "" {
			env = append(env, secretName+"="+value)
		}
	}

	return &RestrictedCommand{
		Path:    binaryPath,
		Args:    args,
		Env:     env,
		Dir:     opts.WorkDir,
		cleanup: nil, // No cleanup for non-verified binaries
	}, nil
}

// NewVerifiedRestrictedCommand creates a command with both verified binary and
// security-hardened environment.
//
// SECURITY: This function provides the strongest security guarantees:
//   - Binary is verified against expected digest (TOCTOU-safe)
//   - Environment is filtered and sanitized
//   - A verified copy of the binary is executed
//
// The caller MUST call Cleanup() after execution to remove the verified copy.
//
// Example usage:
//
//	cmd, err := execsafe.NewVerifiedRestrictedCommand(
//	    binaryPath, expectedDigest, args, execsafe.DefaultCommandOptions())
//	if err != nil {
//	    return err
//	}
//	defer cmd.Cleanup()
//
//	execCmd := exec.Command(cmd.Path, cmd.Args[1:]...)
//	execCmd.Env = cmd.Env
//	return execCmd.Run()
func NewVerifiedRestrictedCommand(binaryPath, expectedDigest string, args []string, opts CommandOptions) (*RestrictedCommand, error) {
	// Create verified copy of binary
	verifiedPath, cleanup, err := VerifiedBinaryFD(binaryPath, expectedDigest)
	if err != nil {
		return nil, fmt.Errorf("verifying binary: %w", err)
	}

	// Build restricted command with verified path
	cmd, err := NewRestrictedCommand(verifiedPath, args, opts)
	if err != nil {
		cleanup()
		return nil, err
	}

	// Transfer cleanup responsibility
	cmd.cleanup = cleanup
	cmd.Path = verifiedPath

	// Update Args[0] if it matches the original binary path
	if len(cmd.Args) > 0 && cmd.Args[0] == binaryPath {
		cmd.Args[0] = verifiedPath
	}

	return cmd, nil
}
