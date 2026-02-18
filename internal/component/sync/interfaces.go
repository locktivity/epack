package sync

import "os"

// Installer abstracts local binary installation for testability.
// The default implementation writes to the filesystem.
type Installer interface {
	// Install writes a binary to the install path with proper permissions.
	// Returns error if installation fails.
	Install(tmpPath, installPath string) error

	// Verify checks if an installed binary matches the expected digest.
	// Returns nil if digest matches, error otherwise.
	Verify(installPath, expectedDigest string) error

	// Exists checks if a binary is already installed at the given path.
	Exists(installPath string) bool
}

// DigestVerifier abstracts digest verification for testability.
type DigestVerifier interface {
	// Verify computes the SHA-256 digest of a file and compares it to expected.
	// Returns nil if match, error if mismatch or read failure.
	Verify(path, expectedDigest string) error
}

// SigstoreVerifier abstracts Sigstore bundle verification for testability.
type SigstoreVerifier interface {
	// Verify verifies a Sigstore bundle against a binary and expected identity.
	// Returns signing result on success, error on verification failure.
	Verify(bundlePath, binaryPath string, expectedIdentity *ExpectedIdentity) (*SigstoreResult, error)
}

// DefaultInstaller is the production Installer using filesystem operations.
type DefaultInstaller struct{}

// Install implements Installer by making the binary executable and renaming atomically.
func (DefaultInstaller) Install(tmpPath, installPath string) error {
	if err := os.Chmod(tmpPath, 0755); err != nil {
		return err
	}
	return os.Rename(tmpPath, installPath)
}

// Verify implements Installer using VerifyDigest.
func (DefaultInstaller) Verify(installPath, expectedDigest string) error {
	return VerifyDigest(installPath, expectedDigest)
}

// Exists implements Installer using os.Stat.
func (DefaultInstaller) Exists(installPath string) bool {
	_, err := os.Stat(installPath)
	return err == nil
}

// DefaultDigestVerifier is the production DigestVerifier.
type DefaultDigestVerifier struct{}

// Verify implements DigestVerifier using VerifyDigest.
func (DefaultDigestVerifier) Verify(path, expectedDigest string) error {
	return VerifyDigest(path, expectedDigest)
}

// DefaultSigstoreVerifier is the production SigstoreVerifier.
type DefaultSigstoreVerifier struct{}

// Verify implements SigstoreVerifier using VerifySigstoreBundle.
func (DefaultSigstoreVerifier) Verify(bundlePath, binaryPath string, expectedIdentity *ExpectedIdentity) (*SigstoreResult, error) {
	return VerifySigstoreBundle(bundlePath, binaryPath, expectedIdentity)
}
