package sync

import (
	"github.com/locktivity/epack/internal/component/sigstore"
	"github.com/locktivity/epack/internal/componenttypes"
)

// Sigstore verification wrappers

// SigstoreResult contains verified signer identity from Sigstore bundle.
type SigstoreResult = sigstore.Result

// ExpectedIdentity specifies the expected source identity for signature verification.
type ExpectedIdentity = sigstore.ExpectedIdentity

// ComputeDigest computes sha256 digest of a file.
func ComputeDigest(path string) (string, error) {
	return sigstore.ComputeDigest(path)
}

// VerifyDigest checks that a file matches the expected digest.
func VerifyDigest(path, expected string) error {
	return sigstore.VerifyDigest(path, expected)
}

// VerifySigstoreBundle verifies a Sigstore bundle against an artifact.
// Returns the verified signer identity claims.
func VerifySigstoreBundle(bundlePath, artifactPath string, expected *ExpectedIdentity) (*SigstoreResult, error) {
	return sigstore.VerifyBundle(bundlePath, artifactPath, expected)
}

// MatchSigner checks that verification result matches expected signer.
func MatchSigner(result *SigstoreResult, expected *componenttypes.LockedSigner) error {
	if expected == nil {
		return sigstore.MatchSigner(result, nil)
	}
	// Convert lockfile.LockedSigner to sigstore.LockedSigner
	sigstoreSigner := &sigstore.LockedSigner{
		Issuer:              expected.Issuer,
		Subject:             expected.Subject,
		SourceRepositoryURI: expected.SourceRepositoryURI,
		SourceRepositoryRef: expected.SourceRepositoryRef,
	}
	return sigstore.MatchSigner(result, sigstoreSigner)
}
