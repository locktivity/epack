// Package sign creates Sigstore attestations for evidence packs.
//
// This package defines the Signer interface and provides high-level pack signing
// operations. The sign/sigstore subpackage provides the Sigstore implementation.
//
// # Package Structure
//
//   - sign: Interface definitions and pack signing operations (SignPackFile)
//   - sign/sigstore: Sigstore implementation (Fulcio, Rekor, TSA integration)
//
// # Signing Methods
//
// Keyless (OIDC): Uses Sigstore's Fulcio CA with identity from an OIDC provider
// (Google, GitHub, etc.). The signer's identity is embedded in a short-lived
// certificate and recorded in the Rekor transparency log.
//
//	signer, err := sigstore.NewSigner(ctx, sigstore.Options{
//	    OIDC: &sigstore.OIDCOptions{Interactive: true},
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if err := sign.SignPackFile(ctx, "evidence.epack", signer); err != nil {
//	    log.Fatal(err)
//	}
//
// Key-based: Uses a provided private key for signing.
//
//	signer, err := sigstore.NewSigner(ctx, sigstore.Options{
//	    PrivateKey: privateKey,
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if err := sign.SignPackFile(ctx, "evidence.epack", signer); err != nil {
//	    log.Fatal(err)
//	}
//
// Signing creates an in-toto attestation with the pack digest as the subject,
// wraps it in a DSSE envelope with a Sigstore bundle, and appends it to the pack.
//
// # Backward Compatibility
//
// For backward compatibility, this package re-exports commonly used types from
// sign/sigstore. New code should import sign/sigstore directly.
package sign
