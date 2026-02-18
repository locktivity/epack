// Package merge combines multiple evidence packs into a single merged pack.
//
// Merged packs include:
//   - All artifacts from source packs (with path prefixing)
//   - A provenance object documenting which packs were merged
//   - Optionally embedded attestations from source packs
//
// # Attestation Handling
//
// When IncludeAttestations is true, source pack attestations are embedded as
// complete Sigstore bundles in the provenance. By default (VerifyAttestations: true),
// signatures are verified and statement subjects are checked against source pack
// digests before embedding.
//
// Signer identity is intentionally not verified during merge. The merge operator
// is untrusted from the receiver's perspective, and identity policy is specific
// to each receiver. Embedded attestations contain complete certificate chains,
// so receivers can and should verify identity themselves:
//
//	// Receiver verifies with their identity policy
//	verifier, _ := verify.NewSigstoreVerifier(
//	    verify.WithIssuer("https://accounts.google.com"),
//	    verify.WithSubject("trusted-signer@example.com"),
//	)
//	results, err := pack.VerifyEmbeddedAttestations(ctx, verifier)
//
// # Example
//
//	verifier, _ := verify.NewSigstoreVerifier(verify.WithInsecureSkipIdentityCheck())
//	opts := merge.Options{
//	    Stream:              "myorg/combined",
//	    IncludeAttestations: true,
//	    VerifyAttestations:  true,
//	    Verifier:            verifier,
//	}
//	err := merge.Merge(ctx, sources, "merged.pack", opts)
package merge
