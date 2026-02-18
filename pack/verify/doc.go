// Package verify validates Sigstore attestations in evidence packs.
//
// This package handles:
//   - Loading Sigstore bundles from attestation files
//   - Verifying signatures against the transparency log
//   - Extracting signer identity (issuer, subject)
//   - Matching attestation subjects to pack digests
//
// Example:
//
//	result, err := verify.VerifyAttestation(ctx, bundleBytes, opts)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Signed by: %s\n", result.Subject)
//
// Identity verification requires specifying expected issuer and/or subject
// using exact match or regular expressions.
package verify
