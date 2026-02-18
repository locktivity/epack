// Package sigstore provides Sigstore-based signing for evidence packs.
//
// This package implements the sign.Signer interface using Sigstore infrastructure:
//   - Fulcio for certificate issuance (keyless/OIDC signing)
//   - Rekor for transparency log entries
//   - Optional TSA for RFC3161 timestamps
//
// For keyless (OIDC) signing:
//
//	signer, err := sigstore.NewSigner(ctx, sigstore.Options{
//	    OIDC: &sigstore.OIDCOptions{Interactive: true},
//	})
//
// For key-based signing:
//
//	signer, err := sigstore.NewSigner(ctx, sigstore.Options{
//	    PrivateKey: privateKey,
//	})
package sigstore
