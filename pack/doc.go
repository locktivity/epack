// Package pack provides APIs to open, validate, and read evidence packs.
//
// An evidence pack is a ZIP archive containing a manifest.json and artifacts.
// This package enforces structural, size, and digest checks defined by the
// Evidence Pack specification.
//
// Opening a pack:
//
//	p, err := pack.Open("evidence.pack")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer p.Close()
//
// Verifying integrity (all digests match):
//
//	if err := p.VerifyIntegrity(); err != nil {
//	    log.Fatal("integrity check failed:", err)
//	}
//
// Reading artifacts:
//
//	data, err := p.ReadArtifact("artifacts/config.json")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Accessing manifest metadata:
//
//	m := p.Manifest()
//	fmt.Printf("Stream: %s\n", m.Stream)
//	fmt.Printf("Pack Digest: %s\n", m.PackDigest)
//	fmt.Printf("Artifacts: %d\n", len(m.Artifacts))
//
// Verifying attestations:
//
//	verifier, _ := verify.NewSigstoreVerifier(verify.WithIssuer("https://accounts.google.com"))
//	results, err := p.VerifyAllAttestations(ctx, verifier)
//
// Verifying embedded attestations in merged packs:
//
//	results, err := p.VerifyEmbeddedAttestations(ctx, verifier)
//	for _, r := range results {
//	    fmt.Printf("Source pack %s: verified by %s\n", r.Stream, r.Result.Identity.Subject)
//	}
//
// For creating packs, see the pack/builder subpackage.
// For Sigstore verification, see the pack/verify subpackage.
//
// # Layer Boundary
//
// This package is Layer 1 (Pack Format) - a foundational layer that defines
// the evidence pack format. It MUST NOT import:
//   - internal/component (component management)
//   - internal/collector (collector execution)
//   - internal/tool (tool execution)
//   - internal/dispatch (tool dispatch)
//   - internal/catalog (discovery)
//   - internal/cli (presentation)
//
// The pack format is independent of how packs are created or consumed.
package pack
