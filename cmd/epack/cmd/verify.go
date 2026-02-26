package cmd

import (
	"fmt"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/verify"
	"github.com/locktivity/epack/pack"
	"github.com/spf13/cobra"
)

var (
	verifyIssuer                     string
	verifyIssuerRegexp               string
	verifySubject                    string
	verifySubjectRegexp              string
	verifyOffline                    bool
	verifyIntegrityOnly              bool
	verifyRequireAttestation         bool
	verifyInsecureSkipIdentityCheck  bool
	verifyInsecureSkipEmbeddedVerify bool
	verifyTrustRoot                  string
)

func init() {
	rootCmd.AddCommand(verifyCmd)

	verifyCmd.Flags().StringVar(&verifyIssuer, "issuer", "", "required OIDC issuer (exact match)")
	verifyCmd.Flags().StringVar(&verifyIssuerRegexp, "issuer-regexp", "", "required OIDC issuer (regexp)")
	verifyCmd.Flags().StringVar(&verifySubject, "subject", "", "required certificate subject (exact match)")
	verifyCmd.Flags().StringVar(&verifySubjectRegexp, "subject-regexp", "", "required certificate subject (regexp)")
	verifyCmd.Flags().BoolVar(&verifyOffline, "offline", false, "skip transparency log verification")
	verifyCmd.Flags().BoolVar(&verifyIntegrityOnly, "integrity-only", false, "only verify digests, skip attestation verification")
	verifyCmd.Flags().BoolVar(&verifyRequireAttestation, "require-attestation", false, "fail if no attestations present")
	verifyCmd.Flags().BoolVar(&verifyInsecureSkipIdentityCheck, "insecure-skip-identity-check", false,
		"INSECURE: accept any valid signer without identity verification (use --issuer/--subject instead)")
	verifyCmd.Flags().BoolVar(&verifyInsecureSkipEmbeddedVerify, "insecure-skip-embedded-verify", false,
		"INSECURE: skip verification of embedded attestations in merged pack provenance")
	verifyCmd.Flags().StringVar(&verifyTrustRoot, "trust-root", "",
		"path to Sigstore trust root JSON file (default: fetch from Sigstore TUF)")
}

var verifyCmd = &cobra.Command{
	Use:        "verify <pack>",
	Short:      "Verify pack integrity and attestations",
	SuggestFor: []string{"verfiy", "veirfy", "varify", "check"},
	Long: `Verify an evidence pack's integrity and cryptographic attestations.

By default, verifies:
  - Artifact digests match the manifest
  - Pack digest is correct
  - Attestation signatures are valid (if present)

When verifying attestations, specify an identity policy (--issuer and/or
--subject) to ensure the pack was signed by an authorized identity. Without
this, verification will fail unless you use --insecure-skip-identity-check.

For CI environments, use --trust-root to pin a specific Sigstore trust root
instead of fetching from TUF. This avoids network dependencies and ensures
reproducible verification. The trust root JSON can be obtained from:
https://raw.githubusercontent.com/sigstore/root-signing/main/targets/trusted_root.json

Exit codes:
  0  Verification passed
  1  Verification failed
  2  Pack malformed/cannot open

Examples:
  # Verify with identity requirements (RECOMMENDED)
  epack verify evidence.epack --issuer "https://accounts.google.com" --subject "user@example.com"

  # CI: Use pinned trust root for reproducible verification
  epack verify evidence.epack --trust-root trusted_root.json --issuer "https://token.actions.githubusercontent.com"

  # Verify only digest integrity (skip attestations)
  epack verify --integrity-only evidence.epack

  # Require at least one attestation
  epack verify --require-attestation evidence.epack --issuer "https://accounts.google.com"

  # Offline verification (skip transparency log)
  epack verify --offline evidence.epack --subject "ci@example.com"

  # INSECURE: Accept any valid signer (not recommended for production)
  epack verify evidence.epack --insecure-skip-identity-check`,
	Args: cobra.ExactArgs(1),
	RunE: runVerify,
}

func runVerify(cmd *cobra.Command, args []string) error {
	packPath := args[0]
	out := outputWriter()
	ctx := cmdContext(cmd)

	// Open the pack
	p, err := pack.Open(packPath)
	if err != nil {
		return exitErrorWithCode(ExitMalformedPack, "failed to open pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	// Build options from flags
	opts := verify.PackOpts{
		Issuer:                     verifyIssuer,
		IssuerRegexp:               verifyIssuerRegexp,
		Subject:                    verifySubject,
		SubjectRegexp:              verifySubjectRegexp,
		TrustRootPath:              verifyTrustRoot,
		Offline:                    verifyOffline,
		IntegrityOnly:              verifyIntegrityOnly,
		RequireAttestation:         verifyRequireAttestation,
		InsecureSkipIdentityCheck:  verifyInsecureSkipIdentityCheck,
		InsecureSkipEmbeddedVerify: verifyInsecureSkipEmbeddedVerify,
	}

	// Run verification with progress spinner.
	// Use context-aware spinner to prevent goroutine leak on cancellation.
	spinner := out.StartSpinnerWithContext(ctx, "Verifying pack...")
	defer spinner.Stop()
	result, err := verify.Pack(ctx, p, opts)
	if err != nil {
		return err
	}

	// Output results
	if out.IsJSON() {
		jsonResult := map[string]interface{}{
			"verified":           result.Verified,
			"stream":             result.Stream,
			"pack_digest":        result.PackDigest,
			"artifact_count":     result.ArtifactCount,
			"attestation_count":  result.AttestationCount,
			"artifact_errors":    result.ArtifactErrors,
			"pack_digest_error":  result.PackDigestError,
			"attestation_errors": result.AttestationErrors,
			"embedded_errors":    result.EmbeddedErrors,
		}
		if err := out.JSON(jsonResult); err != nil {
			return err
		}
		// SECURITY: Return error AFTER JSON output to ensure non-zero exit code on failure.
		if result.HasErrors() {
			return &errors.Error{
				Code:    errors.DigestMismatch,
				Exit:    ExitFailure,
				Message: "verification failed",
			}
		}
		return nil
	}

	// Human-readable output
	return printVerifyResults(out, packPath, result)
}

func printVerifyResults(out *output.Writer, packPath string, result *verify.PackResult) error {
	palette := out.Palette()

	if result.HasErrors() {
		out.PrintAlways("%s %s\n\n", palette.Failure("Verification failed:"), packPath)

		if len(result.ArtifactErrors) > 0 {
			out.PrintAlways("Artifact errors:\n")
			for _, e := range result.ArtifactErrors {
				out.PrintAlways("  %s %s\n", palette.Red("✗"), e)
			}
			out.PrintAlways("\n")
		}

		if result.PackDigestError != "" {
			out.PrintAlways("Pack digest error:\n")
			out.PrintAlways("  %s %s\n\n", palette.Red("✗"), result.PackDigestError)
		}

		if len(result.AttestationErrors) > 0 {
			out.PrintAlways("Attestation errors:\n")
			for _, e := range result.AttestationErrors {
				out.PrintAlways("  %s %s\n", palette.Red("✗"), e)
			}
			out.PrintAlways("\n")
		}

		if len(result.EmbeddedErrors) > 0 {
			out.PrintAlways("Embedded attestation errors:\n")
			for _, e := range result.EmbeddedErrors {
				out.PrintAlways("  %s %s\n", palette.Red("✗"), e)
			}
			out.PrintAlways("\n")
		}

		// Print hint
		if len(result.ArtifactErrors) > 0 || result.PackDigestError != "" {
			out.PrintAlways("Hint: The pack may have been modified after creation.\n")
			out.PrintAlways("      Rebuild the pack with the current artifacts.\n")
		}

		return fmt.Errorf("verification failed")
	}

	// Success
	out.Print("%s %s\n", palette.Success("Verification passed:"), packPath)
	out.Println()
	out.KeyValue("Stream", result.Stream)
	out.KeyValue("Pack Digest", output.FormatDigest(result.PackDigest))
	out.KeyValue("Artifacts", fmt.Sprintf("%d verified", result.ArtifactCount))

	if verifyIntegrityOnly {
		out.KeyValue("Attestations", palette.Dim("skipped (--integrity-only)"))
	} else if result.AttestationCount == 0 {
		out.KeyValue("Attestations", palette.Dim("none"))
	} else {
		out.KeyValue("Attestations", fmt.Sprintf("%d verified", result.AttestationCount))
	}

	out.Println()
	return nil
}
