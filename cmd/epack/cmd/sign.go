package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/securityaudit"
	"github.com/locktivity/epack/internal/securitypolicy"
	"github.com/locktivity/epack/sign"
	"github.com/spf13/cobra"
)

var (
	signOIDCToken                    string
	signKey                          string
	signYes                          bool
	signDryRun                       bool
	signNoTlog                       bool
	signTSAURLs                      []string
	signInsecureAllowCustomEndpoints bool
)

func init() {
	rootCmd.AddCommand(signCmd)

	signCmd.Flags().StringVar(&signOIDCToken, "oidc-token", "", "OIDC token (or EPACK_OIDC_TOKEN env)")
	signCmd.Flags().StringVar(&signKey, "key", "", "path to private key (PEM)")
	signCmd.Flags().BoolVarP(&signYes, "yes", "y", false, "skip confirmation")
	signCmd.Flags().BoolVar(&signDryRun, "dry-run", false, "show what would be signed")
	signCmd.Flags().BoolVar(&signNoTlog, "no-tlog", false, "skip transparency log (Rekor); signature not publicly recorded")
	signCmd.Flags().StringSliceVar(&signTSAURLs, "tsa", nil, "timestamp authority URL(s) for RFC3161 timestamps (requires --insecure-allow-custom-endpoints)")
	signCmd.Flags().BoolVar(&signInsecureAllowCustomEndpoints, "insecure-allow-custom-endpoints", false,
		"allow custom Sigstore endpoints (TSA, Fulcio, Rekor) - use with caution")
}

var signCmd = &cobra.Command{
	Use:        "sign <pack>",
	Short:      "Sign a pack with Sigstore",
	SuggestFor: []string{"attest"}, // "sgin" and "sing" are handled by Cobra's edit distance
	Long: `Sign an evidence pack with Sigstore using keyless or key-based signing.

By default, keyless signing opens a browser for OIDC authentication.
In CI/CD environments, use --oidc-token or EPACK_OIDC_TOKEN.

The attestation is written to attestations/{sha256(identity)}.sigstore.json
inside the pack.

Exit codes:
  0  Pack signed successfully
  1  Signing failed (authentication error, pack not found, etc.)
  2  Pack malformed/cannot open

Examples:
  # Keyless signing (opens browser)
  epack sign evidence.epack

  # Skip confirmation prompt
  epack sign evidence.epack --yes

  # CI/CD with environment token
  EPACK_OIDC_TOKEN=$TOKEN epack sign evidence.epack

  # GitHub Actions (ambient credentials)
  epack sign evidence.epack

  # Key-based signing
  epack sign evidence.epack --key ./private-key.pem

  # Skip public transparency log (private signing)
  epack sign evidence.epack --key ./key.pem --no-tlog

  # Skip tlog but use a timestamp authority (requires explicit opt-in)
  epack sign evidence.epack --key ./key.pem --no-tlog --tsa https://tsa.example.com --insecure-allow-custom-endpoints

  # Dry run (show what would be signed)
  epack sign --dry-run evidence.epack`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return exitError(`missing pack file argument

Usage: epack sign <pack>

Examples:
  epack sign evidence.epack                    # Interactive OIDC signing
  epack sign evidence.epack --key ./key.pem    # Sign with private key
  epack sign evidence.epack --dry-run          # Preview what would be signed`)
		}
		if len(args) > 1 {
			return exitError("too many arguments: expected 1, got %d", len(args))
		}
		return nil
	},
	RunE: runSign,
}

func runSign(cmd *cobra.Command, args []string) error {
	if err := validateSignFlags(); err != nil {
		return err
	}

	packPath := args[0]
	out := outputWriter()
	ctx := cmdContext(cmd)

	// Check pack exists
	if _, err := os.Stat(packPath); os.IsNotExist(err) {
		return exitError("pack not found: %s", packPath)
	}

	opts := signOptionsFromFlags()

	if err := opts.Validate(); err != nil {
		return exitError("%v", err)
	}

	logSignMode(out, opts)

	if signDryRun {
		return printSignDryRun(out, packPath, opts)
	}

	confirmSignIfNeeded(out, packPath, opts)

	signer, err := createSignerWithSpinner(ctx, out, opts)
	if err != nil {
		return err
	}

	// Sign the pack
	signSpinner := out.StartSpinner("Signing pack...")
	if err := sign.SignPackFile(ctx, packPath, signer); err != nil {
		signSpinner.Fail("Signing failed")
		return exitError("failed to sign pack: %v", err)
	}
	signSpinner.Success("Pack signed")

	return printSignResult(out, packPath)
}

func signOptionsFromFlags() sign.SignPackOptions {
	return sign.SignPackOptions{
		KeyPath:                      signKey,
		OIDCToken:                    signOIDCToken,
		Interactive:                  signOIDCToken == "" && os.Getenv("EPACK_OIDC_TOKEN") == "",
		SkipTlog:                     signNoTlog,
		TSAURLs:                      signTSAURLs,
		InsecureAllowCustomEndpoints: signInsecureAllowCustomEndpoints,
	}
}

func logSignMode(out *output.Writer, opts sign.SignPackOptions) {
	if opts.KeyPath != "" {
		out.Verbose("Using key-based signing from %s\n", opts.KeyPath)
	} else if opts.OIDCToken != "" || os.Getenv("EPACK_OIDC_TOKEN") != "" {
		out.Verbose("Using OIDC token from environment\n")
	} else {
		out.Verbose("Using browser-based OIDC authentication\n")
	}
	if opts.SkipTlog {
		out.Verbose("Skipping transparency log (signature will not be publicly recorded)\n")
		if len(opts.TSAURLs) > 0 {
			out.Verbose("Using timestamp authority: %v\n", opts.TSAURLs)
		}
	}
}

func printSignDryRun(out *output.Writer, packPath string, opts sign.SignPackOptions) error {
	out.Print("Would sign: %s\n", packPath)
	if opts.KeyPath != "" {
		out.Print("  Method: key-based (%s)\n", opts.KeyPath)
		return nil
	}
	out.Print("  Method: keyless (OIDC)\n")
	return nil
}

func confirmSignIfNeeded(out *output.Writer, packPath string, opts sign.SignPackOptions) {
	if signYes || out.IsQuiet() {
		return
	}
	out.Print("Sign %s?\n", packPath)
	if opts.KeyPath == "" && opts.OIDCToken == "" && os.Getenv("EPACK_OIDC_TOKEN") == "" {
		out.Print("  This will open your browser for authentication.\n")
	}
	out.Print("\nPress Enter to continue or Ctrl+C to cancel...")
	_, _ = fmt.Scanln()
}

func createSignerWithSpinner(ctx context.Context, out *output.Writer, opts sign.SignPackOptions) (sign.Signer, error) {
	var signerSpinner *output.Spinner
	if opts.KeyPath != "" {
		signerSpinner = out.StartSpinner("Preparing signer...")
	} else if opts.Interactive {
		signerSpinner = out.StartSpinner("Authenticating with Sigstore...")
	} else {
		signerSpinner = out.StartSpinner("Authenticating...")
	}

	signer, err := sign.NewSignerFromOptions(ctx, opts)
	if err != nil {
		signerSpinner.Fail("Authentication failed")
		return nil, exitError("failed to create signer: %v", err)
	}
	signerSpinner.Success("Authenticated")
	return signer, nil
}

func printSignResult(out *output.Writer, packPath string) error {
	if out.IsJSON() {
		return out.JSON(map[string]interface{}{
			"signed": true,
			"path":   packPath,
		})
	}
	out.Success("Signed %s", packPath)
	out.Print("  Use 'epack verify %s' to verify the signature\n", packPath)
	return nil
}

func validateSignFlags() error {
	if err := securitypolicy.EnforceStrictProduction("sign_cli", signInsecureAllowCustomEndpoints); err != nil {
		return err
	}
	if signInsecureAllowCustomEndpoints {
		securityaudit.Emit(securityaudit.Event{
			Type:        securityaudit.EventInsecureBypass,
			Component:   "sign",
			Name:        "sign",
			Description: "sign command running with insecure custom endpoint override",
			Attrs: map[string]string{
				"insecure_allow_custom_endpoints": "true",
			},
		})
	}
	return nil
}
