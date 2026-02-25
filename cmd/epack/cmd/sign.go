package cmd

import (
	"fmt"
	"os"

	"github.com/locktivity/epack/internal/cli/output"
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
	SuggestFor: []string{"sgin", "sing", "attest"},
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
  epack sign evidence.pack

  # Skip confirmation prompt
  epack sign evidence.pack --yes

  # CI/CD with environment token
  EPACK_OIDC_TOKEN=$TOKEN epack sign evidence.pack

  # GitHub Actions (ambient credentials)
  epack sign evidence.pack

  # Key-based signing
  epack sign evidence.pack --key ./private-key.pem

  # Skip public transparency log (private signing)
  epack sign evidence.pack --key ./key.pem --no-tlog

  # Skip tlog but use a timestamp authority (requires explicit opt-in)
  epack sign evidence.pack --key ./key.pem --no-tlog --tsa https://tsa.example.com --insecure-allow-custom-endpoints

  # Dry run (show what would be signed)
  epack sign --dry-run evidence.pack`,
	Args: cobra.ExactArgs(1),
	RunE: runSign,
}

func runSign(cmd *cobra.Command, args []string) error {
	packPath := args[0]
	out := outputWriter()
	ctx := cmdContext(cmd)

	// Check pack exists
	if _, err := os.Stat(packPath); os.IsNotExist(err) {
		return exitError("pack not found: %s", packPath)
	}

	// Build options from flags
	opts := sign.SignPackOptions{
		KeyPath:                      signKey,
		OIDCToken:                    signOIDCToken,
		Interactive:                  signOIDCToken == "" && os.Getenv("EPACK_OIDC_TOKEN") == "",
		SkipTlog:                     signNoTlog,
		TSAURLs:                      signTSAURLs,
		InsecureAllowCustomEndpoints: signInsecureAllowCustomEndpoints,
	}

	// Validate options
	if err := opts.Validate(); err != nil {
		return exitError("%v", err)
	}

	// Verbose logging
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

	// Dry run - just show what would happen
	if signDryRun {
		out.Print("Would sign: %s\n", packPath)
		if opts.KeyPath != "" {
			out.Print("  Method: key-based (%s)\n", opts.KeyPath)
		} else {
			out.Print("  Method: keyless (OIDC)\n")
		}
		return nil
	}

	// Confirm unless --yes
	if !signYes && !out.IsQuiet() {
		out.Print("Sign %s?\n", packPath)
		if opts.KeyPath == "" && opts.OIDCToken == "" && os.Getenv("EPACK_OIDC_TOKEN") == "" {
			out.Print("  This will open your browser for authentication.\n")
		}
		out.Print("\nPress Enter to continue or Ctrl+C to cancel...")
		_, _ = fmt.Scanln()
	}

	// Create signer
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
		return exitError("failed to create signer: %v", err)
	}
	signerSpinner.Success("Authenticated")

	// Sign the pack
	signSpinner := out.StartSpinner("Signing pack...")
	if err := sign.SignPackFile(ctx, packPath, signer); err != nil {
		signSpinner.Fail("Signing failed")
		return exitError("failed to sign pack: %v", err)
	}
	signSpinner.Success("Pack signed")

	// Output result
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
