package sign

import (
	"context"
	"fmt"
	"os"

	"github.com/locktivity/epack/sign/sigstore"
)

// SignPackOptions configures high-level pack signing.
// Simplified interface over sigstore.Options that handles key loading
// and OIDC token resolution.
type SignPackOptions struct {
	// KeyPath is the path to a PEM-encoded private key.
	// Mutually exclusive with OIDCToken/Interactive.
	KeyPath string

	// OIDCToken is the OIDC token for keyless signing.
	// If empty and Interactive is false, ambient credentials are used
	// (e.g., ACTIONS_ID_TOKEN_REQUEST_TOKEN in GitHub Actions).
	OIDCToken string

	// Interactive enables browser-based OIDC authentication.
	// When true and OIDCToken is empty, opens a browser for authentication.
	Interactive bool

	// SkipTlog skips the transparency log (Rekor).
	// When true, signatures are not recorded in the public log.
	SkipTlog bool

	// TSAURLs are optional timestamp authority URLs for RFC3161 timestamps.
	// Requires InsecureAllowCustomEndpoints to be set.
	TSAURLs []string

	// InsecureAllowCustomEndpoints permits non-default TSA/Fulcio/Rekor URLs.
	// Use with caution - custom endpoints could capture OIDC tokens.
	// CLI: --insecure-allow-custom-endpoints
	InsecureAllowCustomEndpoints bool
}

// Method returns "key" or "oidc" based on the configuration.
func (o *SignPackOptions) Method() string {
	if o.KeyPath != "" {
		return "key"
	}
	return "oidc"
}

// Validate checks that SignPackOptions are valid.
func (o *SignPackOptions) Validate() error {
	if len(o.TSAURLs) > 0 && !o.InsecureAllowCustomEndpoints {
		return fmt.Errorf("--tsa requires --insecure-allow-custom-endpoints flag for security")
	}
	return nil
}

// NewKeylessSigner creates a Signer using OIDC/keyless authentication.
// This is the recommended constructor for keyless signing - it opens a browser
// for interactive authentication and records the signature in the transparency log.
//
// For CI/CD environments, use NewSignerFromOptions with an OIDCToken instead.
//
// Example:
//
//	signer, err := sign.NewKeylessSigner(ctx)
//	if err != nil {
//	    return err
//	}
//	if err := sign.SignPackFile(ctx, "evidence.epack", signer); err != nil {
//	    return err
//	}
func NewKeylessSigner(ctx context.Context) (Signer, error) {
	return NewSignerFromOptions(ctx, SignPackOptions{
		Interactive: true,
	})
}

// NewKeySignerFromPath creates a Signer using a PEM-encoded private key.
// This is the recommended constructor for key-based signing.
//
// The signature is recorded in the transparency log by default.
// For private signing (no tlog), use NewSignerFromOptions with SkipTlog.
//
// Example:
//
//	signer, err := sign.NewKeySignerFromPath(ctx, "private-key.pem")
//	if err != nil {
//	    return err
//	}
//	if err := sign.SignPackFile(ctx, "evidence.epack", signer); err != nil {
//	    return err
//	}
func NewKeySignerFromPath(ctx context.Context, keyPath string) (Signer, error) {
	if keyPath == "" {
		return nil, fmt.Errorf("keyPath is required")
	}
	return NewSignerFromOptions(ctx, SignPackOptions{
		KeyPath: keyPath,
	})
}

// NewSignerFromOptions creates a Signer from high-level options.
// This handles key loading and OIDC configuration, returning a
// ready-to-use Signer.
//
// For simple use cases, prefer NewKeylessSigner or NewKeySignerFromPath.
func NewSignerFromOptions(ctx context.Context, opts SignPackOptions) (Signer, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	var sigOpts sigstore.Options

	if opts.KeyPath != "" {
		// Key-based signing
		key, err := LoadPrivateKey(opts.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("loading private key: %w", err)
		}
		sigOpts.PrivateKey = key
	} else {
		// OIDC/keyless signing
		token := opts.OIDCToken
		if token == "" {
			token = os.Getenv("EPACK_OIDC_TOKEN")
		}
		sigOpts.OIDC = &sigstore.OIDCOptions{
			Token:       token,
			Interactive: opts.Interactive,
		}
	}

	sigOpts.SkipTlog = opts.SkipTlog

	if len(opts.TSAURLs) > 0 {
		sigOpts.TSAURLs = opts.TSAURLs
		sigOpts.InsecureAllowCustomEndpoints = true
	}

	return sigstore.NewSigner(ctx, sigOpts)
}
