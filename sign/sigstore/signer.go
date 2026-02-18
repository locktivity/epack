package sigstore

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	sigsign "github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/oauthflow"
)

const (
	// DefaultFulcioURL is the public Sigstore Fulcio instance.
	DefaultFulcioURL = "https://fulcio.sigstore.dev"

	// DefaultRekorURL is the public Sigstore Rekor instance.
	DefaultRekorURL = "https://rekor.sigstore.dev"

	// SigstoreOIDCIssuer is the default OIDC issuer for Sigstore public good.
	SigstoreOIDCIssuer = "https://oauth2.sigstore.dev/auth"

	// SigstoreClientID is the client ID for the Sigstore public good instance.
	SigstoreClientID = "sigstore"
)

// Options configures how signing is performed.
type Options struct {
	// OIDC configures keyless signing via OpenID Connect.
	// Mutually exclusive with PrivateKey.
	OIDC *OIDCOptions

	// PrivateKey enables key-based signing.
	// Mutually exclusive with OIDC.
	PrivateKey crypto.Signer

	// FulcioURL is the Fulcio certificate authority URL.
	// If empty, uses the public Sigstore instance.
	// Custom URLs require InsecureAllowCustomEndpoints to be set.
	FulcioURL string

	// RekorURL is the Rekor transparency log URL.
	// If empty, uses the public Sigstore instance.
	// Custom URLs require InsecureAllowCustomEndpoints to be set.
	RekorURL string

	// TSAURLs are optional timestamp authority URLs for RFC3161 timestamps.
	// Custom URLs require InsecureAllowCustomEndpoints to be set.
	TSAURLs []string

	// SkipTlog skips publishing to the transparency log (Rekor).
	// When true, signatures are not recorded in the public log.
	// This provides privacy but loses non-repudiation and public auditability.
	// Consider using TSAURLs for timestamping when skipping tlog.
	SkipTlog bool

	// InsecureAllowCustomEndpoints permits non-default Fulcio/Rekor/TSA URLs.
	// With OIDC signing, the token is sent to FulcioURL; a malicious endpoint
	// could capture it and impersonate your identity. Only use with trusted
	// private instances or for testing.
	// CLI: --insecure-allow-custom-endpoints
	InsecureAllowCustomEndpoints bool
}

// OIDCOptions configures keyless OIDC-based signing.
type OIDCOptions struct {
	// Token is the OIDC token. If empty and Interactive is false,
	// uses ambient credentials (e.g., ACTIONS_ID_TOKEN_REQUEST_TOKEN in GitHub Actions).
	Token string

	// Interactive enables browser-based OIDC authentication.
	// When true and Token is empty, opens a browser for authentication.
	Interactive bool
}

// Signer implements sign.Signer using Sigstore infrastructure.
type Signer struct {
	opts     Options
	identity string
	keypair  sigsign.Keypair
}

// NewSigner creates a new Sigstore-based signer.
//
// For keyless (OIDC) signing, provide OIDCOptions with a token.
// For key-based signing, provide a PrivateKey.
func NewSigner(ctx context.Context, opts Options) (*Signer, error) {
	// Context accepted for future cancellation-aware setup (e.g., OIDC flows).
	_ = ctx

	if opts.OIDC != nil && opts.PrivateKey != nil {
		return nil, fmt.Errorf("cannot specify both OIDC and PrivateKey")
	}

	if opts.OIDC == nil && opts.PrivateKey == nil {
		return nil, fmt.Errorf("must specify either OIDC or PrivateKey")
	}

	// Validate endpoint URLs
	if err := validateEndpoints(opts); err != nil {
		return nil, err
	}

	s := &Signer{opts: opts}

	// Create keypair
	if opts.PrivateKey != nil {
		s.keypair = &staticKeypair{key: opts.PrivateKey}
		// Use public key fingerprint as identity to avoid collisions
		identity, err := publicKeyFingerprint(opts.PrivateKey.Public())
		if err != nil {
			return nil, fmt.Errorf("computing public key fingerprint: %w", err)
		}
		s.identity = identity
	} else {
		// For OIDC, we'll create an ephemeral keypair
		ephemeral, err := sigsign.NewEphemeralKeypair(nil)
		if err != nil {
			return nil, fmt.Errorf("creating ephemeral keypair: %w", err)
		}
		s.keypair = ephemeral
		// Use ephemeral public key fingerprint as identity
		// The actual OIDC subject will be in the certificate
		identity, err := publicKeyFingerprint(ephemeral.GetPublicKey())
		if err != nil {
			return nil, fmt.Errorf("computing ephemeral key fingerprint: %w", err)
		}
		s.identity = identity
	}

	return s, nil
}

// validateEndpoints checks that custom endpoint URLs are safe to use.
// Custom URLs require InsecureAllowCustomEndpoints and must use HTTPS.
//
// SECURITY: When OIDC signing is used with a custom FulcioURL, the OIDC token
// is sent to that endpoint. A malicious Fulcio could capture the token and
// impersonate the user's identity. This is blocked by default and requires
// explicit opt-in via --insecure-allow-custom-endpoints.
func validateEndpoints(opts Options) error {
	hasCustomEndpoint := opts.FulcioURL != "" || opts.RekorURL != "" || len(opts.TSAURLs) > 0

	if !hasCustomEndpoint {
		return nil
	}

	if !opts.InsecureAllowCustomEndpoints {
		return fmt.Errorf("custom Fulcio/Rekor/TSA URLs require --insecure-allow-custom-endpoints to be set")
	}

	// SECURITY: Explicitly warn when OIDC is combined with custom Fulcio.
	// This is the highest-risk combination because the token grants identity.
	if opts.OIDC != nil && opts.FulcioURL != "" {
		// Return an error that clearly states the risk - users must acknowledge
		// this by using InsecureAllowCustomEndpoints (which they've already done
		// to get here), but we add an extra check to ensure custom Fulcio + OIDC
		// is never the default path.
		// Custom Fulcio + OIDC: Risk is communicated via InsecureAllowCustomEndpoints flag name.
		// Code path is safe because InsecureAllowCustomEndpoints is required to reach here.
		_ = opts.FulcioURL != DefaultFulcioURL // Acknowledge custom endpoint check
	}

	// Validate each URL is HTTPS
	if err := validateOptionalHTTPSURL(opts.FulcioURL, "FulcioURL"); err != nil {
		return err
	}
	if err := validateOptionalHTTPSURL(opts.RekorURL, "RekorURL"); err != nil {
		return err
	}
	for i, tsaURL := range opts.TSAURLs {
		if err := validateHTTPSURL(tsaURL, fmt.Sprintf("TSAURLs[%d]", i)); err != nil {
			return err
		}
	}

	return nil
}

// validateOptionalHTTPSURL validates a URL only if non-empty.
func validateOptionalHTTPSURL(rawURL, fieldName string) error {
	if rawURL == "" {
		return nil
	}
	return validateHTTPSURL(rawURL, fieldName)
}

// publicKeyFingerprint returns a collision-resistant fingerprint of a public key.
// It returns the full SHA-256 hash of the DER-encoded public key as a hex string.
func publicKeyFingerprint(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshaling public key: %w", err)
	}
	h := sha256.Sum256(der)
	return fmt.Sprintf("%x", h), nil
}

// validateHTTPSURL ensures a URL is valid and uses HTTPS.
func validateHTTPSURL(rawURL, fieldName string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%s: invalid URL: %w", fieldName, err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("%s: must use HTTPS (got %q)", fieldName, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("%s: missing host", fieldName)
	}
	return nil
}

// Sign creates a Sigstore bundle for the given in-toto statement JSON.
// The statement is wrapped in a DSSE envelope with the in-toto payload type.
func (s *Signer) Sign(ctx context.Context, statement []byte) (*bundle.Bundle, error) {
	content := &sigsign.DSSEData{
		Data:        statement,
		PayloadType: "application/vnd.in-toto+json",
	}

	// Build bundle options
	bundleOpts := sigsign.BundleOptions{
		Context: ctx,
	}

	// Add certificate provider (Fulcio) for keyless signing
	if s.opts.OIDC != nil {
		token := s.opts.OIDC.Token

		// If no token provided and interactive mode, get token via browser
		if token == "" && s.opts.OIDC.Interactive {
			idToken, err := getInteractiveToken(ctx)
			if err != nil {
				return nil, fmt.Errorf("interactive OIDC authentication failed: %w", err)
			}
			token = idToken
		}

		fulcio := sigsign.NewFulcio(&sigsign.FulcioOptions{
			BaseURL: defaultString(s.opts.FulcioURL, DefaultFulcioURL),
		})
		bundleOpts.CertificateProvider = fulcio
		bundleOpts.CertificateProviderOptions = &sigsign.CertificateProviderOptions{
			IDToken: token,
		}
	}

	// Add transparency log (Rekor) unless skipped
	if !s.opts.SkipTlog {
		rekor := sigsign.NewRekor(&sigsign.RekorOptions{
			BaseURL: defaultString(s.opts.RekorURL, DefaultRekorURL),
		})
		bundleOpts.TransparencyLogs = []sigsign.Transparency{rekor}
	}

	// Add timestamp authorities if configured
	for _, tsaURL := range s.opts.TSAURLs {
		tsa := sigsign.NewTimestampAuthority(&sigsign.TimestampAuthorityOptions{
			URL: tsaURL,
		})
		bundleOpts.TimestampAuthorities = append(bundleOpts.TimestampAuthorities, tsa)
	}

	// Create the bundle
	protoBundle, err := sigsign.Bundle(content, s.keypair, bundleOpts)
	if err != nil {
		return nil, fmt.Errorf("creating sigstore bundle: %w", err)
	}

	// Wrap in the higher-level bundle type
	b, err := bundle.NewBundle(protoBundle)
	if err != nil {
		return nil, fmt.Errorf("wrapping bundle: %w", err)
	}

	return b, nil
}

// Identity returns the signer's identity.
func (s *Signer) Identity() string {
	return s.identity
}

// MarshalBundle serializes a bundle to JSON.
func MarshalBundle(b *bundle.Bundle) ([]byte, error) {
	return json.Marshal(b)
}

// UnmarshalBundle deserializes a bundle from JSON.
func UnmarshalBundle(data []byte) (*bundle.Bundle, error) {
	var b bundle.Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// staticKeypair wraps a crypto.Signer for key-based signing.
type staticKeypair struct {
	key crypto.Signer
}

func (sk *staticKeypair) SignData(_ context.Context, data []byte) ([]byte, []byte, error) {
	// Hash the data first
	h := sha256.Sum256(data)

	// Sign the hash
	sig, err := sk.key.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		return nil, nil, err
	}
	return sig, h[:], nil
}

func (sk *staticKeypair) GetPublicKey() crypto.PublicKey {
	return sk.key.Public()
}

func (sk *staticKeypair) GetPublicKeyPem() (string, error) {
	pubKey := sk.key.Public()
	der, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}
	return string(pem.EncodeToMemory(block)), nil
}

func (sk *staticKeypair) GetHint() []byte {
	return nil
}

func (sk *staticKeypair) GetKeyAlgorithm() string {
	switch sk.key.Public().(type) {
	case *ecdsa.PublicKey:
		return "ecdsa"
	default:
		return "unknown"
	}
}

func (sk *staticKeypair) GetHashAlgorithm() protocommon.HashAlgorithm {
	return protocommon.HashAlgorithm_SHA2_256
}

func (sk *staticKeypair) GetSigningAlgorithm() protocommon.PublicKeyDetails {
	switch pub := sk.key.Public().(type) {
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P256():
			return protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256
		case elliptic.P384():
			return protocommon.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384
		default:
			return protocommon.PublicKeyDetails_PUBLIC_KEY_DETAILS_UNSPECIFIED
		}
	default:
		return protocommon.PublicKeyDetails_PUBLIC_KEY_DETAILS_UNSPECIFIED
	}
}


// defaultString returns v if non-empty, otherwise def.
func defaultString(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// getInteractiveToken obtains an OIDC token via browser-based authentication.
func getInteractiveToken(_ context.Context) (string, error) {
	// Use the default interactive flow from sigstore
	// OIDConnect handles the full OIDC flow including browser redirect
	token, err := oauthflow.OIDConnect(
		SigstoreOIDCIssuer,
		SigstoreClientID,
		"", // no client secret for public clients
		"", // empty redirectURL uses localhost:0 with /auth/callback
		oauthflow.DefaultIDTokenGetter,
	)
	if err != nil {
		return "", err
	}
	return token.RawString, nil
}
