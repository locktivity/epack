package broker

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/locktivity/epack/internal/keyfile"
)

const (
	// GitLabIDTokenEnvVar carries the ID token a GitLab job declared for Locktivity.
	GitLabIDTokenEnvVar = "LOCKTIVITY_ID_TOKEN"
	// SigningKeyEnvVar is the path to the PEM private key a runner signs in with.
	SigningKeyEnvVar = "EPACK_SIGNING_KEY"
	// PipelineIDEnvVar names the pipeline a run belongs to.
	PipelineIDEnvVar = "EPACK_PIPELINE_ID"
	// keyAssertionIssuer is how the broker tells a key assertion from a token
	// a platform issued.
	keyAssertionIssuer   = "epack-key"
	keyAssertionLifetime = 120 * time.Second
)

// TokenSourceFor picks the identity a runtime can present, preferring the
// one the platform issued: GitHub Actions OIDC, then a GitLab ID token,
// then a signing key.
func TokenSourceFor(rt RuntimeContext, httpClient *http.Client, getenv func(string) string) OIDCTokenSource {
	switch {
	case rt.InGitHubActions && rt.OIDCAvailable:
		return GitHubActionsTokenSource{HTTPClient: httpClient, Getenv: getenv}
	case rt.GitLabIDToken:
		return GitLabCITokenSource{Getenv: getenv}
	case rt.SigningKey:
		return SigningKeyTokenSource{Getenv: getenv}
	default:
		return GitHubActionsTokenSource{HTTPClient: httpClient, Getenv: getenv}
	}
}

// NewClientForRuntime returns a broker client presenting the identity the
// runtime has.
func NewClientForRuntime(apiBase string, rt RuntimeContext, getenv func(string) string) *Client {
	client := NewClient(apiBase)
	client.TokenSource = TokenSourceFor(rt, client.HTTPClient, getenvOr(getenv))
	return client
}

// GitLabCITokenSource presents the ID token a GitLab job declared under
// id_tokens for Locktivity. The job fixed the audience, so the one requested
// here is not consulted.
type GitLabCITokenSource struct {
	Getenv func(string) string
}

// Token returns the job's ID token.
func (s GitLabCITokenSource) Token(context.Context, string) (string, error) {
	token := strings.TrimSpace(getenvOr(s.Getenv)(GitLabIDTokenEnvVar))
	if token == "" {
		return "", ErrOIDCUnavailable
	}
	return token, nil
}

// SigningKeyTokenSource signs in with a runner's signing key: it presents a
// short-lived JWS that names the pipeline and is signed by a key the pipeline
// approved.
type SigningKeyTokenSource struct {
	Getenv func(string) string
	// Now and Rand replace the clock and crypto/rand when set.
	Now  func() time.Time
	Rand io.Reader
}

// Token signs an assertion for audience with the key in EPACK_SIGNING_KEY,
// naming the pipeline in EPACK_PIPELINE_ID.
func (s SigningKeyTokenSource) Token(_ context.Context, audience string) (string, error) {
	getenv := getenvOr(s.Getenv)
	keyPath := strings.TrimSpace(getenv(SigningKeyEnvVar))
	if keyPath == "" {
		return "", ErrOIDCUnavailable
	}
	pipelineID := strings.TrimSpace(getenv(PipelineIDEnvVar))
	if pipelineID == "" {
		return "", fmt.Errorf("signing in with the key in %s needs %s set to the pipeline's ID", SigningKeyEnvVar, PipelineIDEnvVar)
	}
	token, err := s.assertion(keyPath, pipelineID, audience)
	if err != nil {
		return "", fmt.Errorf("signing in with the key in %s: %w", SigningKeyEnvVar, err)
	}
	return token, nil
}

func (s SigningKeyTokenSource) assertion(keyPath, pipelineID, audience string) (string, error) {
	key, err := keyfile.LoadPrivateKey(keyPath)
	if err != nil {
		return "", err
	}
	signer, err := newKeyAssertionSigner(key)
	if err != nil {
		return "", err
	}
	id, err := s.tokenID()
	if err != nil {
		return "", err
	}
	issuedAt := s.now()
	return jwt.Signed(signer).Claims(jwt.Claims{
		Issuer:   keyAssertionIssuer,
		Subject:  pipelineID,
		Audience: jwt.Audience{audience},
		IssuedAt: jwt.NewNumericDate(issuedAt),
		Expiry:   jwt.NewNumericDate(issuedAt.Add(keyAssertionLifetime)),
		ID:       id,
	}).Serialize()
}

// newKeyAssertionSigner names the key by its fingerprint, which is how the
// broker finds the key among those the pipeline approved.
func newKeyAssertionSigner(key crypto.Signer) (jose.Signer, error) {
	alg, err := keyAssertionAlgorithm(key.Public())
	if err != nil {
		return nil, err
	}
	fingerprint, err := keyfile.Fingerprint(key.Public())
	if err != nil {
		return nil, err
	}
	return jose.NewSigner(
		jose.SigningKey{Algorithm: alg, Key: jose.JSONWebKey{Key: key, KeyID: fingerprint}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
}

func keyAssertionAlgorithm(pub crypto.PublicKey) (jose.SignatureAlgorithm, error) {
	switch pub := pub.(type) {
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P256():
			return jose.ES256, nil
		case elliptic.P384():
			return jose.ES384, nil
		case elliptic.P521():
			return jose.ES512, nil
		}
		return "", fmt.Errorf("unsupported ECDSA curve %s", pub.Curve.Params().Name)
	case *rsa.PublicKey:
		return jose.RS256, nil
	}
	return "", fmt.Errorf("unsupported key type %T", pub)
}

func (s SigningKeyTokenSource) tokenID() (string, error) {
	source := s.Rand
	if source == nil {
		source = rand.Reader
	}
	id := make([]byte, 16)
	if _, err := io.ReadFull(source, id); err != nil {
		return "", fmt.Errorf("generating the token ID: %w", err)
	}
	return hex.EncodeToString(id), nil
}

func (s SigningKeyTokenSource) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func getenvOr(getenv func(string) string) func(string) string {
	if getenv != nil {
		return getenv
	}
	return os.Getenv
}
