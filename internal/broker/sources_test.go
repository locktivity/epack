package broker

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestGitLabCITokenSource(t *testing.T) {
	t.Parallel()

	source := GitLabCITokenSource{Getenv: envOf(map[string]string{GitLabIDTokenEnvVar: " jwt-from-gitlab "})}
	token, err := source.Token(context.Background(), "https://api.locktivity.com")
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	if token != "jwt-from-gitlab" {
		t.Fatalf("Token() = %q", token)
	}

	_, err = GitLabCITokenSource{Getenv: envOf(nil)}.Token(context.Background(), "aud")
	if !errors.Is(err, ErrOIDCUnavailable) {
		t.Fatalf("Token() without the variable = %v, want ErrOIDCUnavailable", err)
	}
}

func TestSigningKeyTokenSource(t *testing.T) {
	t.Parallel()

	cases := []struct {
		alg     string
		newKey  func() (crypto.Signer, error)
		hash    crypto.Hash
		sigSize int
	}{
		{"ES256", ecdsaKey(elliptic.P256()), crypto.SHA256, 64},
		{"ES384", ecdsaKey(elliptic.P384()), crypto.SHA384, 96},
		{"ES512", ecdsaKey(elliptic.P521()), crypto.SHA512, 132},
		{"RS256", func() (crypto.Signer, error) { return rsa.GenerateKey(rand.Reader, 2048) }, crypto.SHA256, 256},
	}
	for _, tc := range cases {
		t.Run(tc.alg, func(t *testing.T) {
			t.Parallel()

			key, err := tc.newKey()
			if err != nil {
				t.Fatal(err)
			}
			issuedAt := time.Unix(1_791_000_000, 0)
			source := SigningKeyTokenSource{
				Getenv: envOf(map[string]string{SigningKeyEnvVar: writeSigningKey(t, key), PipelineIDEnvVar: " pipe_1 "}),
				Now:    func() time.Time { return issuedAt },
				Rand:   bytes.NewReader(bytes.Repeat([]byte{0xab}, 16)),
			}

			token, err := source.Token(context.Background(), "https://api.locktivity.com")
			if err != nil {
				t.Fatalf("Token() error = %v", err)
			}
			header, claims, signingInput, signature := decodeKeyAssertion(t, token)

			der, err := x509.MarshalPKIXPublicKey(key.Public())
			if err != nil {
				t.Fatal(err)
			}
			fingerprint := sha256.Sum256(der)
			wantHeader := map[string]any{"alg": tc.alg, "typ": "JWT", "kid": hex.EncodeToString(fingerprint[:])}
			if !reflect.DeepEqual(header, wantHeader) {
				t.Errorf("header = %v, want %v", header, wantHeader)
			}
			wantClaims := map[string]any{
				"iss": "epack-key",
				"sub": "pipe_1",
				"aud": "https://api.locktivity.com",
				"iat": float64(issuedAt.Unix()),
				"exp": float64(issuedAt.Unix() + 120),
				"jti": strings.Repeat("ab", 16),
			}
			if !reflect.DeepEqual(claims, wantClaims) {
				t.Errorf("claims = %v, want %v", claims, wantClaims)
			}
			if len(signature) != tc.sigSize {
				t.Fatalf("signature is %d bytes, want %d", len(signature), tc.sigSize)
			}
			digest := tc.hash.New()
			digest.Write(signingInput)
			if !verifies(key.Public(), tc.hash, digest.Sum(nil), signature) {
				t.Fatal("signature does not verify with the public key")
			}
		})
	}
}

func TestSigningKeyTokenSourceWithoutAKeyIsUnavailable(t *testing.T) {
	t.Parallel()

	source := SigningKeyTokenSource{Getenv: envOf(map[string]string{PipelineIDEnvVar: "pipe_1"})}
	if _, err := source.Token(context.Background(), "aud"); !errors.Is(err, ErrOIDCUnavailable) {
		t.Fatalf("Token() = %v, want ErrOIDCUnavailable", err)
	}
}

func TestSigningKeyTokenSourceNeedsThePipeline(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	source := SigningKeyTokenSource{Getenv: envOf(map[string]string{SigningKeyEnvVar: writeSigningKey(t, key)})}
	_, err = source.Token(context.Background(), "aud")
	if err == nil || !strings.Contains(err.Error(), PipelineIDEnvVar) || errors.Is(err, ErrOIDCUnavailable) {
		t.Fatalf("Token() = %v, want an error naming %s", err, PipelineIDEnvVar)
	}
}

func TestSigningKeyTokenSourceRefusesKeysItCannotSignInWith(t *testing.T) {
	t.Parallel()

	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p224Key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	notAKey := filepath.Join(t.TempDir(), "notes.pem")
	if err := os.WriteFile(notAKey, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"ed25519 key":  writeSigningKey(t, ed25519Key),
		"P-224 key":    writeSigningKey(t, p224Key),
		"not a key":    notAKey,
		"missing file": filepath.Join(t.TempDir(), "missing.pem"),
	}
	for name, path := range cases {
		source := SigningKeyTokenSource{Getenv: envOf(map[string]string{SigningKeyEnvVar: path, PipelineIDEnvVar: "pipe_1"})}
		_, err := source.Token(context.Background(), "aud")
		if err == nil || !strings.Contains(err.Error(), SigningKeyEnvVar) || errors.Is(err, ErrOIDCUnavailable) {
			t.Errorf("%s: Token() = %v, want an error naming %s", name, err, SigningKeyEnvVar)
		}
	}
}

func TestTokenSourceFor(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		rt   RuntimeContext
		want string
	}{
		{"github actions", RuntimeContext{InGitHubActions: true, OIDCAvailable: true, SigningKey: true}, "GitHubActionsTokenSource"},
		{"gitlab id token", RuntimeContext{InGitLabCI: true, GitLabIDToken: true}, "GitLabCITokenSource"},
		{"gitlab id token beside a signing key", RuntimeContext{InGitLabCI: true, GitLabIDToken: true, SigningKey: true}, "GitLabCITokenSource"},
		{"signing key", RuntimeContext{SigningKey: true}, "SigningKeyTokenSource"},
		{"signing key in gitlab without an id token", RuntimeContext{InGitLabCI: true, SigningKey: true}, "SigningKeyTokenSource"},
		{"signing key in github actions without oidc", RuntimeContext{InGitHubActions: true, SigningKey: true}, "SigningKeyTokenSource"},
		{"nothing", RuntimeContext{}, "GitHubActionsTokenSource"},
	}
	for _, tc := range cases {
		source := TokenSourceFor(tc.rt, nil, envOf(nil))
		var got string
		switch source.(type) {
		case GitHubActionsTokenSource:
			got = "GitHubActionsTokenSource"
		case GitLabCITokenSource:
			got = "GitLabCITokenSource"
		case SigningKeyTokenSource:
			got = "SigningKeyTokenSource"
		}
		if got != tc.want {
			t.Errorf("%s: TokenSourceFor() = %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestClientResolveSignsInWithTheKeyForThePipeline(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rt := RuntimeContext{SigningKey: true}
	client := NewClientForRuntime("https://api.locktivity.test/", rt, envOf(map[string]string{
		SigningKeyEnvVar: writeSigningKey(t, key),
		PipelineIDEnvVar: "pipe_1",
	}))
	var path, authorization, requestBody string
	client.HTTPClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		path = r.URL.Path
		authorization = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		requestBody = string(body)
		return jsonResponse(`{"env":{"LOCKTIVITY_ACCESS_TOKEN":"ltk_test"},"expires_at":"2026-01-01T12:00:00Z"}`), nil
	})

	_, err = client.Resolve(context.Background(), ResolveRequest{
		CredentialSets: []string{"credset_abc123"},
		PipelineID:     "pipe_1",
	}, rt)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if path != "/oidc/v1/credential_sets/resolve" {
		t.Fatalf("path = %q", path)
	}
	if requestBody != `{"credential_sets":["credset_abc123"],"pipeline_id":"pipe_1"}` {
		t.Fatalf("request body = %s", requestBody)
	}
	token, ok := strings.CutPrefix(authorization, "Bearer ")
	if !ok {
		t.Fatalf("Authorization = %q", authorization)
	}
	_, claims, _, _ := decodeKeyAssertion(t, token)
	if claims["aud"] != "https://api.locktivity.test" || claims["sub"] != "pipe_1" {
		t.Fatalf("claims = %v", claims)
	}
	issuedAt, _ := claims["iat"].(float64)
	expires, _ := claims["exp"].(float64)
	if time.Since(time.Unix(int64(issuedAt), 0)).Abs() > time.Minute || expires-issuedAt != 120 {
		t.Fatalf("iat = %v, exp = %v", claims["iat"], claims["exp"])
	}
	jti, _ := claims["jti"].(string)
	if id, err := hex.DecodeString(jti); err != nil || len(id) < 16 || len(jti) > 64 {
		t.Fatalf("jti = %q", jti)
	}
}

func ecdsaKey(curve elliptic.Curve) func() (crypto.Signer, error) {
	return func() (crypto.Signer, error) { return ecdsa.GenerateKey(curve, rand.Reader) }
}

// writeSigningKey writes key the way a runner would hold it: an EC key as
// "EC PRIVATE KEY", anything else as PKCS#8.
func writeSigningKey(t *testing.T, key crypto.Signer) string {
	t.Helper()
	block := &pem.Block{Type: "PRIVATE KEY"}
	var err error
	if ec, ok := key.(*ecdsa.PrivateKey); ok {
		block.Type = "EC PRIVATE KEY"
		block.Bytes, err = x509.MarshalECPrivateKey(ec)
	} else {
		block.Bytes, err = x509.MarshalPKCS8PrivateKey(key)
	}
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "signing-key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func decodeKeyAssertion(t *testing.T, token string) (header, claims map[string]any, signingInput, signature []byte) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts, want 3", len(parts))
	}
	segments := make([][]byte, len(parts))
	for i, part := range parts {
		decoded, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			t.Fatalf("segment %d is not unpadded base64url: %v", i, err)
		}
		segments[i] = decoded
	}
	if err := json.Unmarshal(segments[0], &header); err != nil {
		t.Fatalf("decoding header: %v", err)
	}
	if err := json.Unmarshal(segments[1], &claims); err != nil {
		t.Fatalf("decoding claims: %v", err)
	}
	return header, claims, []byte(parts[0] + "." + parts[1]), segments[2]
}

// verifies checks a JWS signature: ECDSA as raw r||s, RSA as PKCS#1 v1.5.
func verifies(pub crypto.PublicKey, hash crypto.Hash, digest, signature []byte) bool {
	switch pub := pub.(type) {
	case *ecdsa.PublicKey:
		half := len(signature) / 2
		r := new(big.Int).SetBytes(signature[:half])
		s := new(big.Int).SetBytes(signature[half:])
		return ecdsa.Verify(pub, digest, r, s)
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(pub, hash, digest, signature) == nil
	}
	return false
}

func envOf(values map[string]string) func(string) string {
	return func(name string) string {
		return values[name]
	}
}
