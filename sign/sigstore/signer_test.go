package sigstore

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// newTestKeypair creates a test keypair for use in this package's tests.
// This is a local helper to avoid import cycles with sign/testsupport.
func newTestKeypair() (crypto.Signer, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// TestValidateHTTPSURL tests the URL validation function directly.
func TestValidateHTTPSURL(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		fieldName string
		wantErr   bool
		errSubstr string
	}{
		// Valid HTTPS URLs
		{
			name:      "valid https url",
			url:       "https://example.com",
			fieldName: "TestField",
			wantErr:   false,
		},
		{
			name:      "https with port",
			url:       "https://example.com:8443",
			fieldName: "TestField",
			wantErr:   false,
		},
		{
			name:      "https with path",
			url:       "https://example.com/api/v1",
			fieldName: "TestField",
			wantErr:   false,
		},
		{
			name:      "https with subdomain",
			url:       "https://api.fulcio.sigstore.dev",
			fieldName: "TestField",
			wantErr:   false,
		},
		{
			name:      "https uppercase scheme",
			url:       "HTTPS://example.com",
			fieldName: "TestField",
			wantErr:   false,
		},
		{
			name:      "https mixed case scheme",
			url:       "HtTpS://example.com",
			fieldName: "TestField",
			wantErr:   false,
		},

		// Invalid: HTTP scheme
		{
			name:      "http scheme rejected",
			url:       "http://example.com",
			fieldName: "TestField",
			wantErr:   true,
			errSubstr: "must use HTTPS",
		},

		// Invalid: other schemes
		{
			name:      "ftp scheme rejected",
			url:       "ftp://example.com",
			fieldName: "TestField",
			wantErr:   true,
			errSubstr: "must use HTTPS",
		},
		{
			name:      "file scheme rejected",
			url:       "file:///etc/passwd",
			fieldName: "TestField",
			wantErr:   true,
			errSubstr: "must use HTTPS",
		},

		// Invalid: missing host
		{
			name:      "missing host",
			url:       "https://",
			fieldName: "TestField",
			wantErr:   true,
			errSubstr: "missing host",
		},
		{
			name:      "scheme only",
			url:       "https:",
			fieldName: "TestField",
			wantErr:   true,
			errSubstr: "missing host",
		},

		// Invalid: no scheme
		{
			name:      "no scheme",
			url:       "example.com",
			fieldName: "TestField",
			wantErr:   true,
			errSubstr: "must use HTTPS",
		},

		// Edge cases
		{
			name:      "localhost",
			url:       "https://localhost",
			fieldName: "TestField",
			wantErr:   false,
		},
		{
			name:      "localhost with port",
			url:       "https://localhost:8443",
			fieldName: "TestField",
			wantErr:   false,
		},
		{
			name:      "ip address",
			url:       "https://192.168.1.1",
			fieldName: "TestField",
			wantErr:   false,
		},
		{
			name:      "ipv6 address",
			url:       "https://[::1]",
			fieldName: "TestField",
			wantErr:   false,
		},
		{
			name:      "with query string",
			url:       "https://example.com?param=value",
			fieldName: "TestField",
			wantErr:   false,
		},
		{
			name:      "with fragment",
			url:       "https://example.com#section",
			fieldName: "TestField",
			wantErr:   false,
		},
		{
			name:      "empty string",
			url:       "",
			fieldName: "TestField",
			wantErr:   true,
			errSubstr: "must use HTTPS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateHTTPSURL(tt.url, tt.fieldName)
			if tt.wantErr {
				if err == nil {
					t.Errorf("validateHTTPSURL(%q) = nil, want error containing %q", tt.url, tt.errSubstr)
				} else if tt.errSubstr != "" && !containsSubstring(err.Error(), tt.errSubstr) {
					t.Errorf("validateHTTPSURL(%q) = %q, want error containing %q", tt.url, err.Error(), tt.errSubstr)
				}
			} else {
				if err != nil {
					t.Errorf("validateHTTPSURL(%q) = %v, want nil", tt.url, err)
				}
			}
		})
	}
}

// TestValidateOptionalHTTPSURL tests the optional URL validation.
func TestValidateOptionalHTTPSURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{
			name:    "empty string is valid",
			url:     "",
			wantErr: false,
		},
		{
			name:    "valid https",
			url:     "https://example.com",
			wantErr: false,
		},
		{
			name:    "http rejected",
			url:     "http://example.com",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOptionalHTTPSURL(tt.url, "TestField")
			if (err != nil) != tt.wantErr {
				t.Errorf("validateOptionalHTTPSURL(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

// TestValidateEndpoints tests the endpoint validation through NewSigner.
func TestValidateEndpoints(t *testing.T) {
	ctx := context.Background()

	testKey, err := newTestKeypair()
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	tests := []struct {
		name    string
		opts    Options
		wantErr bool
		errSub  string
	}{
		{
			name: "no custom endpoints",
			opts: Options{
				PrivateKey: testKey,
			},
			wantErr: false,
		},
		{
			name: "all custom endpoints with unsafe flag",
			opts: Options{
				PrivateKey:                   testKey,
				FulcioURL:                    "https://fulcio.example.com",
				RekorURL:                     "https://rekor.example.com",
				TSAURLs:                      []string{"https://tsa1.example.com", "https://tsa2.example.com"},
				InsecureAllowCustomEndpoints: true,
			},
			wantErr: false,
		},
		{
			name: "mixed valid and invalid TSA URLs",
			opts: Options{
				PrivateKey:                   testKey,
				TSAURLs:                      []string{"https://tsa1.example.com", "http://bad.com"},
				InsecureAllowCustomEndpoints: true,
			},
			wantErr: true,
			errSub:  "must use HTTPS",
		},
		{
			name: "only FulcioURL custom",
			opts: Options{
				PrivateKey:                   testKey,
				FulcioURL:                    "https://fulcio.example.com",
				InsecureAllowCustomEndpoints: true,
			},
			wantErr: false,
		},
		{
			name: "only RekorURL custom",
			opts: Options{
				PrivateKey:                   testKey,
				RekorURL:                     "https://rekor.example.com",
				InsecureAllowCustomEndpoints: true,
			},
			wantErr: false,
		},
		{
			name: "only TSA custom",
			opts: Options{
				PrivateKey:                   testKey,
				TSAURLs:                      []string{"https://tsa.example.com"},
				InsecureAllowCustomEndpoints: true,
			},
			wantErr: false,
		},
		{
			name: "empty TSA array is valid",
			opts: Options{
				PrivateKey:                   testKey,
				TSAURLs:                      []string{},
				InsecureAllowCustomEndpoints: true,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewSigner(ctx, tt.opts)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errSub)
				} else if tt.errSub != "" && !containsSubstring(err.Error(), tt.errSub) {
					t.Errorf("expected error containing %q, got %q", tt.errSub, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestPublicKeyFingerprint tests the fingerprint function.
func TestPublicKeyFingerprint(t *testing.T) {
	key1, err := newTestKeypair()
	if err != nil {
		t.Fatalf("failed to generate key1: %v", err)
	}

	key2, err := newTestKeypair()
	if err != nil {
		t.Fatalf("failed to generate key2: %v", err)
	}

	// Same key should produce same fingerprint
	fp1a, err := publicKeyFingerprint(key1.Public())
	if err != nil {
		t.Fatalf("publicKeyFingerprint failed: %v", err)
	}

	fp1b, err := publicKeyFingerprint(key1.Public())
	if err != nil {
		t.Fatalf("publicKeyFingerprint failed: %v", err)
	}

	if fp1a != fp1b {
		t.Errorf("same key should produce same fingerprint: %q != %q", fp1a, fp1b)
	}

	// Different keys should produce different fingerprints
	fp2, err := publicKeyFingerprint(key2.Public())
	if err != nil {
		t.Fatalf("publicKeyFingerprint failed: %v", err)
	}

	if fp1a == fp2 {
		t.Errorf("different keys should produce different fingerprints: both got %q", fp1a)
	}

	// Fingerprint should be 64 hex chars (SHA-256)
	if len(fp1a) != 64 {
		t.Errorf("fingerprint should be 64 chars, got %d: %q", len(fp1a), fp1a)
	}

	// Should be valid hex
	for _, c := range fp1a {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			t.Errorf("fingerprint contains non-hex char: %q", fp1a)
			break
		}
	}
}

// TestDefaultString tests the defaultString helper.
func TestDefaultString(t *testing.T) {
	tests := []struct {
		v    string
		def  string
		want string
	}{
		{"value", "default", "value"},
		{"", "default", "default"},
		{"", "", ""},
		{"value", "", "value"},
	}

	for _, tt := range tests {
		got := defaultString(tt.v, tt.def)
		if got != tt.want {
			t.Errorf("defaultString(%q, %q) = %q, want %q", tt.v, tt.def, got, tt.want)
		}
	}
}

// containsSubstring is a case-sensitive substring check.
func containsSubstring(s, substr string) bool {
	return len(substr) == 0 || (len(s) >= len(substr) && findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestStaticKeypair_SignData tests the staticKeypair.SignData method.
func TestStaticKeypair_SignData(t *testing.T) {
	key, err := newTestKeypair()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	sk := &staticKeypair{key: key}
	data := []byte("test data to sign")

	sig, hash, err := sk.SignData(context.Background(), data)
	if err != nil {
		t.Fatalf("SignData() error: %v", err)
	}

	// Signature should be non-empty
	if len(sig) == 0 {
		t.Error("SignData() returned empty signature")
	}

	// Hash should be SHA-256 (32 bytes)
	if len(hash) != 32 {
		t.Errorf("SignData() hash length = %d, want 32", len(hash))
	}

	// Same data should produce same hash
	_, hash2, err := sk.SignData(context.Background(), data)
	if err != nil {
		t.Fatalf("SignData() second call error: %v", err)
	}
	if string(hash) != string(hash2) {
		t.Error("SignData() should produce same hash for same data")
	}

	// Different data should produce different hash
	_, hash3, err := sk.SignData(context.Background(), []byte("different data"))
	if err != nil {
		t.Fatalf("SignData() third call error: %v", err)
	}
	if string(hash) == string(hash3) {
		t.Error("SignData() should produce different hash for different data")
	}
}

// TestStaticKeypair_GetPublicKey tests the staticKeypair.GetPublicKey method.
func TestStaticKeypair_GetPublicKey(t *testing.T) {
	key, err := newTestKeypair()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	sk := &staticKeypair{key: key}
	pub := sk.GetPublicKey()

	if pub == nil {
		t.Fatal("GetPublicKey() returned nil")
	}

	// Should return the same public key as the underlying signer
	if pub != key.Public() {
		t.Error("GetPublicKey() should return the signer's public key")
	}
}

// TestStaticKeypair_GetPublicKeyPem tests the staticKeypair.GetPublicKeyPem method.
func TestStaticKeypair_GetPublicKeyPem(t *testing.T) {
	key, err := newTestKeypair()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	sk := &staticKeypair{key: key}
	pem, err := sk.GetPublicKeyPem()
	if err != nil {
		t.Fatalf("GetPublicKeyPem() error: %v", err)
	}

	// Should be valid PEM format
	if !containsSubstring(pem, "-----BEGIN PUBLIC KEY-----") {
		t.Errorf("GetPublicKeyPem() should contain BEGIN header: %q", pem)
	}
	if !containsSubstring(pem, "-----END PUBLIC KEY-----") {
		t.Errorf("GetPublicKeyPem() should contain END header: %q", pem)
	}
}

// TestStaticKeypair_GetHint tests the staticKeypair.GetHint method.
func TestStaticKeypair_GetHint(t *testing.T) {
	key, err := newTestKeypair()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	sk := &staticKeypair{key: key}
	hint := sk.GetHint()

	// Current implementation returns nil
	if hint != nil {
		t.Errorf("GetHint() = %v, want nil", hint)
	}
}

// TestStaticKeypair_GetKeyAlgorithm tests the staticKeypair.GetKeyAlgorithm method.
func TestStaticKeypair_GetKeyAlgorithm(t *testing.T) {
	key, err := newTestKeypair()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	sk := &staticKeypair{key: key}
	algo := sk.GetKeyAlgorithm()

	// newTestKeypair creates ECDSA P-256 keys
	if algo != "ecdsa" {
		t.Errorf("GetKeyAlgorithm() = %q, want %q", algo, "ecdsa")
	}
}

// TestStaticKeypair_GetHashAlgorithm tests the staticKeypair.GetHashAlgorithm method.
func TestStaticKeypair_GetHashAlgorithm(t *testing.T) {
	key, err := newTestKeypair()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	sk := &staticKeypair{key: key}
	algo := sk.GetHashAlgorithm()

	// Should return SHA2_256
	if algo.String() != "SHA2_256" {
		t.Errorf("GetHashAlgorithm() = %s, want SHA2_256", algo.String())
	}
}

// TestStaticKeypair_GetSigningAlgorithm tests the staticKeypair.GetSigningAlgorithm method.
func TestStaticKeypair_GetSigningAlgorithm(t *testing.T) {
	key, err := newTestKeypair()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	sk := &staticKeypair{key: key}
	algo := sk.GetSigningAlgorithm()

	// newTestKeypair creates ECDSA P-256, so should return PKIX_ECDSA_P256_SHA_256
	if algo.String() != "PKIX_ECDSA_P256_SHA_256" {
		t.Errorf("GetSigningAlgorithm() = %s, want PKIX_ECDSA_P256_SHA_256", algo.String())
	}
}

// TestNewTestKeypair tests the newTestKeypair helper function.
func TestNewTestKeypair(t *testing.T) {
	key, err := newTestKeypair()
	if err != nil {
		t.Fatalf("newTestKeypair() error: %v", err)
	}

	if key == nil {
		t.Fatal("newTestKeypair() returned nil key")
	}

	// Should be able to get public key
	pub := key.Public()
	if pub == nil {
		t.Error("newTestKeypair().Public() returned nil")
	}

	// Two calls should produce different keys
	key2, err := newTestKeypair()
	if err != nil {
		t.Fatalf("newTestKeypair() second call error: %v", err)
	}

	fp1, _ := publicKeyFingerprint(key.Public())
	fp2, _ := publicKeyFingerprint(key2.Public())
	if fp1 == fp2 {
		t.Error("newTestKeypair() should produce unique keys on each call")
	}
}

// TestNewSigner_NoCredentials tests that signer creation fails without credentials.
func TestNewSigner_NoCredentials(t *testing.T) {
	ctx := context.Background()

	// No private key, no OIDC - should fail
	_, err := NewSigner(ctx, Options{})
	if err == nil {
		t.Error("NewSigner() should fail without any credentials")
	}
}

// TestNewSigner_CustomEndpointsWithoutFlag tests that custom endpoints require the unsafe flag.
func TestNewSigner_CustomEndpointsWithoutFlag(t *testing.T) {
	ctx := context.Background()

	key, err := newTestKeypair()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Custom FulcioURL without InsecureAllowCustomEndpoints
	_, err = NewSigner(ctx, Options{
		PrivateKey: key,
		FulcioURL:  "https://custom.fulcio.example.com",
		// InsecureAllowCustomEndpoints not set
	})
	if err == nil {
		t.Error("NewSigner() should fail with custom FulcioURL without unsafe flag")
	}

	// Custom RekorURL without InsecureAllowCustomEndpoints
	_, err = NewSigner(ctx, Options{
		PrivateKey: key,
		RekorURL:   "https://custom.rekor.example.com",
	})
	if err == nil {
		t.Error("NewSigner() should fail with custom RekorURL without unsafe flag")
	}

	// Custom TSAURLs without InsecureAllowCustomEndpoints
	_, err = NewSigner(ctx, Options{
		PrivateKey: key,
		TSAURLs:    []string{"https://custom.tsa.example.com"},
	})
	if err == nil {
		t.Error("NewSigner() should fail with custom TSAURLs without unsafe flag")
	}
}

// TestNewSigner_HTTPEndpointsRejected tests that HTTP endpoints are rejected.
func TestNewSigner_HTTPEndpointsRejected(t *testing.T) {
	ctx := context.Background()

	key, err := newTestKeypair()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	tests := []struct {
		name string
		opts Options
	}{
		{
			name: "HTTP FulcioURL",
			opts: Options{
				PrivateKey:                   key,
				FulcioURL:                    "http://insecure.fulcio.example.com",
				InsecureAllowCustomEndpoints: true,
			},
		},
		{
			name: "HTTP RekorURL",
			opts: Options{
				PrivateKey:                   key,
				RekorURL:                     "http://insecure.rekor.example.com",
				InsecureAllowCustomEndpoints: true,
			},
		},
		{
			name: "HTTP TSA URL",
			opts: Options{
				PrivateKey:                   key,
				TSAURLs:                      []string{"http://insecure.tsa.example.com"},
				InsecureAllowCustomEndpoints: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewSigner(ctx, tt.opts)
			if err == nil {
				t.Error("NewSigner() should reject HTTP endpoints")
			}
			if !containsSubstring(err.Error(), "HTTPS") {
				t.Errorf("error should mention HTTPS: %v", err)
			}
		})
	}
}

// TestSigner_IdentityWithPrivateKey tests the identity with a private key signer.
func TestSigner_IdentityWithPrivateKey(t *testing.T) {
	ctx := context.Background()

	key, err := newTestKeypair()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := NewSigner(ctx, Options{
		PrivateKey: key,
	})
	if err != nil {
		t.Fatalf("NewSigner() error: %v", err)
	}

	identity := signer.Identity()
	if identity == "" {
		t.Error("Identity() should not be empty for private key signer")
	}

	// Identity should be 64-char hex fingerprint
	if len(identity) != 64 {
		t.Errorf("Identity() length = %d, want 64", len(identity))
	}
}

// TestSigner_IdentityConsistent tests that identity is consistent.
func TestSigner_IdentityConsistent(t *testing.T) {
	ctx := context.Background()

	key, err := newTestKeypair()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := NewSigner(ctx, Options{
		PrivateKey: key,
	})
	if err != nil {
		t.Fatalf("NewSigner() error: %v", err)
	}

	// Multiple calls should return same identity
	id1 := signer.Identity()
	id2 := signer.Identity()
	if id1 != id2 {
		t.Errorf("Identity() not consistent: %q != %q", id1, id2)
	}
}

// TestSignerOptions_Validation tests validation of signer options.
func TestSignerOptions_Validation(t *testing.T) {
	ctx := context.Background()

	key, err := newTestKeypair()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Valid options should succeed
	_, err = NewSigner(ctx, Options{
		PrivateKey: key,
	})
	if err != nil {
		t.Errorf("NewSigner() with valid options error: %v", err)
	}

	// Valid options with skip tlog
	_, err = NewSigner(ctx, Options{
		PrivateKey: key,
		SkipTlog:   true,
	})
	if err != nil {
		t.Errorf("NewSigner() with SkipTlog error: %v", err)
	}
}

// TestSigstoreConstants tests the Sigstore constant values.
func TestSigstoreConstants(t *testing.T) {
	// Verify constants are valid HTTPS URLs
	if !containsSubstring(DefaultFulcioURL, "https://") {
		t.Errorf("DefaultFulcioURL should be HTTPS: %q", DefaultFulcioURL)
	}
	if !containsSubstring(DefaultRekorURL, "https://") {
		t.Errorf("DefaultRekorURL should be HTTPS: %q", DefaultRekorURL)
	}
	if !containsSubstring(SigstoreOIDCIssuer, "https://") {
		t.Errorf("SigstoreOIDCIssuer should be HTTPS: %q", SigstoreOIDCIssuer)
	}

	// Verify they point to sigstore.dev
	if !containsSubstring(DefaultFulcioURL, "sigstore.dev") {
		t.Errorf("DefaultFulcioURL should point to sigstore.dev: %q", DefaultFulcioURL)
	}
	if !containsSubstring(DefaultRekorURL, "sigstore.dev") {
		t.Errorf("DefaultRekorURL should point to sigstore.dev: %q", DefaultRekorURL)
	}
}

// TestMarshalUnmarshalBundle tests bundle serialization roundtrip.
func TestMarshalUnmarshalBundle(t *testing.T) {
	// Note: Creating a real bundle requires Sigstore infrastructure,
	// so we test that marshal/unmarshal returns errors for nil/invalid inputs

	// Test UnmarshalBundle with invalid JSON
	_, err := UnmarshalBundle([]byte("not valid json"))
	if err == nil {
		t.Error("UnmarshalBundle(invalid json) should return error")
	}

	// Test UnmarshalBundle with empty bytes
	_, err = UnmarshalBundle([]byte{})
	if err == nil {
		t.Error("UnmarshalBundle(empty) should return error")
	}

	// Test UnmarshalBundle with valid JSON but invalid bundle structure
	// This may or may not error depending on how lenient the Bundle unmarshaling is
	// Just verify it doesn't panic
	_, _ = UnmarshalBundle([]byte(`{"not": "a bundle"}`))
}

// TestOIDCSignerCreation tests OIDC-based signer creation.
func TestOIDCSignerCreation(t *testing.T) {
	ctx := context.Background()

	// OIDC with token should create signer
	signer, err := NewSigner(ctx, Options{
		OIDC: &OIDCOptions{Token: "test-token"},
	})
	if err != nil {
		t.Fatalf("NewSigner(OIDC) error: %v", err)
	}

	// Identity should be a 64-char hex fingerprint
	identity := signer.Identity()
	if len(identity) != 64 {
		t.Errorf("OIDC signer identity length = %d, want 64", len(identity))
	}
}

// TestSignerWithSkipTlog tests signer creation with SkipTlog option.
func TestSignerWithSkipTlog(t *testing.T) {
	ctx := context.Background()

	key, err := newTestKeypair()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Should create signer successfully with SkipTlog
	signer, err := NewSigner(ctx, Options{
		PrivateKey: key,
		SkipTlog:   true,
	})
	if err != nil {
		t.Fatalf("NewSigner(SkipTlog) error: %v", err)
	}

	if signer.Identity() == "" {
		t.Error("signer.Identity() should not be empty")
	}
}

// TestSignerProducesDSSEBundle verifies that the Sign method produces
// a bundle with a DSSE envelope containing the in-toto statement.
func TestSignerProducesDSSEBundle(t *testing.T) {
	ctx := context.Background()

	key, err := newTestKeypair()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := NewSigner(ctx, Options{
		PrivateKey: key,
		SkipTlog:   true, // Skip tlog for unit testing
	})
	if err != nil {
		t.Fatalf("NewSigner error: %v", err)
	}

	// Create a test statement
	statement := []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"pack","digest":{"sha256":"abc123"}}],"predicateType":"https://evidencepack.org/attestation/v1","predicate":{"pack_digest":"sha256:abc123"}}`)

	bundle, err := signer.Sign(ctx, statement)
	if err != nil {
		t.Fatalf("Sign error: %v", err)
	}

	if bundle == nil {
		t.Fatal("Sign returned nil bundle")
	}

	protoBundle := bundle.Bundle
	if protoBundle == nil {
		t.Fatal("bundle.Bundle is nil")
	}

	dsseEnvelope := protoBundle.GetDsseEnvelope()
	if dsseEnvelope == nil {
		t.Fatal("bundle should contain a DSSE envelope, but GetDsseEnvelope() returned nil. This indicates the fix to use DSSEData instead of PlainData may have regressed.")
	}

	// Verify payload type is correct
	if dsseEnvelope.PayloadType != "application/vnd.in-toto+json" {
		t.Errorf("payload type = %q, want %q", dsseEnvelope.PayloadType, "application/vnd.in-toto+json")
	}

	// Verify the payload is not empty
	if len(dsseEnvelope.Payload) == 0 {
		t.Error("DSSE envelope payload is empty")
	}

	// Verify signatures are present
	if len(dsseEnvelope.Signatures) == 0 {
		t.Error("DSSE envelope has no signatures")
	}
}
