package sign

import (
	"context"
	"strings"
	"testing"

	"github.com/locktivity/epack/sign/sigstore"
	"github.com/locktivity/epack/sign/testsupport"
)

func TestNewSignerValidation(t *testing.T) {
	ctx := context.Background()

	// Generate a test key
	testKey, err := testsupport.NewTestKeypair()
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	tests := []struct {
		name    string
		opts    sigstore.Options
		wantErr string
	}{
		{
			name:    "neither OIDC nor PrivateKey",
			opts:    sigstore.Options{},
			wantErr: "must specify either OIDC or PrivateKey",
		},
		{
			name: "both OIDC and PrivateKey",
			opts: sigstore.Options{
				OIDC:       &sigstore.OIDCOptions{Token: "test-token"},
				PrivateKey: testKey,
			},
			wantErr: "cannot specify both OIDC and PrivateKey",
		},
		{
			name: "valid key-based signer",
			opts: sigstore.Options{
				PrivateKey: testKey,
			},
			wantErr: "",
		},
		// URL validation tests
		{
			name: "custom FulcioURL without unsafe flag",
			opts: sigstore.Options{
				PrivateKey: testKey,
				FulcioURL:  "https://custom.fulcio.example.com",
			},
			wantErr: "--insecure-allow-custom-endpoints",
		},
		{
			name: "custom RekorURL without unsafe flag",
			opts: sigstore.Options{
				PrivateKey: testKey,
				RekorURL:   "https://custom.rekor.example.com",
			},
			wantErr: "--insecure-allow-custom-endpoints",
		},
		{
			name: "custom TSA URL without unsafe flag",
			opts: sigstore.Options{
				PrivateKey: testKey,
				TSAURLs:    []string{"https://tsa.example.com"},
			},
			wantErr: "--insecure-allow-custom-endpoints",
		},
		{
			name: "HTTP FulcioURL rejected even with unsafe flag",
			opts: sigstore.Options{
				PrivateKey:                 testKey,
				FulcioURL:                  "http://attacker.com",
				InsecureAllowCustomEndpoints: true,
			},
			wantErr: "must use HTTPS",
		},
		{
			name: "HTTP RekorURL rejected even with unsafe flag",
			opts: sigstore.Options{
				PrivateKey:                 testKey,
				RekorURL:                   "http://attacker.com",
				InsecureAllowCustomEndpoints: true,
			},
			wantErr: "must use HTTPS",
		},
		{
			name: "HTTP TSA URL rejected even with unsafe flag",
			opts: sigstore.Options{
				PrivateKey:                 testKey,
				TSAURLs:                    []string{"http://attacker.com"},
				InsecureAllowCustomEndpoints: true,
			},
			wantErr: "must use HTTPS",
		},
		{
			name: "valid custom HTTPS endpoints with unsafe flag",
			opts: sigstore.Options{
				PrivateKey:                 testKey,
				FulcioURL:                  "https://private-fulcio.corp.example.com",
				RekorURL:                   "https://private-rekor.corp.example.com",
				TSAURLs:                    []string{"https://tsa.corp.example.com"},
				InsecureAllowCustomEndpoints: true,
			},
			wantErr: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := sigstore.NewSigner(ctx, tc.opts)
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tc.wantErr)
				} else if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("expected error containing %q, got %q", tc.wantErr, err.Error())
				}
			}
		})
	}
}

func TestKeyBasedSignerIdentity(t *testing.T) {
	ctx := context.Background()

	key, err := testsupport.NewTestKeypair()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := sigstore.NewSigner(ctx, sigstore.Options{PrivateKey: key})
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	// Identity should be a 64-char hex public key fingerprint
	identity := signer.Identity()
	if len(identity) != 64 {
		t.Errorf("expected 64-char hex identity, got %d chars: %q", len(identity), identity)
	}
}

func TestDistinctKeysHaveDistinctIdentities(t *testing.T) {
	ctx := context.Background()

	key1, err := testsupport.NewTestKeypair()
	if err != nil {
		t.Fatalf("failed to generate key1: %v", err)
	}

	key2, err := testsupport.NewTestKeypair()
	if err != nil {
		t.Fatalf("failed to generate key2: %v", err)
	}

	signer1, err := sigstore.NewSigner(ctx, sigstore.Options{PrivateKey: key1})
	if err != nil {
		t.Fatalf("failed to create signer1: %v", err)
	}

	signer2, err := sigstore.NewSigner(ctx, sigstore.Options{PrivateKey: key2})
	if err != nil {
		t.Fatalf("failed to create signer2: %v", err)
	}

	if signer1.Identity() == signer2.Identity() {
		t.Errorf("two distinct keys should have distinct identities, both got %q", signer1.Identity())
	}
}

func TestSafeAttestationFilename(t *testing.T) {
	tests := []struct {
		identity string
		wantErr  bool
		errMsg   string
	}{
		// Valid identities
		{"test@example.com", false, ""},
		{"security@acme.com", false, ""},
		{"https://github.com/org/repo", false, ""},
		{"user123", false, ""},
		{"a", false, ""},

		// Invalid: empty identity
		{"", true, "cannot be empty"},
	}

	for _, tc := range tests {
		t.Run(tc.identity, func(t *testing.T) {
			filename, err := safeAttestationFilename(tc.identity)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tc.errMsg)
				} else if !strings.Contains(err.Error(), tc.errMsg) {
					t.Errorf("expected error containing %q, got %q", tc.errMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify format: attestations/{64-hex-chars}.sigstore.json
			if !strings.HasPrefix(filename, "attestations/") {
				t.Errorf("filename should start with 'attestations/': %q", filename)
			}
			if !strings.HasSuffix(filename, ".sigstore.json") {
				t.Errorf("filename should end with '.sigstore.json': %q", filename)
			}

			// Extract the hash part
			remainder := strings.TrimPrefix(filename, "attestations/")
			hashPart := strings.TrimSuffix(remainder, ".sigstore.json")

			// Should be 64 hex chars (SHA-256)
			if len(hashPart) != 64 {
				t.Errorf("hash part should be 64 chars, got %d: %q", len(hashPart), hashPart)
			}

			// Should be valid hex
			for _, c := range hashPart {
				if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
					t.Errorf("hash part contains non-hex char %q in %q", string(c), hashPart)
					break
				}
			}

			// Should not contain path separators
			if strings.Contains(remainder, "/") || strings.Contains(remainder, "\\") {
				t.Errorf("remainder contains path separator: %q", remainder)
			}
		})
	}
}

func TestSafeAttestationFilenamePathInjection(t *testing.T) {
	// These are malicious identities that attempt path injection
	// All should produce safe filenames (hashed), not inject paths
	maliciousIdentities := []string{
		"../artifacts/pwn",
		"..\\artifacts\\pwn",
		"../../etc/passwd",
		"/etc/passwd",
		"attestations/../artifacts/pwn",
		"foo/bar/baz",
		"...",
		"./.",
		".\x00.",
		"foo\x00bar",
		"attestations/nested/path",
	}

	for _, identity := range maliciousIdentities {
		t.Run(identity, func(t *testing.T) {
			filename, err := safeAttestationFilename(identity)
			if err != nil {
				// Error is acceptable - means it was rejected
				return
			}

			// If no error, the filename must be safe
			if !strings.HasPrefix(filename, "attestations/") {
				t.Errorf("filename should start with 'attestations/': %q", filename)
			}

			remainder := strings.TrimPrefix(filename, "attestations/")

			// Must not contain path separators
			if strings.Contains(remainder, "/") {
				t.Errorf("malicious identity %q produced nested path: %q", identity, filename)
			}
			if strings.Contains(remainder, "\\") {
				t.Errorf("malicious identity %q produced backslash path: %q", identity, filename)
			}

			// Must not start with dots
			if strings.HasPrefix(remainder, ".") {
				t.Errorf("malicious identity %q produced dot-prefixed path: %q", identity, filename)
			}

			// Must end with .sigstore.json
			if !strings.HasSuffix(remainder, ".sigstore.json") {
				t.Errorf("malicious identity %q produced wrong extension: %q", identity, filename)
			}
		})
	}
}
