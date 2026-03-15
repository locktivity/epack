package sigstore

import (
	"os"
	"path/filepath"
	"testing"
)

func validTrustRootPath() string {
	return filepath.Join("..", "..", "..", "pack", "verify", "testdata", "public-good.json")
}

func TestIdentityPolicy_HasPolicy(t *testing.T) {
	tests := []struct {
		name   string
		policy IdentityPolicy
		want   bool
	}{
		{
			name:   "empty policy",
			policy: IdentityPolicy{},
			want:   false,
		},
		{
			name:   "issuer only",
			policy: IdentityPolicy{Issuer: "https://accounts.google.com"},
			want:   true,
		},
		{
			name:   "issuer regexp only",
			policy: IdentityPolicy{IssuerRegexp: ".*google.*"},
			want:   true,
		},
		{
			name:   "subject only",
			policy: IdentityPolicy{Subject: "user@example.com"},
			want:   true,
		},
		{
			name:   "subject regexp only",
			policy: IdentityPolicy{SubjectRegexp: ".*@example.com"},
			want:   true,
		},
		{
			name: "all fields set",
			policy: IdentityPolicy{
				Issuer:        "https://accounts.google.com",
				IssuerRegexp:  ".*google.*",
				Subject:       "user@example.com",
				SubjectRegexp: ".*@example.com",
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.policy.HasPolicy()
			if got != tt.want {
				t.Errorf("HasPolicy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildVerifierOptions_InvalidIssuerRegexp(t *testing.T) {
	cfg := VerifierConfig{
		Identity: IdentityPolicy{
			IssuerRegexp: "[invalid", // unclosed bracket
		},
	}

	_, err := BuildVerifierOptions(cfg)
	if err == nil {
		t.Error("expected error for invalid issuer-regexp, got nil")
	}
}

func TestBuildVerifierOptions_InvalidSubjectRegexp(t *testing.T) {
	cfg := VerifierConfig{
		Identity: IdentityPolicy{
			SubjectRegexp: "[invalid", // unclosed bracket
		},
	}

	_, err := BuildVerifierOptions(cfg)
	if err == nil {
		t.Error("expected error for invalid subject-regexp, got nil")
	}
}

func TestBuildVerifierOptions_ValidRegexp(t *testing.T) {
	cfg := VerifierConfig{
		Identity: IdentityPolicy{
			IssuerRegexp:  "^https://.*\\.google\\.com$",
			SubjectRegexp: ".*@example\\.com$",
		},
		InsecureSkipIdentityCheck: false,
	}

	opts, err := BuildVerifierOptions(cfg)
	if err != nil {
		t.Fatalf("BuildVerifierOptions failed: %v", err)
	}

	// Should have options for issuer and subject regexps
	if len(opts) < 2 {
		t.Errorf("expected at least 2 options, got %d", len(opts))
	}
}

func TestBuildVerifierOptions_InsecureSkipIdentityCheck(t *testing.T) {
	cfg := VerifierConfig{
		Identity:                  IdentityPolicy{}, // no policy
		InsecureSkipIdentityCheck: true,
	}

	opts, err := BuildVerifierOptions(cfg)
	if err != nil {
		t.Fatalf("BuildVerifierOptions failed: %v", err)
	}

	// Should have the insecure skip option
	if len(opts) == 0 {
		t.Error("expected at least 1 option for insecure skip")
	}
}

func TestBuildVerifierOptions_NoOptionsWhenEmpty(t *testing.T) {
	cfg := VerifierConfig{
		Identity:                  IdentityPolicy{},
		InsecureSkipIdentityCheck: false,
	}

	opts, err := BuildVerifierOptions(cfg)
	if err != nil {
		t.Fatalf("BuildVerifierOptions failed: %v", err)
	}

	// No identity policy and no insecure skip = no options
	if len(opts) != 0 {
		t.Errorf("expected 0 options, got %d", len(opts))
	}
}

func TestBuildVerifierOptions_OfflineRequiresTrustRoot(t *testing.T) {
	cfg := VerifierConfig{
		Identity:                  IdentityPolicy{},
		Offline:                   true,
		InsecureSkipIdentityCheck: true, // need this since no identity
	}

	_, err := BuildVerifierOptions(cfg)
	if err == nil {
		t.Fatal("expected error for offline verification without trust root")
	}
}

func TestBuildVerifierOptions_OfflineWithTrustRoot(t *testing.T) {
	cfg := VerifierConfig{
		TrustRootPath:             validTrustRootPath(),
		Identity:                  IdentityPolicy{},
		Offline:                   true,
		InsecureSkipIdentityCheck: true, // need this since no identity
	}

	opts, err := BuildVerifierOptions(cfg)
	if err != nil {
		t.Fatalf("BuildVerifierOptions failed: %v", err)
	}

	// Should have trusted root + offline + insecure skip options.
	if len(opts) < 3 {
		t.Errorf("expected at least 3 options, got %d", len(opts))
	}
}

func TestLoadTrustRootOption_NoPath(t *testing.T) {
	opt, err := LoadTrustRootOption("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opt != nil {
		t.Error("expected nil option when no path specified")
	}
}

func TestLoadTrustRootOption_FileNotFound(t *testing.T) {
	_, err := LoadTrustRootOption("/nonexistent/path/trust-root.json")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadTrustRootOption_InvalidContent(t *testing.T) {
	// Create a temp file with invalid trust root content
	tmpDir := t.TempDir()
	flagPath := filepath.Join(tmpDir, "invalid-trust-root.json")
	if err := os.WriteFile(flagPath, []byte(`{}`), 0644); err != nil {
		t.Fatalf("failed to write trust root: %v", err)
	}

	// Should fail on parse since {} is not a valid trust root
	_, err := LoadTrustRootOption(flagPath)
	if err == nil {
		t.Error("expected error for invalid trust root content")
	}
}

func TestBuildVerifierOptions_AllIdentityFields(t *testing.T) {
	cfg := VerifierConfig{
		Identity: IdentityPolicy{
			Issuer:        "https://accounts.google.com",
			IssuerRegexp:  ".*google.*",
			Subject:       "user@example.com",
			SubjectRegexp: ".*@example.com",
		},
	}

	opts, err := BuildVerifierOptions(cfg)
	if err != nil {
		t.Fatalf("BuildVerifierOptions failed: %v", err)
	}

	// Should have 4 options (issuer, issuer-regexp, subject, subject-regexp)
	if len(opts) != 4 {
		t.Errorf("expected 4 options, got %d", len(opts))
	}
}

func TestBuildVerifierOptions_ComplexRegexp(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantErr bool
	}{
		{
			name:    "simple pattern",
			pattern: ".*",
			wantErr: false,
		},
		{
			name:    "email pattern",
			pattern: `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`,
			wantErr: false,
		},
		{
			name:    "url pattern",
			pattern: `^https://[a-z]+\.example\.com$`,
			wantErr: false,
		},
		{
			name:    "unclosed group",
			pattern: "(abc",
			wantErr: true,
		},
		{
			name:    "invalid quantifier",
			pattern: "a{1,0}", // min > max
			wantErr: true,
		},
		{
			name:    "invalid escape",
			pattern: `\`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+"_issuer", func(t *testing.T) {
			cfg := VerifierConfig{
				Identity: IdentityPolicy{IssuerRegexp: tt.pattern},
			}
			_, err := BuildVerifierOptions(cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("IssuerRegexp %q: error = %v, wantErr = %v", tt.pattern, err, tt.wantErr)
			}
		})

		t.Run(tt.name+"_subject", func(t *testing.T) {
			cfg := VerifierConfig{
				Identity: IdentityPolicy{SubjectRegexp: tt.pattern},
			}
			_, err := BuildVerifierOptions(cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("SubjectRegexp %q: error = %v, wantErr = %v", tt.pattern, err, tt.wantErr)
			}
		})
	}
}
