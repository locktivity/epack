package verify

import (
	"context"
	"encoding/json"
	"regexp"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
)

// TestNewSigstoreVerifier_InvalidBundle tests that invalid bundle JSON is rejected.
func TestNewSigstoreVerifier_InvalidBundle(t *testing.T) {
	// Skip if we can't create a verifier (requires network for TUF)
	// Use InsecureSkipIdentityCheck since we're only testing bundle parsing
	v, err := NewSigstoreVerifier(WithOffline(), WithInsecureSkipIdentityCheck())
	if err != nil {
		t.Skipf("skipping test, cannot create verifier: %v", err)
	}

	tests := []struct {
		name        string
		attestation []byte
		wantErr     bool
	}{
		{
			name:        "empty input",
			attestation: []byte{},
			wantErr:     true,
		},
		{
			name:        "invalid json",
			attestation: []byte(`{invalid}`),
			wantErr:     true,
		},
		{
			name:        "empty object",
			attestation: []byte(`{}`),
			wantErr:     true,
		},
		{
			name:        "wrong structure",
			attestation: []byte(`{"foo": "bar"}`),
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := v.Verify(context.Background(), tt.attestation)
			if tt.wantErr && err == nil {
				t.Error("Verify() expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Verify() unexpected error: %v", err)
			}
		})
	}
}

// TestSigstoreVerifier_ImplementsInterface verifies the interface is satisfied.
func TestSigstoreVerifier_ImplementsInterface(t *testing.T) {
	// This is a compile-time check, but we include it as a test for clarity
	var _ Verifier = (*SigstoreVerifier)(nil)
}

// TestBuildIdentityPolicy tests the identity policy builder.
func TestBuildIdentityPolicy(t *testing.T) {
	tests := []struct {
		name    string
		opts    []Option
		wantErr bool
	}{
		{
			name:    "no identity requirements - requires explicit opt-in",
			opts:    nil,
			wantErr: true, // Must explicitly use WithInsecureSkipIdentityCheck
		},
		{
			name:    "explicit insecure skip identity check",
			opts:    []Option{WithInsecureSkipIdentityCheck()},
			wantErr: false,
		},
		{
			name:    "with issuer only - requires subject too",
			opts:    []Option{WithIssuer("https://accounts.google.com")},
			wantErr: true, // sigstore-go requires both issuer and subject
		},
		{
			name:    "with subject only - requires issuer too",
			opts:    []Option{WithSubject("user@example.com")},
			wantErr: true, // sigstore-go requires both issuer and subject
		},
		{
			name: "with both issuer and subject",
			opts: []Option{
				WithIssuer("https://accounts.google.com"),
				WithSubject("user@example.com"),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := applyOptions(tt.opts)
			sv := &SigstoreVerifier{cfg: cfg}

			opts, err := sv.buildIdentityPolicy()
			if tt.wantErr && err == nil {
				t.Error("buildIdentityPolicy() expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("buildIdentityPolicy() unexpected error: %v", err)
			}
			if !tt.wantErr && opts == nil {
				t.Error("buildIdentityPolicy() returned nil options")
			}
		})
	}
}

// TestLoadTrustedRoot_InvalidJSON tests that invalid trusted root JSON is rejected.
func TestLoadTrustedRoot_InvalidJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:    "empty input",
			input:   []byte{},
			wantErr: true,
		},
		{
			name:    "invalid json",
			input:   []byte(`{invalid}`),
			wantErr: true,
		},
		{
			name:    "wrong structure",
			input:   []byte(`{"foo": "bar"}`),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadTrustedRoot(tt.input)
			if tt.wantErr && err == nil {
				t.Error("LoadTrustedRoot() expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("LoadTrustedRoot() unexpected error: %v", err)
			}
		})
	}
}

// TestBuildIdentityPolicy_RegexpPatterns tests identity policy with regexp patterns.
// Note: sigstore-go requires both issuer AND subject criteria when using certificate identity.
func TestBuildIdentityPolicy_RegexpPatterns(t *testing.T) {
	tests := []struct {
		name    string
		opts    []Option
		wantErr bool
	}{
		{
			name: "issuer regexp only - requires subject too",
			opts: []Option{
				WithIssuerRegexp(regexp.MustCompile(`https://.*\.google\.com`)),
			},
			wantErr: true, // sigstore-go requires subject criteria
		},
		{
			name: "subject regexp only - requires issuer too",
			opts: []Option{
				WithSubjectRegexp(regexp.MustCompile(`.*@example\.com`)),
			},
			wantErr: true, // sigstore-go requires issuer criteria
		},
		{
			name: "both regexp patterns",
			opts: []Option{
				WithIssuerRegexp(regexp.MustCompile(`https://.*\.google\.com`)),
				WithSubjectRegexp(regexp.MustCompile(`.*@example\.com`)),
			},
			wantErr: false,
		},
		{
			name: "exact issuer with subject regexp",
			opts: []Option{
				WithIssuer("https://accounts.google.com"),
				WithSubjectRegexp(regexp.MustCompile(`.*@example\.com`)),
			},
			wantErr: false,
		},
		{
			name: "issuer regexp with exact subject",
			opts: []Option{
				WithIssuerRegexp(regexp.MustCompile(`https://.*\.google\.com`)),
				WithSubject("user@example.com"),
			},
			wantErr: false,
		},
		{
			name: "all four constraints",
			opts: []Option{
				WithIssuer("https://accounts.google.com"),
				WithIssuerRegexp(regexp.MustCompile(`https://.*\.google\.com`)),
				WithSubject("user@example.com"),
				WithSubjectRegexp(regexp.MustCompile(`.*@example\.com`)),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := applyOptions(tt.opts)
			sv := &SigstoreVerifier{cfg: cfg}

			opts, err := sv.buildIdentityPolicy()
			if tt.wantErr && err == nil {
				t.Error("buildIdentityPolicy() expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("buildIdentityPolicy() unexpected error: %v", err)
			}
			if !tt.wantErr && opts == nil {
				t.Error("buildIdentityPolicy() returned nil options")
			}
		})
	}
}

// TestRegexpString tests the regexpString helper function.
func TestRegexpString(t *testing.T) {
	tests := []struct {
		name    string
		pattern *regexp.Regexp
		want    string
	}{
		{
			name:    "nil regexp",
			pattern: nil,
			want:    "",
		},
		{
			name:    "simple pattern",
			pattern: regexp.MustCompile(`.*`),
			want:    ".*",
		},
		{
			name:    "email pattern",
			pattern: regexp.MustCompile(`^[a-z]+@example\.com$`),
			want:    `^[a-z]+@example\.com$`,
		},
		{
			name:    "url pattern",
			pattern: regexp.MustCompile(`https://[a-z]+\.google\.com`),
			want:    `https://[a-z]+\.google\.com`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := regexpString(tt.pattern)
			if got != tt.want {
				t.Errorf("regexpString() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestConfigIdentityChecks tests the hasIdentityPolicy logic.
func TestConfigIdentityChecks(t *testing.T) {
	tests := []struct {
		name              string
		opts              []Option
		hasIdentityPolicy bool
	}{
		{
			name:              "empty config",
			opts:              nil,
			hasIdentityPolicy: false,
		},
		{
			name:              "issuer only",
			opts:              []Option{WithIssuer("https://accounts.google.com")},
			hasIdentityPolicy: true,
		},
		{
			name:              "issuer regexp only",
			opts:              []Option{WithIssuerRegexp(regexp.MustCompile(`.*`))},
			hasIdentityPolicy: true,
		},
		{
			name:              "subject only",
			opts:              []Option{WithSubject("user@example.com")},
			hasIdentityPolicy: true,
		},
		{
			name:              "subject regexp only",
			opts:              []Option{WithSubjectRegexp(regexp.MustCompile(`.*`))},
			hasIdentityPolicy: true,
		},
		{
			name: "offline mode without identity",
			opts: []Option{WithOffline()},
			// offline mode doesn't count as identity policy
			hasIdentityPolicy: false,
		},
		{
			name: "threshold options without identity",
			opts: []Option{
				WithTransparencyLogThreshold(2),
				WithTimestampAuthorityThreshold(1),
			},
			hasIdentityPolicy: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := applyOptions(tt.opts)
			hasPolicy := cfg.issuer != "" || cfg.issuerRegexp != nil ||
				cfg.subject != "" || cfg.subjectRegexp != nil

			if hasPolicy != tt.hasIdentityPolicy {
				t.Errorf("hasIdentityPolicy = %v, want %v", hasPolicy, tt.hasIdentityPolicy)
			}
		})
	}
}

// TestWithInsecureSkipIdentityCheck tests the insecure skip option.
func TestWithInsecureSkipIdentityCheck(t *testing.T) {
	cfg := applyOptions([]Option{WithInsecureSkipIdentityCheck()})

	if !cfg.insecureSkipIdentityCheck {
		t.Error("WithInsecureSkipIdentityCheck() should set insecureSkipIdentityCheck = true")
	}

	// Should allow building policy without identity requirements
	sv := &SigstoreVerifier{cfg: cfg}
	opts, err := sv.buildIdentityPolicy()
	if err != nil {
		t.Errorf("buildIdentityPolicy() with insecure skip should not error: %v", err)
	}
	if opts == nil {
		t.Error("buildIdentityPolicy() should return non-nil options")
	}
}

// TestBuildIdentityPolicy_ErrorMessage tests that error messages are helpful.
func TestBuildIdentityPolicy_ErrorMessage(t *testing.T) {
	cfg := applyOptions(nil) // No options = no identity policy
	sv := &SigstoreVerifier{cfg: cfg}

	_, err := sv.buildIdentityPolicy()
	if err == nil {
		t.Fatal("expected error for missing identity policy")
	}

	errMsg := err.Error()

	// Error should mention how to fix it
	if !containsString(errMsg, "WithIssuer") && !containsString(errMsg, "WithSubject") {
		t.Errorf("error message should mention WithIssuer/WithSubject: %q", errMsg)
	}
	if !containsString(errMsg, "WithInsecureSkipIdentityCheck") {
		t.Errorf("error message should mention WithInsecureSkipIdentityCheck: %q", errMsg)
	}
}

// TestExtractStatementFromBundle tests statement extraction from DSSE envelopes.
func TestExtractStatementFromBundle_NilBundle(t *testing.T) {
	// nil bundle should not panic, just return nil
	stmt := extractStatementFromBundle(nil)
	if stmt != nil {
		t.Error("extractStatementFromBundle(nil) should return nil")
	}
}

func TestExtractStatementFromBundle_EmptyBundle(t *testing.T) {
	// Create a minimal bundle without DSSE envelope
	b := &bundle.Bundle{}
	stmt := extractStatementFromBundle(b)
	// Empty bundle has no DSSE envelope, so statement should be nil
	if stmt != nil {
		t.Error("extractStatementFromBundle() should return nil for bundle without DSSE envelope")
	}
}

// TestInTotoStatementParsing tests the in-toto statement JSON parsing.
func TestInTotoStatementParsing(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantErr bool
	}{
		{
			name: "valid statement",
			json: `{
				"_type": "https://in-toto.io/Statement/v1",
				"predicateType": "https://slsa.dev/provenance/v1",
				"subject": [
					{"name": "artifact.tar.gz", "digest": {"sha256": "abc123"}}
				],
				"predicate": {}
			}`,
			wantErr: false,
		},
		{
			name: "multiple subjects",
			json: `{
				"_type": "https://in-toto.io/Statement/v1",
				"predicateType": "https://evidencepack.org/attestation/v1",
				"subject": [
					{"name": "pack1.pack", "digest": {"sha256": "abc"}},
					{"name": "pack2.pack", "digest": {"sha256": "def"}}
				],
				"predicate": {"pack_digest": "sha256:xyz"}
			}`,
			wantErr: false,
		},
		{
			name: "empty subjects",
			json: `{
				"_type": "https://in-toto.io/Statement/v1",
				"predicateType": "https://test/v1",
				"subject": [],
				"predicate": {}
			}`,
			wantErr: false,
		},
		{
			name:    "invalid json",
			json:    `{invalid}`,
			wantErr: true,
		},
		{
			name:    "missing type field",
			json:    `{"predicateType": "test", "subject": [], "predicate": {}}`,
			wantErr: false, // Missing _type is valid JSON, just empty string
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stmt inTotoStatement
			err := json.Unmarshal([]byte(tt.json), &stmt)
			if (err != nil) != tt.wantErr {
				t.Errorf("json.Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestVerifierOptionsChaining tests that options can be chained.
func TestVerifierOptionsChaining(t *testing.T) {
	opts := []Option{
		WithIssuer("https://accounts.google.com"),
		WithSubject("user@example.com"),
		WithOffline(),
		WithTransparencyLogThreshold(0),
		WithTimestampAuthorityThreshold(1),
	}

	cfg := applyOptions(opts)

	if cfg.issuer != "https://accounts.google.com" {
		t.Errorf("issuer = %q, want %q", cfg.issuer, "https://accounts.google.com")
	}
	if cfg.subject != "user@example.com" {
		t.Errorf("subject = %q, want %q", cfg.subject, "user@example.com")
	}
	if !cfg.offline {
		t.Error("offline should be true")
	}
	if cfg.tlogThreshold != 0 {
		t.Errorf("tlogThreshold = %d, want 0", cfg.tlogThreshold)
	}
	if cfg.tsaThreshold != 1 {
		t.Errorf("tsaThreshold = %d, want 1", cfg.tsaThreshold)
	}
}

// TestVerifierOptionsOverride tests that later options override earlier ones.
func TestVerifierOptionsOverride(t *testing.T) {
	opts := []Option{
		WithIssuer("first-issuer"),
		WithIssuer("second-issuer"),
		WithSubject("first-subject"),
		WithSubject("second-subject"),
	}

	cfg := applyOptions(opts)

	if cfg.issuer != "second-issuer" {
		t.Errorf("issuer = %q, want %q (last applied)", cfg.issuer, "second-issuer")
	}
	if cfg.subject != "second-subject" {
		t.Errorf("subject = %q, want %q (last applied)", cfg.subject, "second-subject")
	}
}

// TestResultStruct tests Result struct fields.
func TestResultStruct_AllFields(t *testing.T) {
	ts := time.Now()
	result := &Result{
		Verified: true,
		Identity: &Identity{
			Issuer:                  "https://accounts.google.com",
			Subject:                 "user@example.com",
			SubjectAlternativeNames: []string{"user@example.com", "https://github.com/user"},
		},
		Timestamps: []time.Time{ts},
		Statement: &Statement{
			Type:          "https://in-toto.io/Statement/v1",
			PredicateType: "https://evidencepack.org/attestation/v1",
			Subjects: []Subject{
				{Name: "test.pack", Digest: map[string]string{"sha256": "abc123"}},
			},
			Predicate: []byte(`{"pack_digest": "sha256:abc123"}`),
		},
	}

	// Verify all fields are accessible and have expected values
	if !result.Verified {
		t.Error("Verified should be true")
	}
	if result.Identity == nil {
		t.Fatal("Identity should not be nil")
	}
	if len(result.Identity.SubjectAlternativeNames) != 2 {
		t.Errorf("SubjectAlternativeNames length = %d, want 2", len(result.Identity.SubjectAlternativeNames))
	}
	if len(result.Timestamps) != 1 {
		t.Errorf("Timestamps length = %d, want 1", len(result.Timestamps))
	}
	if result.Statement == nil {
		t.Fatal("Statement should not be nil")
	}
	if len(result.Statement.Subjects) != 1 {
		t.Errorf("Statement.Subjects length = %d, want 1", len(result.Statement.Subjects))
	}
	if result.Statement.Subjects[0].Digest["sha256"] != "abc123" {
		t.Errorf("Subject digest = %q, want %q", result.Statement.Subjects[0].Digest["sha256"], "abc123")
	}
}

// containsString checks if s contains substr.
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (len(substr) == 0 || findString(s, substr))
}

func findString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
