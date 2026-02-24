package sigstore

import (
	"regexp"
	"testing"
)

func TestTrustedSLSABuildersNotEmpty(t *testing.T) {
	if len(TrustedSLSABuilders) == 0 {
		t.Fatal("TrustedSLSABuilders must not be empty")
	}
}

func TestTrustedSLSABuildersAreValidRegex(t *testing.T) {
	for i, pattern := range TrustedSLSABuilders {
		_, err := regexp.Compile(pattern)
		if err != nil {
			t.Errorf("TrustedSLSABuilders[%d] is not a valid regex: %v", i, err)
		}
	}
}

func TestTrustedSLSABuildersMatchOfficialBuilder(t *testing.T) {
	// Test cases for the official SLSA builder
	validSANs := []string{
		"https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/tags/v2.1.0",
		"https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.0.0",
		"https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.0.0",
		"https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_container_slsa3.yml@refs/tags/v10.20.30",
	}

	invalidSANs := []string{
		// Wrong repo
		"https://github.com/evil/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/tags/v2.1.0",
		// Wrong org
		"https://github.com/attacker-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/tags/v2.1.0",
		// Not a tag ref
		"https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/heads/main",
		// Branch ref
		"https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/heads/v2.1.0",
		// Commit SHA instead of tag
		"https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@abc123",
		// Missing version
		"https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/tags/",
		// Invalid version format
		"https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/tags/v2",
		"https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/tags/v2.1",
		"https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/tags/latest",
		// User workflow (not SLSA builder)
		"https://github.com/locktivity/epack-tool-scan-secrets/.github/workflows/release.yaml@refs/tags/v0.1.0",
		// Empty
		"",
	}

	for _, pattern := range TrustedSLSABuilders {
		re := regexp.MustCompile(pattern)

		for _, san := range validSANs {
			if !re.MatchString(san) {
				t.Errorf("TrustedSLSABuilders should match valid SAN %q", san)
			}
		}

		for _, san := range invalidSANs {
			if re.MatchString(san) {
				t.Errorf("TrustedSLSABuilders should NOT match invalid SAN %q", san)
			}
		}
	}
}

func TestGitHubActionsIssuer(t *testing.T) {
	expected := "https://token.actions.githubusercontent.com"
	if GitHubActionsIssuer != expected {
		t.Errorf("GitHubActionsIssuer = %q, want %q", GitHubActionsIssuer, expected)
	}
}

func TestComputeDigest(t *testing.T) {
	// Test with non-existent file
	_, err := ComputeDigest("/nonexistent/file")
	if err == nil {
		t.Error("ComputeDigest should fail for non-existent file")
	}
}

func TestVerifyDigest(t *testing.T) {
	tests := []struct {
		name     string
		expected string
		wantErr  bool
	}{
		{
			name:     "invalid expected format",
			expected: "invalid",
			wantErr:  true,
		},
		{
			name:     "non-existent file",
			expected: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyDigest("/nonexistent/file", tt.expected)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyDigest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExpectedIdentity(t *testing.T) {
	// Test that ExpectedIdentity struct has required fields
	id := ExpectedIdentity{
		SourceRepositoryURI: "https://github.com/owner/repo",
		SourceRepositoryRef: "refs/tags/v1.0.0",
	}

	if id.SourceRepositoryURI == "" {
		t.Error("SourceRepositoryURI should be set")
	}
	if id.SourceRepositoryRef == "" {
		t.Error("SourceRepositoryRef should be set")
	}
}

func TestLockedSigner(t *testing.T) {
	// Test that LockedSigner struct has required fields
	signer := LockedSigner{
		Issuer:              "https://token.actions.githubusercontent.com",
		SourceRepositoryURI: "https://github.com/owner/repo",
		SourceRepositoryRef: "refs/tags/v1.0.0",
	}

	if signer.Issuer == "" {
		t.Error("Issuer should be set")
	}
	if signer.SourceRepositoryURI == "" {
		t.Error("SourceRepositoryURI should be set")
	}
	if signer.SourceRepositoryRef == "" {
		t.Error("SourceRepositoryRef should be set")
	}
}

func TestMatchSigner(t *testing.T) {
	tests := []struct {
		name     string
		result   *Result
		expected *LockedSigner
		wantErr  bool
	}{
		{
			name:     "nil expected",
			result:   &Result{Issuer: "issuer", SourceRepositoryURI: "uri", SourceRepositoryRef: "ref"},
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "issuer mismatch",
			result:   &Result{Issuer: "wrong", SourceRepositoryURI: "uri", SourceRepositoryRef: "ref"},
			expected: &LockedSigner{Issuer: "correct", SourceRepositoryURI: "uri", SourceRepositoryRef: "ref"},
			wantErr:  true,
		},
		{
			name:     "uri mismatch",
			result:   &Result{Issuer: "issuer", SourceRepositoryURI: "wrong", SourceRepositoryRef: "ref"},
			expected: &LockedSigner{Issuer: "issuer", SourceRepositoryURI: "correct", SourceRepositoryRef: "ref"},
			wantErr:  true,
		},
		{
			name:     "ref mismatch",
			result:   &Result{Issuer: "issuer", SourceRepositoryURI: "uri", SourceRepositoryRef: "wrong"},
			expected: &LockedSigner{Issuer: "issuer", SourceRepositoryURI: "uri", SourceRepositoryRef: "correct"},
			wantErr:  true,
		},
		{
			name:     "all match",
			result:   &Result{Issuer: "issuer", SourceRepositoryURI: "uri", SourceRepositoryRef: "ref"},
			expected: &LockedSigner{Issuer: "issuer", SourceRepositoryURI: "uri", SourceRepositoryRef: "ref"},
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := MatchSigner(tt.result, tt.expected)
			if (err != nil) != tt.wantErr {
				t.Errorf("MatchSigner() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
