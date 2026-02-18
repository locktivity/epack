package component

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/locktivity/epack/internal/component/sync"
	"github.com/locktivity/epack/internal/componenttypes"
)

func TestComputeDigest(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test file with known content
	content := []byte("hello world\n")
	path := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	digest, err := sync.ComputeDigest(path)
	if err != nil {
		t.Fatalf("ComputeDigest() error: %v", err)
	}

	// sha256 of "hello world\n"
	want := "sha256:a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447"
	if digest != want {
		t.Errorf("digest = %q, want %q", digest, want)
	}
}

func TestComputeDigestNotFound(t *testing.T) {
	_, err := sync.ComputeDigest("/nonexistent/path")
	if err == nil {
		t.Error("ComputeDigest() expected error for nonexistent file, got nil")
	}
}

func TestVerifyDigest(t *testing.T) {
	tmpDir := t.TempDir()

	content := []byte("test content")
	path := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	// Get the correct digest
	correctDigest, err := sync.ComputeDigest(path)
	if err != nil {
		t.Fatalf("ComputeDigest() error: %v", err)
	}

	// Verify with correct digest should succeed
	if err := sync.VerifyDigest(path, correctDigest); err != nil {
		t.Errorf("VerifyDigest() with correct digest failed: %v", err)
	}

	// Verify with wrong digest should fail
	wrongDigest := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	if err := sync.VerifyDigest(path, wrongDigest); err == nil {
		t.Error("VerifyDigest() with wrong digest expected error, got nil")
	}
}

func TestVerifyDigestNonexistent(t *testing.T) {
	err := sync.VerifyDigest("/nonexistent/path", "sha256:abc")
	if err == nil {
		t.Error("VerifyDigest() expected error for nonexistent file, got nil")
	}
}

func TestMatchSigner(t *testing.T) {
	tests := []struct {
		name     string
		result   *sync.SigstoreResult
		expected *componenttypes.LockedSigner
		wantErr  bool
	}{
		{
			name: "exact match",
			result: &sync.SigstoreResult{
				Issuer:              "https://token.actions.githubusercontent.com",
				SourceRepositoryURI: "https://github.com/owner/repo",
				SourceRepositoryRef: "refs/tags/v1.0.0",
			},
			expected: &componenttypes.LockedSigner{
				Issuer:              "https://token.actions.githubusercontent.com",
				SourceRepositoryURI: "https://github.com/owner/repo",
				SourceRepositoryRef: "refs/tags/v1.0.0",
			},
			wantErr: false,
		},
		{
			name: "issuer mismatch",
			result: &sync.SigstoreResult{
				Issuer:              "https://accounts.google.com",
				SourceRepositoryURI: "https://github.com/owner/repo",
				SourceRepositoryRef: "refs/tags/v1.0.0",
			},
			expected: &componenttypes.LockedSigner{
				Issuer:              "https://token.actions.githubusercontent.com",
				SourceRepositoryURI: "https://github.com/owner/repo",
				SourceRepositoryRef: "refs/tags/v1.0.0",
			},
			wantErr: true,
		},
		{
			name: "repository URI mismatch",
			result: &sync.SigstoreResult{
				Issuer:              "https://token.actions.githubusercontent.com",
				SourceRepositoryURI: "https://github.com/other/repo",
				SourceRepositoryRef: "refs/tags/v1.0.0",
			},
			expected: &componenttypes.LockedSigner{
				Issuer:              "https://token.actions.githubusercontent.com",
				SourceRepositoryURI: "https://github.com/owner/repo",
				SourceRepositoryRef: "refs/tags/v1.0.0",
			},
			wantErr: true,
		},
		{
			name: "ref mismatch",
			result: &sync.SigstoreResult{
				Issuer:              "https://token.actions.githubusercontent.com",
				SourceRepositoryURI: "https://github.com/owner/repo",
				SourceRepositoryRef: "refs/tags/v2.0.0",
			},
			expected: &componenttypes.LockedSigner{
				Issuer:              "https://token.actions.githubusercontent.com",
				SourceRepositoryURI: "https://github.com/owner/repo",
				SourceRepositoryRef: "refs/tags/v1.0.0",
			},
			wantErr: true,
		},
		{
			name: "nil expected signer",
			result: &sync.SigstoreResult{
				Issuer: "https://token.actions.githubusercontent.com",
			},
			expected: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sync.MatchSigner(tt.result, tt.expected)
			if tt.wantErr {
				if err == nil {
					t.Error("MatchSigner() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("MatchSigner() unexpected error: %v", err)
				}
			}
		})
	}
}
