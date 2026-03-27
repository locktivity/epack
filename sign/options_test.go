package sign

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/broker"
	"github.com/locktivity/epack/sign/sigstore"
)

func TestNewSignerFromOptions_UsesAmbientGitHubActionsOIDC(t *testing.T) {
	originalResolver := ambientOIDCTokenResolver
	defer func() { ambientOIDCTokenResolver = originalResolver }()

	ambientOIDCTokenResolver = func(_ context.Context, audience string) (string, error) {
		if audience != sigstore.SigstoreClientID {
			t.Fatalf("audience = %q, want %q", audience, sigstore.SigstoreClientID)
		}
		return "ambient-token", nil
	}
	_ = os.Unsetenv("EPACK_OIDC_TOKEN")

	signer, err := NewSignerFromOptions(context.Background(), SignPackOptions{Interactive: false})
	if err != nil {
		t.Fatalf("NewSignerFromOptions() error = %v", err)
	}
	if signer == nil {
		t.Fatal("NewSignerFromOptions() returned nil signer")
	}
}

func TestNewSignerFromOptions_ReportsUnavailableAmbientOIDC(t *testing.T) {
	originalResolver := ambientOIDCTokenResolver
	defer func() { ambientOIDCTokenResolver = originalResolver }()

	ambientOIDCTokenResolver = func(context.Context, string) (string, error) {
		return "", broker.ErrOIDCUnavailable
	}
	_ = os.Unsetenv("EPACK_OIDC_TOKEN")

	_, err := NewSignerFromOptions(context.Background(), SignPackOptions{Interactive: false})
	if err == nil {
		t.Fatal("NewSignerFromOptions() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "ambient OIDC is unavailable") {
		t.Fatalf("error = %q, want ambient OIDC guidance", err.Error())
	}
}

func TestNewSignerFromOptions_UsesExplicitOIDCTokenBeforeAmbient(t *testing.T) {
	originalResolver := ambientOIDCTokenResolver
	defer func() { ambientOIDCTokenResolver = originalResolver }()

	ambientOIDCTokenResolver = func(context.Context, string) (string, error) {
		return "", errors.New("ambient resolver should not be called")
	}

	signer, err := NewSignerFromOptions(context.Background(), SignPackOptions{
		OIDCToken:   "explicit-token",
		Interactive: false,
	})
	if err != nil {
		t.Fatalf("NewSignerFromOptions() error = %v", err)
	}
	if signer == nil {
		t.Fatal("NewSignerFromOptions() returned nil signer")
	}
}
