package sign

import (
	"github.com/locktivity/epack/sign/sigstore"
	"github.com/sigstore/sigstore-go/pkg/bundle"
)

// Re-export sigstore package constants for convenience.
const (
	DefaultFulcioURL   = sigstore.DefaultFulcioURL
	DefaultRekorURL    = sigstore.DefaultRekorURL
	SigstoreOIDCIssuer = sigstore.SigstoreOIDCIssuer
	SigstoreClientID   = sigstore.SigstoreClientID
)

// MarshalBundle serializes a bundle to JSON.
func MarshalBundle(b *bundle.Bundle) ([]byte, error) {
	return sigstore.MarshalBundle(b)
}

// UnmarshalBundle deserializes a bundle from JSON.
func UnmarshalBundle(data []byte) (*bundle.Bundle, error) {
	return sigstore.UnmarshalBundle(data)
}
