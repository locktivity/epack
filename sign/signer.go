// Package sign provides Sigstore signing for evidence packs.
package sign

import (
	"context"

	"github.com/sigstore/sigstore-go/pkg/bundle"
)

// Signer signs evidence packs using Sigstore.
type Signer interface {
	// Sign creates a Sigstore bundle for the given in-toto statement JSON.
	Sign(ctx context.Context, statement []byte) (*bundle.Bundle, error)

	// Identity returns the signer's identity (email, URI, or key fingerprint).
	Identity() string
}
