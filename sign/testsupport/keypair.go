// Package testsupport provides test-only helpers for the sign package.
//
// This package is intended for use in tests only. Do not import this
// package in production code.
package testsupport

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

// NewTestKeypair creates a new ECDSA P-256 keypair for testing.
// Generates ephemeral keys - do not use for production signing.
func NewTestKeypair() (crypto.Signer, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
