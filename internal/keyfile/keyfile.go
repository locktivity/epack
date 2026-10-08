// Package keyfile loads PEM private keys and fingerprints public keys. It
// sits below sign, which imports the credential broker, so the broker reads a
// signing key exactly the way sign does.
package keyfile

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// MaxSize is the maximum size of a key file.
// Private keys are typically small (< 10KB even for RSA 4096).
// This limit prevents memory exhaustion from malicious paths.
const MaxSize = 64 * 1024 // 64 KB

// LoadPrivateKey loads a PEM-encoded private key from a file.
// Supports EC, PKCS8, and RSA private key formats.
func LoadPrivateKey(path string) (crypto.Signer, error) {
	data, err := Read(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	return parsePEMPrivateKey(block)
}

// Read reads a key file no larger than MaxSize.
func Read(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}
	if info.Size() > MaxSize {
		return nil, fmt.Errorf("key file too large: %d bytes exceeds limit of %d bytes", info.Size(), MaxSize)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}
	return data, nil
}

func parsePEMPrivateKey(block *pem.Block) (crypto.Signer, error) {
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing EC private key: %w", err)
		}
		return key, nil
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing PKCS8 private key: %w", err)
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("key type %T does not implement crypto.Signer", key)
		}
		return signer, nil
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing RSA private key: %w", err)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}
}

// Fingerprint is the hex SHA-256 of a public key's PKIX DER encoding, the
// identity a remote records for a registered key and a signature names.
func Fingerprint(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("encoding public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return fmt.Sprintf("%x", sum), nil
}
