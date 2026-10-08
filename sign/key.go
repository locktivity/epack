package sign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/locktivity/epack/internal/keyfile"
	"github.com/locktivity/epack/internal/safefile"
)

// MaxPrivateKeySize is the maximum size of a private key file.
// Private keys are typically small (< 10KB even for RSA 4096).
// This limit prevents memory exhaustion from malicious paths.
const MaxPrivateKeySize = keyfile.MaxSize

// LoadPrivateKey loads a PEM-encoded private key from a file.
// Supports EC, PKCS8, and RSA private key formats.
func LoadPrivateKey(path string) (crypto.Signer, error) {
	return keyfile.LoadPrivateKey(path)
}

// LoadPublicKey loads a PEM-encoded public key from a file: a PKIX
// "PUBLIC KEY" block or a PKCS#1 "RSA PUBLIC KEY" block.
func LoadPublicKey(path string) (crypto.PublicKey, error) {
	data, err := keyfile.Read(path)
	if err != nil {
		return nil, err
	}
	key, err := ParsePublicKeyPEM(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return key, nil
}

// ParsePublicKeyPEM parses a PEM-encoded public key.
func ParsePublicKeyPEM(data []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	switch block.Type {
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing public key: %w", err)
		}
		return key, nil
	case "RSA PUBLIC KEY":
		key, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing RSA public key: %w", err)
		}
		return key, nil
	case "EC PRIVATE KEY", "PRIVATE KEY", "RSA PRIVATE KEY":
		return nil, fmt.Errorf("expected a public key, found a private key")
	default:
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}
}

// GenerateKey makes an ECDSA P-256 signing key, the kind a remote registers
// for a machine.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}
	return key, nil
}

// MarshalPrivateKeyPEM encodes an EC private key as an "EC PRIVATE KEY" block.
func MarshalPrivateKeyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encoding private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// MarshalPublicKeyPEM encodes a public key as a PKIX "PUBLIC KEY" block.
func MarshalPublicKeyPEM(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("encoding public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// Fingerprint is the hex SHA-256 of a public key's PKIX DER encoding, the
// identity a remote records for a registered key and a signature names.
func Fingerprint(pub crypto.PublicKey) (string, error) {
	return keyfile.Fingerprint(pub)
}

// SavePrivateKey writes a PEM-encoded private key readable only by its
// owner, replacing any file already there in one step.
func SavePrivateKey(path string, pemBytes []byte) error {
	dir := filepath.Dir(path)
	if err := safefile.MkdirAllPrivate(filepath.Dir(dir), dir); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("writing key: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("writing key: %w", err)
	}
	if _, err := tmp.Write(pemBytes); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("writing key: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("writing key: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("writing key: %w", err)
	}
	return nil
}
