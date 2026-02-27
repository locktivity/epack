package sign

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// MaxPrivateKeySize is the maximum size of a private key file.
// Private keys are typically small (< 10KB even for RSA 4096).
// This limit prevents memory exhaustion from malicious paths.
const MaxPrivateKeySize = 64 * 1024 // 64 KB

// LoadPrivateKey loads a PEM-encoded private key from a file.
// Supports EC, PKCS8, and RSA private key formats.
func LoadPrivateKey(path string) (crypto.Signer, error) {
	data, err := readPrivateKeyFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	return parsePEMPrivateKey(block)
}

func readPrivateKeyFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}
	if info.Size() > MaxPrivateKeySize {
		return nil, fmt.Errorf("key file too large: %d bytes exceeds limit of %d bytes", info.Size(), MaxPrivateKeySize)
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
