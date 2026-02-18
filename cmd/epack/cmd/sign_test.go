package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/locktivity/epack/sign"
)

func TestLoadPrivateKey_EC(t *testing.T) {
	// Generate a test EC key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Encode as PEM
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("Failed to marshal key: %v", err)
	}

	pemBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	}

	// Write to temp file
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "ec-key.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	// Load the key
	loaded, err := sign.LoadPrivateKey(keyPath)
	if err != nil {
		t.Fatalf("sign.LoadPrivateKey() error: %v", err)
	}

	if loaded == nil {
		t.Fatal("sign.LoadPrivateKey() returned nil")
	}

	// Verify it's an ECDSA key
	if _, ok := loaded.(*ecdsa.PrivateKey); !ok {
		t.Errorf("loaded key is %T, want *ecdsa.PrivateKey", loaded)
	}
}

func TestLoadPrivateKey_PKCS8(t *testing.T) {
	// Generate a test EC key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Encode as PKCS8
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("Failed to marshal key: %v", err)
	}

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}

	// Write to temp file
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "pkcs8-key.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	// Load the key
	loaded, err := sign.LoadPrivateKey(keyPath)
	if err != nil {
		t.Fatalf("sign.LoadPrivateKey() error: %v", err)
	}

	if loaded == nil {
		t.Fatal("sign.LoadPrivateKey() returned nil")
	}
}

func TestLoadPrivateKey_InvalidPEM(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "invalid.pem")

	// Write non-PEM content
	if err := os.WriteFile(keyPath, []byte("not a pem file"), 0600); err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	_, err := sign.LoadPrivateKey(keyPath)
	if err == nil {
		t.Error("sign.LoadPrivateKey() expected error for invalid PEM, got nil")
	}
	if !strings.Contains(err.Error(), "no PEM block") {
		t.Errorf("error = %q, want containing 'no PEM block'", err.Error())
	}
}

func TestLoadPrivateKey_UnsupportedType(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "unsupported.pem")

	// Write PEM with unsupported type
	pemBlock := &pem.Block{
		Type:  "UNKNOWN KEY TYPE",
		Bytes: []byte("some data"),
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0600); err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	_, err := sign.LoadPrivateKey(keyPath)
	if err == nil {
		t.Error("sign.LoadPrivateKey() expected error for unsupported type, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported key type") {
		t.Errorf("error = %q, want containing 'unsupported key type'", err.Error())
	}
}

func TestLoadPrivateKey_FileNotFound(t *testing.T) {
	_, err := sign.LoadPrivateKey("/nonexistent/path/key.pem")
	if err == nil {
		t.Error("sign.LoadPrivateKey() expected error for missing file, got nil")
	}
}

func TestLoadPrivateKey_CorruptedEC(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "corrupted.pem")

	// Write PEM with EC type but garbage bytes
	pemBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: []byte("not a valid EC key"),
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0600); err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	_, err := sign.LoadPrivateKey(keyPath)
	if err == nil {
		t.Error("sign.LoadPrivateKey() expected error for corrupted key, got nil")
	}
	if !strings.Contains(err.Error(), "parsing EC private key") {
		t.Errorf("error = %q, want containing 'parsing EC private key'", err.Error())
	}
}

func TestSignCmd_Exists(t *testing.T) {
	if signCmd == nil {
		t.Fatal("signCmd is nil")
	}

	if signCmd.Use != "sign <pack>" {
		t.Errorf("signCmd.Use = %q, want %q", signCmd.Use, "sign <pack>")
	}

	if signCmd.Short == "" {
		t.Error("signCmd.Short is empty")
	}

	if signCmd.RunE == nil {
		t.Error("signCmd.RunE is nil")
	}
}

func TestSignCmd_Flags(t *testing.T) {
	flags := signCmd.Flags()

	// Check required flags exist
	requiredFlags := []string{"oidc-token", "key", "yes", "dry-run", "no-tlog", "tsa"}
	for _, name := range requiredFlags {
		if flags.Lookup(name) == nil {
			t.Errorf("signCmd missing flag: %s", name)
		}
	}

	// Check --yes has short flag -y
	yesFlag := flags.Lookup("yes")
	if yesFlag != nil && yesFlag.Shorthand != "y" {
		t.Errorf("--yes shorthand = %q, want %q", yesFlag.Shorthand, "y")
	}
}

func TestSignCmd_Examples(t *testing.T) {
	if signCmd.Long == "" {
		t.Error("signCmd.Long is empty")
	}

	// Check that examples are present
	examples := []string{
		"epack sign",
		"--key",
		"--yes",
		"--dry-run",
		"--no-tlog",
		"--tsa",
	}

	for _, example := range examples {
		if !strings.Contains(signCmd.Long, example) {
			t.Errorf("signCmd.Long missing example containing: %s", example)
		}
	}
}

// Security regression tests

func TestSignCmd_RequiresExplicitCustomEndpoints(t *testing.T) {
	// Verify that the --insecure-allow-custom-endpoints flag exists
	// This is a security requirement to prevent auto-enabling unsafe endpoints
	flags := signCmd.Flags()

	allowCustomFlag := flags.Lookup("insecure-allow-custom-endpoints")
	if allowCustomFlag == nil {
		t.Fatal("signCmd missing --insecure-allow-custom-endpoints flag")
	}

	// Verify default is false (secure by default)
	if allowCustomFlag.DefValue != "false" {
		t.Errorf("--insecure-allow-custom-endpoints default = %q, want %q", allowCustomFlag.DefValue, "false")
	}
}

func TestSignCmd_TSARequiresAllowCustomEndpoints(t *testing.T) {
	// Verify that the help text explains TSA requires --insecure-allow-custom-endpoints
	if signCmd.Long == "" {
		t.Fatal("signCmd.Long is empty")
	}

	// The help should show that TSA with custom endpoints requires explicit opt-in
	if !strings.Contains(signCmd.Long, "--insecure-allow-custom-endpoints") {
		t.Error("signCmd.Long should mention --insecure-allow-custom-endpoints requirement for --tsa")
	}
}

func TestSignCmd_SecurityFlags(t *testing.T) {
	// Verify all security-relevant flags exist
	flags := signCmd.Flags()

	securityFlags := []string{
		"no-tlog",                // Skip transparency log
		"tsa",                    // Custom TSA
		"insecure-allow-custom-endpoints", // Explicit opt-in for custom endpoints
	}

	for _, name := range securityFlags {
		if flags.Lookup(name) == nil {
			t.Errorf("signCmd missing security-relevant flag: %s", name)
		}
	}
}
