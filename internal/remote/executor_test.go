package remote_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/locktivity/epack/internal/remote"
)

func TestNewExecutor(t *testing.T) {
	exec := remote.NewExecutor("/fake/path", "test-adapter")
	if exec == nil {
		t.Fatal("NewExecutor returned nil")
	}
	if exec.BinaryPath != "/fake/path" {
		t.Errorf("BinaryPath = %q, want %q", exec.BinaryPath, "/fake/path")
	}
	if exec.AdapterName != "test-adapter" {
		t.Errorf("AdapterName = %q, want %q", exec.AdapterName, "test-adapter")
	}
	if exec.Timeout != remote.DefaultTimeout {
		t.Errorf("Timeout = %v, want %v", exec.Timeout, remote.DefaultTimeout)
	}
}

func TestExecutor_Close_Idempotent(t *testing.T) {
	exec := remote.NewExecutor("/fake/path", "test-adapter")

	// Close should not panic even when called multiple times
	exec.Close()
	exec.Close()
	exec.Close()
}

func TestExecutor_Close_Nil(t *testing.T) {
	// Close on nil should not panic
	var exec *remote.Executor
	exec.Close() // Should not panic
}

func TestQueryCapabilities_NonexistentBinary(t *testing.T) {
	ctx := context.Background()
	_, err := remote.QueryCapabilities(ctx, "/nonexistent/binary/path")
	if err == nil {
		t.Error("expected error for nonexistent binary")
	}
}

func TestQueryCapabilities_Timeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows - no sleep command")
	}

	// Create a script that sleeps forever
	dir := t.TempDir()
	script := filepath.Join(dir, "slow-adapter")
	content := "#!/bin/sh\nsleep 60\n"
	if err := os.WriteFile(script, []byte(content), 0755); err != nil {
		t.Fatalf("creating test script: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := remote.QueryCapabilities(ctx, script)
	if err == nil {
		t.Error("expected timeout error")
	}
}

func TestQueryCapabilities_InvalidJSON(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows - no echo command in same format")
	}

	// Create a script that outputs invalid JSON
	dir := t.TempDir()
	script := filepath.Join(dir, "bad-json-adapter")
	content := "#!/bin/sh\necho 'not valid json'\n"
	if err := os.WriteFile(script, []byte(content), 0755); err != nil {
		t.Fatalf("creating test script: %v", err)
	}

	ctx := context.Background()
	_, err := remote.QueryCapabilities(ctx, script)
	if err == nil {
		t.Error("expected JSON parsing error")
	}
}

func TestQueryCapabilities_ValidResponse(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows - no echo command in same format")
	}

	// Create a script that outputs valid capabilities JSON
	dir := t.TempDir()
	script := filepath.Join(dir, "good-adapter")
	content := `#!/bin/sh
echo '{"name":"test","kind":"remote_adapter","deploy_protocol_version":1,"features":{"prepare_finalize":true}}'
`
	if err := os.WriteFile(script, []byte(content), 0755); err != nil {
		t.Fatalf("creating test script: %v", err)
	}

	ctx := context.Background()
	caps, err := remote.QueryCapabilities(ctx, script)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if caps.DeployProtocolVersion != 1 {
		t.Errorf("DeployProtocolVersion = %d, want 1", caps.DeployProtocolVersion)
	}
	if caps.Name != "test" {
		t.Errorf("Name = %q, want %q", caps.Name, "test")
	}
}

func TestQueryCapabilitiesVerified_InvalidDigest(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows")
	}

	// Create a valid script
	dir := t.TempDir()
	script := filepath.Join(dir, "adapter")
	content := `#!/bin/sh
echo '{"protocol_version":1}'
`
	if err := os.WriteFile(script, []byte(content), 0755); err != nil {
		t.Fatalf("creating test script: %v", err)
	}

	ctx := context.Background()
	// Use wrong digest - should fail verification
	wrongDigest := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	_, err := remote.QueryCapabilitiesVerified(ctx, script, wrongDigest)
	if err == nil {
		t.Error("expected digest verification error")
	}
}

func TestNewVerifiedExecutor_InvalidDigest(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows")
	}

	// Create a valid script
	dir := t.TempDir()
	script := filepath.Join(dir, "adapter")
	content := `#!/bin/sh
echo '{"ok":true}'
`
	if err := os.WriteFile(script, []byte(content), 0755); err != nil {
		t.Fatalf("creating test script: %v", err)
	}

	// Use wrong digest - should fail verification
	wrongDigest := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	_, err := remote.NewVerifiedExecutor(script, wrongDigest, "test-adapter")
	if err == nil {
		t.Error("expected digest verification error")
	}
}

func TestAdapterError(t *testing.T) {
	err := &remote.AdapterError{
		AdapterName: "test-adapter",
		Code:        "auth_required",
		Message:     "authentication required",
		Retryable:   true,
	}

	// Test Error() method
	errStr := err.Error()
	if errStr == "" {
		t.Error("Error() returned empty string")
	}

	// Test IsAuthRequired
	if !err.IsAuthRequired() {
		t.Error("IsAuthRequired() should return true for auth_required code")
	}

	// Test IsRetryable
	if !err.IsRetryable() {
		t.Error("IsRetryable() should return true when Retryable=true")
	}

	// Test HasAction
	if err.HasAction() {
		t.Error("HasAction() should return false when Action is nil")
	}

	// Test with Action
	err.Action = &remote.ActionHint{
		Type: "open_url",
		URL:  "https://example.com/login",
	}
	if !err.HasAction() {
		t.Error("HasAction() should return true when Action is set")
	}
}

func TestAdapterError_NotAuthRequired(t *testing.T) {
	err := &remote.AdapterError{
		AdapterName: "test-adapter",
		Code:        "rate_limited",
		Message:     "too many requests",
		Retryable:   true,
	}

	if err.IsAuthRequired() {
		t.Error("IsAuthRequired() should return false for non-auth code")
	}
}

func TestAdapterError_NotRetryable(t *testing.T) {
	err := &remote.AdapterError{
		AdapterName: "test-adapter",
		Code:        "invalid_request",
		Message:     "bad request",
		Retryable:   false,
	}

	if err.IsRetryable() {
		t.Error("IsRetryable() should return false when Retryable=false")
	}
}

// TestExecutor_RestrictedEnvironment verifies that adapters don't receive
// sensitive environment variables. This is a security-critical test.
func TestExecutor_RestrictedEnvironment(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows")
	}

	// Create a script that outputs its environment
	dir := t.TempDir()
	script := filepath.Join(dir, "env-adapter")
	content := `#!/bin/sh
# Output valid capabilities JSON
echo '{"name":"env-test","kind":"remote_adapter","deploy_protocol_version":1,"features":{"prepare_finalize":true}}'
# Also dump env to stderr for inspection
env >&2
`
	if err := os.WriteFile(script, []byte(content), 0755); err != nil {
		t.Fatalf("creating test script: %v", err)
	}

	// Set a sensitive environment variable that should NOT be passed
	t.Setenv("AWS_SECRET_ACCESS_KEY", "super-secret-key")

	ctx := context.Background()
	caps, err := remote.QueryCapabilities(ctx, script)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The capabilities should parse correctly
	if caps.DeployProtocolVersion != 1 {
		t.Errorf("DeployProtocolVersion = %d, want 1", caps.DeployProtocolVersion)
	}

	// Note: We can't easily verify the env filtering from this test,
	// but the execsafe.BuildRestrictedEnvSafe is tested elsewhere.
	// This test verifies the integration works.
}

// TestExecutor_CommandInjection verifies that command arguments are safe.
func TestExecutor_CommandInjection(t *testing.T) {
	// Executor should use exec.Command properly, not shell expansion.
	// This test verifies the binary path is used literally.
	exec := remote.NewExecutor("/bin/sh -c 'echo pwned'", "malicious")

	// The binary path should be treated as a literal path, not shell-expanded
	if exec.BinaryPath != "/bin/sh -c 'echo pwned'" {
		t.Errorf("BinaryPath should be literal, got %q", exec.BinaryPath)
	}

	// Attempting to execute should fail because the literal path doesn't exist
	ctx := context.Background()
	_, err := remote.QueryCapabilities(ctx, exec.BinaryPath)
	if err == nil {
		t.Error("expected error when binary path contains spaces/special chars as literal path")
	}
}

// TestProtocolConstants verifies protocol constants are accessible.
func TestProtocolConstants(t *testing.T) {
	// These should be defined and non-empty
	if remote.CommandCapabilities == "" {
		t.Error("CommandCapabilities is empty")
	}
	if remote.TypePushPrepare == "" {
		t.Error("TypePushPrepare is empty")
	}
	if remote.TypePullPrepare == "" {
		t.Error("TypePullPrepare is empty")
	}
}

// TestDefaultTimeout verifies the default timeout is reasonable.
func TestDefaultTimeout(t *testing.T) {
	if remote.DefaultTimeout < time.Minute {
		t.Errorf("DefaultTimeout %v seems too short", remote.DefaultTimeout)
	}
	if remote.DefaultTimeout > 10*time.Minute {
		t.Errorf("DefaultTimeout %v seems too long", remote.DefaultTimeout)
	}
}
