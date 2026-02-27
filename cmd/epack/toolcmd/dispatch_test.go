//go:build components

package toolcmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/dispatch"
	"github.com/locktivity/epack/internal/securityaudit"
	"github.com/locktivity/epack/internal/securitypolicy"
	"github.com/locktivity/epack/internal/toolprotocol"
	"github.com/spf13/cobra"
)

// mockCmd creates a cobra command with captured stderr for testing.
// The command is set up with a background context for proper context propagation.
func mockCmd() (*cobra.Command, *bytes.Buffer) {
	cmd := &cobra.Command{}
	stderr := &bytes.Buffer{}
	cmd.SetErr(stderr)
	cmd.SetContext(context.Background())
	return cmd, stderr
}

type dispatchAuditSink struct {
	mu     sync.Mutex
	events []securityaudit.Event
}

func (s *dispatchAuditSink) HandleSecurityEvent(evt securityaudit.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, evt)
}

func (s *dispatchAuditSink) Snapshot() []securityaudit.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]securityaudit.Event, len(s.events))
	copy(out, s.events)
	return out
}

func TestDispatchTool_ToolNotFound(t *testing.T) {
	// Create a temp directory for packless runs
	tmpDir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", tmpDir)

	cmd, _ := mockCmd()

	// Try to dispatch a tool that doesn't exist and isn't in lockfile
	err := dispatchTool(cmd, "nonexistent", []string{})

	// Should return an exit error with code 10 (tool not found)
	exitErr, ok := err.(*exitError)
	if !ok {
		t.Fatalf("expected *exitError, got %T: %v", err, err)
	}
	if exitErr.code != componenttypes.ExitLockfileMissing {
		t.Errorf("expected exit code %d, got %d", componenttypes.ExitLockfileMissing, exitErr.code)
	}

	// Should have created a run directory with result.json
	runDirs, err := filepath.Glob(filepath.Join(tmpDir, "epack", "runs", "nonexistent", "*"))
	if err != nil {
		t.Fatalf("glob error: %v", err)
	}
	if len(runDirs) != 1 {
		t.Fatalf("expected 1 run directory, got %d", len(runDirs))
	}

	// Read and validate result.json
	resultPath := filepath.Join(runDirs[0], "result.json")
	data, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatalf("failed to read result.json: %v", err)
	}

	var result toolprotocol.Result
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to parse result.json: %v", err)
	}

	if result.ExitCode != componenttypes.ExitLockfileMissing {
		t.Errorf("result.exit_code: expected %d, got %d", componenttypes.ExitLockfileMissing, result.ExitCode)
	}
	if result.Status != toolprotocol.StatusFailure {
		t.Errorf("result.status: expected %q, got %q", toolprotocol.StatusFailure, result.Status)
	}
	if len(result.Errors) != 1 {
		t.Fatalf("result.errors: expected 1 error, got %d", len(result.Errors))
	}
	if result.Errors[0].Code != componenttypes.ErrCodeLockfileError {
		t.Errorf("error code: expected %q, got %q", componenttypes.ErrCodeLockfileError, result.Errors[0].Code)
	}
}

func TestParseWrapperArgs(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		wantPack     string
		wantOutput   string
		wantJSON     bool
		wantQuiet    bool
		wantToolArgs []string
		wantErr      bool
	}{
		{
			name:         "pack with separator",
			args:         []string{"--pack", "vendor.epack", "--", "-q"},
			wantPack:     "vendor.epack",
			wantToolArgs: []string{"-q"},
		},
		{
			name:     "pack equals syntax",
			args:     []string{"--pack=vendor.epack"},
			wantPack: "vendor.epack",
		},
		{
			name:     "short pack flag",
			args:     []string{"-p", "vendor.epack"},
			wantPack: "vendor.epack",
		},
		{
			name:      "json and quiet flags",
			args:      []string{"--json", "--quiet"},
			wantJSON:  true,
			wantQuiet: true,
		},
		{
			name:       "output-dir flag",
			args:       []string{"--output-dir", "/tmp/out"},
			wantOutput: "/tmp/out",
		},
		{
			name:    "pack without argument",
			args:    []string{"--pack"},
			wantErr: true,
		},
		{
			name:         "unknown flags passed to tool",
			args:         []string{"--unknown", "value"},
			wantToolArgs: []string{"--unknown", "value"},
		},
		{
			name:     "positional pack argument",
			args:     []string{"evidence.epack"},
			wantPack: "evidence.epack",
		},
		{
			name:         "positional pack with tool args",
			args:         []string{"evidence.epack", "--config", "custom.yaml"},
			wantPack:     "evidence.epack",
			wantToolArgs: []string{"--config", "custom.yaml"},
		},
		{
			name:         "pack flag takes precedence over positional",
			args:         []string{"--pack", "flag.epack", "positional.epack"},
			wantPack:     "flag.epack",
			wantToolArgs: []string{"positional.epack"},
		},
		{
			name:         "non-epack positional goes to tool",
			args:         []string{"config.yaml"},
			wantToolArgs: []string{"config.yaml"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags, toolArgs, err := dispatch.ParseWrapperArgs(tt.args)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if flags.PackPath != tt.wantPack {
				t.Errorf("PackPath: expected %q, got %q", tt.wantPack, flags.PackPath)
			}
			if flags.OutputDir != tt.wantOutput {
				t.Errorf("OutputDir: expected %q, got %q", tt.wantOutput, flags.OutputDir)
			}
			if flags.JSONMode != tt.wantJSON {
				t.Errorf("JSONMode: expected %v, got %v", tt.wantJSON, flags.JSONMode)
			}
			if flags.QuietMode != tt.wantQuiet {
				t.Errorf("QuietMode: expected %v, got %v", tt.wantQuiet, flags.QuietMode)
			}

			if len(toolArgs) != len(tt.wantToolArgs) {
				t.Errorf("toolArgs length: expected %d, got %d", len(tt.wantToolArgs), len(toolArgs))
			} else {
				for i, want := range tt.wantToolArgs {
					if toolArgs[i] != want {
						t.Errorf("toolArgs[%d]: expected %q, got %q", i, want, toolArgs[i])
					}
				}
			}
		})
	}
}

func TestWrapperExitCodes(t *testing.T) {
	// Verify exit code constants match the spec
	tests := []struct {
		name     string
		code     int
		expected int
	}{
		{"ComponentNotFound", componenttypes.ExitComponentNotFound, 10},
		{"VerifyFailed", componenttypes.ExitVerifyFailed, 11},
		{"PackVerifyFailed", componenttypes.ExitPackVerifyFailed, 12},
		{"LockfileMissing", componenttypes.ExitLockfileMissing, 13},
		{"RunDirFailed", componenttypes.ExitRunDirFailed, 14},
		{"ConfigFailed", componenttypes.ExitConfigFailed, 15},
		{"PackRequired", componenttypes.ExitPackRequired, 16},
		{"DependencyMissing", componenttypes.ExitDependencyMissing, 17},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.code != tt.expected {
				t.Errorf("%s: expected %d, got %d", tt.name, tt.expected, tt.code)
			}
		})
	}
}

func TestFindProjectRoot(t *testing.T) {
	// Create a temp directory with epack.yaml
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "epack.yaml")
	if err := os.WriteFile(configPath, []byte("collectors: []"), 0644); err != nil {
		t.Fatalf("failed to write epack.yaml: %v", err)
	}

	// Create a subdirectory
	subDir := filepath.Join(tmpDir, "sub", "nested")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("failed to create subdir: %v", err)
	}

	// Search from subdirectory should find project root
	found, err := findProjectRoot(subDir)
	if err != nil {
		t.Fatalf("findProjectRoot error: %v", err)
	}
	if found != tmpDir {
		t.Errorf("findProjectRoot: expected %q, got %q", tmpDir, found)
	}

	// Search from directory without epack.yaml should fail
	otherDir := t.TempDir()
	_, err = findProjectRoot(otherDir)
	if err == nil {
		t.Error("expected error when no epack.yaml exists")
	}
}

func TestValidateDispatchFlags_EmitsInsecureBypassWhenAllowed(t *testing.T) {
	t.Setenv(securitypolicy.StrictProductionEnvVar, "")

	sink := &dispatchAuditSink{}
	securityaudit.SetSink(sink)
	t.Cleanup(func() { securityaudit.SetSink(nil) })

	if err := validateDispatchFlags(true); err != nil {
		t.Fatalf("validateDispatchFlags(true) error = %v", err)
	}
	for _, evt := range sink.Snapshot() {
		if evt.Type == securityaudit.EventInsecureBypass && evt.Component == "dispatch" {
			return
		}
	}
	t.Fatalf("expected insecure bypass event, got: %+v", sink.Snapshot())
}

func TestValidateDispatchFlags_StrictProductionBlocksInsecure(t *testing.T) {
	t.Setenv(securitypolicy.StrictProductionEnvVar, "1")

	err := validateDispatchFlags(true)
	if err == nil {
		t.Fatal("expected strict production enforcement error")
	}
	if !strings.Contains(err.Error(), "strict production mode forbids insecure execution overrides") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateDispatchFlags_AllowsSecure(t *testing.T) {
	t.Setenv(securitypolicy.StrictProductionEnvVar, "1")

	if err := validateDispatchFlags(false); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestParseWrapperArgs_EnvPrecedence(t *testing.T) {
	tests := []struct {
		name         string
		envPack      string
		args         []string
		wantPack     string
		wantToolArgs []string
	}{
		{
			name:         "env pack takes precedence over positional",
			envPack:      "env.epack",
			args:         []string{"positional.epack"},
			wantPack:     "env.epack",
			wantToolArgs: []string{"positional.epack"},
		},
		{
			name:         "cli flag overrides env",
			envPack:      "env.epack",
			args:         []string{"--pack", "flag.epack"},
			wantPack:     "flag.epack",
			wantToolArgs: nil,
		},
		{
			name:         "env pack with additional tool args",
			envPack:      "env.epack",
			args:         []string{"positional.epack", "--config", "custom.yaml"},
			wantPack:     "env.epack",
			wantToolArgs: []string{"positional.epack", "--config", "custom.yaml"},
		},
		{
			name:         "no env with positional uses positional",
			envPack:      "",
			args:         []string{"positional.epack"},
			wantPack:     "positional.epack",
			wantToolArgs: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("EPACK_PACK", tt.envPack)

			flags, toolArgs, err := dispatch.ParseWrapperArgs(tt.args)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if flags.PackPath != tt.wantPack {
				t.Errorf("PackPath: expected %q, got %q", tt.wantPack, flags.PackPath)
			}

			if len(toolArgs) != len(tt.wantToolArgs) {
				t.Errorf("toolArgs length: expected %d, got %d", len(tt.wantToolArgs), len(toolArgs))
			} else {
				for i, want := range tt.wantToolArgs {
					if toolArgs[i] != want {
						t.Errorf("toolArgs[%d]: expected %q, got %q", i, want, toolArgs[i])
					}
				}
			}
		})
	}
}
