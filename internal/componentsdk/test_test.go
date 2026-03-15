package componentsdk

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestBuildConformanceCommand_NormalizesKind(t *testing.T) {
	tempDir := t.TempDir()
	binaryName := "epack-conformance"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}

	conformancePath := filepath.Join(tempDir, binaryName)
	if err := os.WriteFile(conformancePath, []byte("stub"), 0o755); err != nil {
		t.Fatalf("write conformance stub: %v", err)
	}

	t.Setenv("PATH", tempDir)

	tests := []struct {
		name string
		kind string
		want string
	}{
		{name: "remote adapter", kind: "remote_adapter", want: "remote"},
		{name: "collector", kind: "collector", want: "collector"},
		{name: "tool", kind: "tool", want: "tool"},
		{name: "utility", kind: "utility", want: "utility"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, err := buildConformanceCommand(context.Background(), tt.kind, "./component", false)
			if err != nil {
				t.Fatalf("buildConformanceCommand returned error: %v", err)
			}
			if len(cmd.Args) != 3 {
				t.Fatalf("expected 3 args, got %d: %#v", len(cmd.Args), cmd.Args)
			}
			if got := cmd.Args[1]; got != tt.want {
				t.Fatalf("expected normalized kind %q, got %q", tt.want, got)
			}
			if got := cmd.Args[2]; got != "./component" {
				t.Fatalf("expected binary path ./component, got %q", got)
			}
		})
	}
}
