package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestCompletionCmd_Exists(t *testing.T) {
	if completionCmd == nil {
		t.Fatal("completionCmd is nil")
	}

	if completionCmd.Use != "completion [bash|zsh|fish|powershell]" {
		t.Errorf("completionCmd.Use = %q, want %q", completionCmd.Use, "completion [bash|zsh|fish|powershell]")
	}

	if completionCmd.Short == "" {
		t.Error("completionCmd.Short is empty")
	}

	if completionCmd.Long == "" {
		t.Error("completionCmd.Long is empty")
	}

	if completionCmd.Run == nil {
		t.Error("completionCmd.Run is nil")
	}
}

func TestCompletionCmd_ValidArgs(t *testing.T) {
	expectedArgs := []string{"bash", "zsh", "fish", "powershell"}
	if len(completionCmd.ValidArgs) != len(expectedArgs) {
		t.Errorf("len(ValidArgs) = %d, want %d", len(completionCmd.ValidArgs), len(expectedArgs))
	}

	for i, arg := range expectedArgs {
		if completionCmd.ValidArgs[i] != arg {
			t.Errorf("ValidArgs[%d] = %q, want %q", i, completionCmd.ValidArgs[i], arg)
		}
	}
}

func TestCompletionCmd_DisableFlagsInUseLine(t *testing.T) {
	if !completionCmd.DisableFlagsInUseLine {
		t.Error("DisableFlagsInUseLine should be true")
	}
}

func TestCompletion_Bash(t *testing.T) {
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs([]string{"completion", "bash"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("completion bash failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "bash completion") || !strings.Contains(output, "epack") {
		t.Errorf("bash completion output doesn't contain expected content")
	}
}

func TestCompletion_Zsh(t *testing.T) {
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs([]string{"completion", "zsh"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("completion zsh failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "zsh") || !strings.Contains(output, "epack") {
		t.Errorf("zsh completion output doesn't contain expected content")
	}
}

func TestCompletion_Fish(t *testing.T) {
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs([]string{"completion", "fish"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("completion fish failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "fish") || !strings.Contains(output, "epack") {
		t.Errorf("fish completion output doesn't contain expected content")
	}
}

func TestCompletion_Powershell(t *testing.T) {
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs([]string{"completion", "powershell"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("completion powershell failed: %v", err)
	}

	output := buf.String()
	// PowerShell completion uses Register-ArgumentCompleter
	if !strings.Contains(output, "Register-ArgumentCompleter") || !strings.Contains(output, "epack") {
		t.Errorf("powershell completion output doesn't contain expected content")
	}
}

func TestCompletion_InvalidShell(t *testing.T) {
	var buf bytes.Buffer
	var errBuf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&errBuf)
	rootCmd.SetArgs([]string{"completion", "invalid"})

	err := rootCmd.Execute()
	if err == nil {
		t.Error("completion with invalid shell should return error")
	}
}

func TestCompletion_NoArgs(t *testing.T) {
	var buf bytes.Buffer
	var errBuf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&errBuf)
	rootCmd.SetArgs([]string{"completion"})

	err := rootCmd.Execute()
	if err == nil {
		t.Error("completion without args should return error")
	}
}

func TestCompletion_TooManyArgs(t *testing.T) {
	var buf bytes.Buffer
	var errBuf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&errBuf)
	rootCmd.SetArgs([]string{"completion", "bash", "extra"})

	err := rootCmd.Execute()
	if err == nil {
		t.Error("completion with too many args should return error")
	}
}

func TestCompletion_LongHelp(t *testing.T) {
	// Verify that the long help contains instructions for all supported shells
	shells := []string{"Bash:", "Zsh:", "Fish:", "PowerShell:"}
	for _, shell := range shells {
		if !strings.Contains(completionCmd.Long, shell) {
			t.Errorf("Long help should contain instructions for %s", shell)
		}
	}
}
