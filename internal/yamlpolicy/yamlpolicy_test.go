package yamlpolicy

import (
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/limits"
	"gopkg.in/yaml.v3"
)

func TestCheckAliasAbuse_NoAliases(t *testing.T) {
	data := []byte(`
name: test
values:
  - one
  - two
`)
	if err := CheckAliasAbuse(data); err != nil {
		t.Errorf("expected no error for YAML without aliases, got: %v", err)
	}
}

func TestCheckAliasAbuse_NormalAliasUsage(t *testing.T) {
	// Normal usage: one anchor, one or two aliases
	data := []byte(`
defaults: &defaults
  timeout: 30
  retries: 3

production:
  <<: *defaults
  timeout: 60

staging:
  <<: *defaults
`)
	if err := CheckAliasAbuse(data); err != nil {
		t.Errorf("expected no error for normal alias usage, got: %v", err)
	}
}

func TestCheckAliasAbuse_DetectsBomb(t *testing.T) {
	// Construct valid YAML with many aliases pointing to few anchors
	// This simulates an alias bomb pattern using valid YAML syntax
	var sb strings.Builder
	sb.WriteString("anchor: &a [1,2,3]\n")
	sb.WriteString("explosion:\n")
	// Write more aliases than the limit allows (MaxYAMLAliasExpansion = 10)
	// We need > 10 aliases for 1 anchor to trigger the check
	// Using "key: *a" format for valid YAML map entries
	for i := 0; i < limits.MaxYAMLAliasExpansion+5; i++ {
		sb.WriteString("  item")
		sb.WriteString(strings.Repeat("x", i)) // unique key
		sb.WriteString(": *a\n")
	}

	data := []byte(sb.String())
	err := CheckAliasAbuse(data)
	if err == nil {
		t.Error("expected error for alias bomb pattern, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "alias bomb") {
		t.Errorf("expected error to mention 'alias bomb', got: %v", err)
	}
}

func TestCheckAliasAbuse_InvalidYAML(t *testing.T) {
	// Invalid YAML should not error here - let main parser report it
	data := []byte(`{invalid yaml: [`)
	if err := CheckAliasAbuse(data); err != nil {
		t.Errorf("expected no error for invalid YAML (let main parser handle it), got: %v", err)
	}
}

func TestValidateBeforeParse_SizeLimit(t *testing.T) {
	data := []byte("name: test")

	// Within limit
	if err := ValidateBeforeParse(data, 100); err != nil {
		t.Errorf("expected no error within size limit, got: %v", err)
	}

	// Exceeds limit
	err := ValidateBeforeParse(data, 5)
	if err == nil {
		t.Error("expected error for data exceeding size limit, got nil")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("expected error to mention 'too large', got: %v", err)
	}
}

func TestValidateBeforeParse_AliasBomb(t *testing.T) {
	// Construct valid YAML with many aliases pointing to few anchors
	var sb strings.Builder
	sb.WriteString("anchor: &a [1]\n")
	sb.WriteString("refs:\n")
	for i := 0; i < limits.MaxYAMLAliasExpansion+5; i++ {
		sb.WriteString("  key")
		sb.WriteString(strings.Repeat("x", i)) // unique key
		sb.WriteString(": *a\n")
	}
	data := []byte(sb.String())

	err := ValidateBeforeParse(data, 1<<20) // Large size limit
	if err == nil {
		t.Error("expected error for alias bomb, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "alias bomb") {
		t.Errorf("expected error to mention 'alias bomb', got: %v", err)
	}
}

func TestCountAliasesInNode(t *testing.T) {
	data := []byte(`
anchor1: &a1 value1
anchor2: &a2 value2
ref1: *a1
ref2: *a2
ref3: *a1
`)
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		t.Fatalf("failed to parse test YAML: %v", err)
	}

	anchors, aliases := CountAliasesInNode(&root)
	if anchors != 2 {
		t.Errorf("expected 2 anchors, got %d", anchors)
	}
	if aliases != 3 {
		t.Errorf("expected 3 aliases, got %d", aliases)
	}
}
