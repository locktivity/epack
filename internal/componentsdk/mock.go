package componentsdk

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/locktivity/epack/internal/componenttypes"
)

// MockOptions configures mock generation.
type MockOptions struct {
	// OutputDir is where to write the generated files.
	OutputDir string

	// Kind is the component kind to generate mocks for.
	Kind componenttypes.ComponentKind
}

// MockResult contains the result of mock generation.
type MockResult struct {
	// FilesCreated is the list of files created.
	FilesCreated []string
}

// GenerateMocks creates sample input files for testing components.
func GenerateMocks(opts MockOptions) (*MockResult, error) {
	// Create output directory if needed
	if err := os.MkdirAll(opts.OutputDir, 0755); err != nil {
		return nil, fmt.Errorf("creating output directory: %w", err)
	}

	var files []string
	var err error

	switch opts.Kind {
	case componenttypes.KindTool:
		files, err = generateToolMocks(opts.OutputDir)
	case componenttypes.KindCollector:
		files, err = generateCollectorMocks(opts.OutputDir)
	case componenttypes.KindRemote:
		files, err = generateRemoteMocks(opts.OutputDir)
	case componenttypes.KindUtility:
		files, err = generateUtilityMocks(opts.OutputDir)
	default:
		return nil, fmt.Errorf("unsupported component type: %s", opts.Kind)
	}

	if err != nil {
		return nil, err
	}

	return &MockResult{FilesCreated: files}, nil
}

// generateToolMocks creates mock inputs for testing tools.
func generateToolMocks(outputDir string) ([]string, error) {
	var files []string

	// Create a minimal evidence pack structure (as a directory for now)
	packDir := filepath.Join(outputDir, "sample-evidence")
	if err := os.MkdirAll(packDir, 0755); err != nil {
		return nil, fmt.Errorf("creating pack directory: %w", err)
	}

	// Create manifest.yaml
	manifestPath := filepath.Join(packDir, "manifest.yaml")
	manifestContent := `# Sample evidence pack manifest for testing tools
schema_version: 1
name: sample-evidence
description: Sample evidence pack for component development
created_at: 2024-01-01T00:00:00Z
collectors:
  - name: sample-collector
    version: v1.0.0
`
	if err := os.WriteFile(manifestPath, []byte(manifestContent), 0644); err != nil {
		return nil, fmt.Errorf("writing manifest: %w", err)
	}
	files = append(files, manifestPath)

	// Create sample evidence file
	evidenceDir := filepath.Join(packDir, "evidence")
	if err := os.MkdirAll(evidenceDir, 0755); err != nil {
		return nil, fmt.Errorf("creating evidence directory: %w", err)
	}

	samplePath := filepath.Join(evidenceDir, "sample.json")
	sampleContent := `{
  "timestamp": "2024-01-01T00:00:00Z",
  "collector": "sample-collector",
  "data": {
    "example_field": "example_value",
    "secret_field": "AKIAIOSFODNN7EXAMPLE"
  }
}
`
	if err := os.WriteFile(samplePath, []byte(sampleContent), 0644); err != nil {
		return nil, fmt.Errorf("writing sample evidence: %w", err)
	}
	files = append(files, samplePath)

	// Create a test script
	scriptPath := filepath.Join(outputDir, "test-tool.sh")
	scriptContent := `#!/bin/bash
# Test script for running your tool against sample evidence
#
# Usage: ./test-tool.sh ./your-tool-binary

TOOL="${1:?Usage: $0 <tool-binary>}"
PACK_DIR="$(dirname "$0")/sample-evidence"

echo "Testing tool: $TOOL"
echo "Input pack: $PACK_DIR"
echo ""

# Run the tool (adjust arguments as needed for your tool)
"$TOOL" --pack "$PACK_DIR"
`
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0755); err != nil {
		return nil, fmt.Errorf("writing test script: %w", err)
	}
	files = append(files, scriptPath)

	return files, nil
}

// generateCollectorMocks creates mock inputs for testing collectors.
func generateCollectorMocks(outputDir string) ([]string, error) {
	var files []string

	// Create sample configuration
	configPath := filepath.Join(outputDir, "sample-config.yaml")
	configContent := `# Sample collector configuration for testing
#
# This file simulates the configuration that would be passed to your collector
# via the epack.yaml job configuration.

# Example configuration fields (customize for your collector)
target: https://api.example.com
credentials:
  api_key: ${API_KEY}  # Will be expanded from environment
options:
  include_metadata: true
  max_results: 100
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		return nil, fmt.Errorf("writing config: %w", err)
	}
	files = append(files, configPath)

	// Create environment file
	envPath := filepath.Join(outputDir, "sample.env")
	envContent := `# Sample environment variables for testing your collector
#
# Source this file before running your collector:
#   source sample.env && ./your-collector

# Standard epack environment variables
EPACK_OUTPUT_DIR=./output
EPACK_WORK_DIR=./work

# Collector-specific variables (customize for your collector)
API_KEY=test-api-key-12345
API_SECRET=test-secret-value
`
	if err := os.WriteFile(envPath, []byte(envContent), 0644); err != nil {
		return nil, fmt.Errorf("writing env file: %w", err)
	}
	files = append(files, envPath)

	// Create output directory
	outputPath := filepath.Join(outputDir, "output")
	if err := os.MkdirAll(outputPath, 0755); err != nil {
		return nil, fmt.Errorf("creating output directory: %w", err)
	}

	// Create test script
	scriptPath := filepath.Join(outputDir, "test-collector.sh")
	scriptContent := `#!/bin/bash
# Test script for running your collector with sample inputs
#
# Usage: ./test-collector.sh ./your-collector-binary

COLLECTOR="${1:?Usage: $0 <collector-binary>}"
SCRIPT_DIR="$(dirname "$0")"

echo "Testing collector: $COLLECTOR"
echo ""

# Set up environment
source "$SCRIPT_DIR/sample.env"

# Create output directory
mkdir -p "$SCRIPT_DIR/output"

# Run the collector
# Note: Collectors receive configuration via stdin in JSON format
echo '{"target":"https://api.example.com","options":{"include_metadata":true}}' | \
    "$COLLECTOR"

echo ""
echo "Check output in: $SCRIPT_DIR/output/"
`
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0755); err != nil {
		return nil, fmt.Errorf("writing test script: %w", err)
	}
	files = append(files, scriptPath)

	return files, nil
}

// generateRemoteMocks creates mock inputs for testing remote adapters.
func generateRemoteMocks(outputDir string) ([]string, error) {
	var files []string

	// Create sample push request
	pushPath := filepath.Join(outputDir, "sample-push-request.json")
	pushContent := `{
  "action": "push",
  "pack_path": "./sample-evidence.pack",
  "destination": "registry.example.com/org/sample-evidence:v1.0.0",
  "options": {
    "force": false,
    "sign": true
  }
}
`
	if err := os.WriteFile(pushPath, []byte(pushContent), 0644); err != nil {
		return nil, fmt.Errorf("writing push request: %w", err)
	}
	files = append(files, pushPath)

	// Create sample pull request
	pullPath := filepath.Join(outputDir, "sample-pull-request.json")
	pullContent := `{
  "action": "pull",
  "source": "registry.example.com/org/sample-evidence:v1.0.0",
  "output_path": "./downloaded.pack",
  "options": {
    "verify": true
  }
}
`
	if err := os.WriteFile(pullPath, []byte(pullContent), 0644); err != nil {
		return nil, fmt.Errorf("writing pull request: %w", err)
	}
	files = append(files, pullPath)

	// Create sample list request
	listPath := filepath.Join(outputDir, "sample-list-request.json")
	listContent := `{
  "action": "list",
  "registry": "registry.example.com",
  "prefix": "org/",
  "options": {
    "include_tags": true,
    "limit": 50
  }
}
`
	if err := os.WriteFile(listPath, []byte(listContent), 0644); err != nil {
		return nil, fmt.Errorf("writing list request: %w", err)
	}
	files = append(files, listPath)

	// Create test script
	scriptPath := filepath.Join(outputDir, "test-remote.sh")
	scriptContent := `#!/bin/bash
# Test script for running your remote adapter with sample inputs
#
# Usage: ./test-remote.sh ./your-remote-binary

REMOTE="${1:?Usage: $0 <remote-binary>}"
SCRIPT_DIR="$(dirname "$0")"

echo "Testing remote adapter: $REMOTE"
echo ""

# Test capabilities
echo "=== Capabilities ==="
"$REMOTE" --capabilities
echo ""

# Test list operation (customize based on your adapter)
echo "=== List Request ==="
cat "$SCRIPT_DIR/sample-list-request.json" | "$REMOTE"
echo ""
`
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0755); err != nil {
		return nil, fmt.Errorf("writing test script: %w", err)
	}
	files = append(files, scriptPath)

	return files, nil
}

// generateUtilityMocks creates mock inputs for testing utilities.
func generateUtilityMocks(outputDir string) ([]string, error) {
	var files []string

	// Create sample evidence pack (reuse tool mock)
	toolFiles, err := generateToolMocks(outputDir)
	if err != nil {
		return nil, err
	}
	files = append(files, toolFiles...)

	// Create test script for utility
	scriptPath := filepath.Join(outputDir, "test-utility.sh")
	scriptContent := `#!/bin/bash
# Test script for running your utility with sample inputs
#
# Usage: ./test-utility.sh ./your-utility-binary

UTILITY="${1:?Usage: $0 <utility-binary>}"
SCRIPT_DIR="$(dirname "$0")"

echo "Testing utility: $UTILITY"
echo ""

# Test capabilities
echo "=== Capabilities ==="
"$UTILITY" --capabilities
echo ""

# Test with sample evidence pack
echo "=== Running with sample pack ==="
"$UTILITY" "$SCRIPT_DIR/sample-evidence"
`
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0755); err != nil {
		return nil, fmt.Errorf("writing test script: %w", err)
	}
	files = append(files, scriptPath)

	return files, nil
}
