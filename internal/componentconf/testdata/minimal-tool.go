//go:build ignore

// Minimal tool for conformance testing.
// Build with: go build -o epack-tool-minimal ./minimal-tool.go
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

func main() {
	// Handle --capabilities
	if len(os.Args) > 1 && os.Args[1] == "--capabilities" {
		caps := map[string]interface{}{
			"name":             "minimal",
			"version":          "1.0.0",
			"protocol_version": 1,
			"description":      "Minimal tool for conformance testing",
			"requires_pack":    false,
		}
		json.NewEncoder(os.Stdout).Encode(caps)
		return
	}

	// Normal execution - write result.json
	runID := os.Getenv("EPACK_RUN_ID")
	runDir := os.Getenv("EPACK_RUN_DIR")
	if runDir == "" {
		runDir = "."
	}

	startedAt := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	completedAt := time.Now().UTC().Format("2006-01-02T15:04:05Z")

	result := map[string]interface{}{
		"schema_version": 1,
		"tool": map[string]interface{}{
			"name":             "minimal",
			"version":          "1.0.0",
			"protocol_version": 1,
		},
		"run_id":       runID,
		"status":       "success",
		"started_at":   startedAt,
		"completed_at": completedAt,
		"duration_ms":  0,
		"outputs":      []interface{}{},
	}

	resultPath := filepath.Join(runDir, "result.json")
	f, err := os.Create(resultPath)
	if err != nil {
		os.Exit(1)
	}
	defer f.Close()
	json.NewEncoder(f).Encode(result)
}
