//go:build ignore

// Minimal collector for conformance testing.
// Build with: go build -o epack-collector-minimal ./minimal-collector.go
package main

import (
	"encoding/json"
	"os"
)

func main() {
	output := map[string]interface{}{
		"protocol_version": 1,
		"data": map[string]interface{}{
			"collected_at": "2026-02-22T10:00:00Z",
			"source":       os.Getenv("EPACK_COLLECTOR_NAME"),
			"items":        []interface{}{},
		},
	}
	json.NewEncoder(os.Stdout).Encode(output)
}
