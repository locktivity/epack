//go:build ignore

// Minimal remote adapter for conformance testing.
// Build with: go build -o epack-remote-minimal ./minimal-remote.go
package main

import (
	"encoding/json"
	"os"
)

func main() {
	// Handle --capabilities
	if len(os.Args) > 1 && os.Args[1] == "--capabilities" {
		caps := map[string]interface{}{
			"name":                    "minimal",
			"kind":                    "remote_adapter",
			"deploy_protocol_version": 1,
			"features": map[string]interface{}{
				"prepare_finalize": false,
				"pull":             false,
			},
		}
		json.NewEncoder(os.Stdout).Encode(caps)
		return
	}

	// Handle protocol commands
	var request map[string]interface{}
	if err := json.NewDecoder(os.Stdin).Decode(&request); err != nil {
		response := map[string]interface{}{
			"ok":         false,
			"type":       "error",
			"request_id": "",
			"error": map[string]interface{}{
				"code":    "invalid_request",
				"message": "failed to parse request",
			},
		}
		json.NewEncoder(os.Stdout).Encode(response)
		return
	}

	requestID, _ := request["request_id"].(string)
	reqType, _ := request["type"].(string)

	// Return error for unsupported commands
	response := map[string]interface{}{
		"ok":         false,
		"type":       "error",
		"request_id": requestID,
		"error": map[string]interface{}{
			"code":      "unsupported_command",
			"message":   "command not supported: " + reqType,
			"retryable": false,
		},
	}
	json.NewEncoder(os.Stdout).Encode(response)
}
