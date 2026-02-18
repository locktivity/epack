//go:build ignore

// gensample generates sample.epack for embedding in the CLI.
//
// Usage:
//
//	go run cmd/epack/componentcmd/gensample/main.go
//
// This creates an unsigned evidence pack with demo artifacts that users
// can explore with `epack inspect` and `epack list` commands.
package main

import (
	"encoding/json"
	"log"
	"path/filepath"
	"time"

	"github.com/locktivity/epack/pack/builder"
)

func main() {
	// Create builder with demo stream
	b := builder.New("demo/sample/quickstart")

	// Add demo source
	b.AddSource("sample-generator", "1.0.0")

	// Create timestamp for artifacts
	ts := time.Now().UTC().Format(time.RFC3339)

	// Add a system info artifact
	systemInfo := map[string]any{
		"hostname":    "demo-host",
		"os":          "linux",
		"arch":        "amd64",
		"collected":   ts,
		"description": "This is sample evidence demonstrating the pack format.",
	}
	systemInfoJSON, err := json.MarshalIndent(systemInfo, "", "  ")
	if err != nil {
		log.Fatalf("marshaling system info: %v", err)
	}
	if err := b.AddArtifactWithOptions("system-info.json", systemInfoJSON, builder.ArtifactOptions{
		ContentType: "application/json",
		DisplayName: "System Information",
		Description: "Basic system information collected at build time.",
		CollectedAt: ts,
	}); err != nil {
		log.Fatalf("adding system info: %v", err)
	}

	// Add a dependencies artifact
	deps := map[string]any{
		"packages": []map[string]any{
			{"name": "example-lib", "version": "2.1.0", "license": "MIT"},
			{"name": "demo-framework", "version": "1.5.3", "license": "Apache-2.0"},
			{"name": "test-utils", "version": "0.9.1", "license": "BSD-3-Clause"},
		},
		"vulnerabilities": []any{},
		"summary": map[string]any{
			"total":      3,
			"vulnerable": 0,
		},
	}
	depsJSON, err := json.MarshalIndent(deps, "", "  ")
	if err != nil {
		log.Fatalf("marshaling deps: %v", err)
	}
	if err := b.AddArtifactWithOptions("dependencies.json", depsJSON, builder.ArtifactOptions{
		ContentType: "application/json",
		DisplayName: "Dependency Scan",
		Description: "Package dependencies and vulnerability scan results.",
		CollectedAt: ts,
		Controls:    []string{"vuln-mgmt", "sbom"},
	}); err != nil {
		log.Fatalf("adding deps: %v", err)
	}

	// Add a compliance checklist artifact
	compliance := map[string]any{
		"framework": "Demo Compliance Framework",
		"version":   "1.0",
		"checks": []map[string]any{
			{"id": "DCF-1.1", "title": "Access Control", "status": "pass"},
			{"id": "DCF-1.2", "title": "Authentication", "status": "pass"},
			{"id": "DCF-2.1", "title": "Encryption at Rest", "status": "pass"},
			{"id": "DCF-2.2", "title": "Encryption in Transit", "status": "pass"},
			{"id": "DCF-3.1", "title": "Audit Logging", "status": "pass"},
		},
		"summary": map[string]any{
			"total":  5,
			"passed": 5,
			"failed": 0,
		},
	}
	complianceJSON, err := json.MarshalIndent(compliance, "", "  ")
	if err != nil {
		log.Fatalf("marshaling compliance: %v", err)
	}
	if err := b.AddArtifactWithOptions("compliance.json", complianceJSON, builder.ArtifactOptions{
		ContentType: "application/json",
		DisplayName: "Compliance Checks",
		Description: "Automated compliance framework assessment results.",
		CollectedAt: ts,
		Controls:    []string{"compliance", "audit"},
	}); err != nil {
		log.Fatalf("adding compliance: %v", err)
	}

	// Build the pack
	outputPath := filepath.Join("cmd", "epack", "componentcmd", "sample.epack")
	if err := b.Build(outputPath); err != nil {
		log.Fatalf("building pack: %v", err)
	}

	log.Printf("Generated %s", outputPath)
}
