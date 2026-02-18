package componentsdk

import (
	"encoding/json"
	"fmt"
	"os"
)

// UtilitySpec defines the utility's metadata and capabilities.
type UtilitySpec struct {
	// Name is the utility name (without epack-util- prefix).
	// Must match ^[a-z0-9][a-z0-9._-]{0,63}$
	Name string

	// Version is the semantic version (e.g., "1.0.0").
	Version string

	// Description is a human-readable description of what the utility does.
	Description string

	// Usage is the usage synopsis shown in --help output.
	// Example: "epack-util-viewer [options] <pack>"
	Usage string

	// Examples are usage examples shown in --help output.
	Examples []string
}

// UtilityHandler is the function signature for utility implementations.
// It receives the command-line arguments (excluding the program name and
// any flags already handled like --version, --capabilities, --help).
// Return nil for success, or an error for failure.
type UtilityHandler func(args []string) error

// RunUtility executes the utility handler with protocol compliance.
// It handles --version, --capabilities, --help, and proper exit codes.
// This function does not return.
func RunUtility(spec UtilitySpec, handler UtilityHandler) {
	os.Exit(runUtilityInternal(spec, handler))
}

func runUtilityInternal(spec UtilitySpec, handler UtilityHandler) int {
	// Process flags, collect remaining args
	var remainingArgs []string
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--version", "-v":
			fmt.Println(spec.Version)
			return 0
		case "--capabilities":
			return outputUtilityCapabilities(spec)
		case "--help", "-h":
			printUtilityHelp(spec)
			return 0
		default:
			// Collect all args after the program name
			remainingArgs = os.Args[1:]
		}
	}

	// Run handler
	if err := handler(remainingArgs); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	return 0
}

func outputUtilityCapabilities(spec UtilitySpec) int {
	caps := map[string]any{
		"name":        spec.Name,
		"kind":        "utility",
		"version":     spec.Version,
		"description": spec.Description,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(caps); err != nil {
		fmt.Fprintf(os.Stderr, "error encoding capabilities: %v\n", err)
		return 1
	}
	return 0
}

func printUtilityHelp(spec UtilitySpec) {
	if spec.Usage != "" {
		fmt.Printf("Usage: %s\n\n", spec.Usage)
	} else {
		fmt.Printf("Usage: epack-util-%s [options]\n\n", spec.Name)
	}

	if spec.Description != "" {
		fmt.Printf("%s\n\n", spec.Description)
	}

	fmt.Println("Options:")
	fmt.Println("  -h, --help          Show this help message")
	fmt.Println("  -v, --version       Show version")
	fmt.Println("  --capabilities      Output capabilities as JSON")

	if len(spec.Examples) > 0 {
		fmt.Println("\nExamples:")
		for _, ex := range spec.Examples {
			fmt.Printf("  %s\n", ex)
		}
	}
}
