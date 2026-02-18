package toolprotocol

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// DependencyError represents a missing tool dependency.
type DependencyError struct {
	Tool   string // Required tool name (empty if checking output directly)
	Output string // Required output path (if checking requires_outputs)
}

// CheckDependencies verifies that required tools have been run and required outputs exist.
// Returns a list of missing dependencies. Empty list means all dependencies are satisfied.
//
// packSidecar is the path to <pack>.epack directory.
// For packless runs, pass empty string (dependencies cannot be checked).
func CheckDependencies(caps *Capabilities, packSidecar string) []DependencyError {
	if caps == nil {
		return nil
	}
	if packSidecar == "" {
		// Packless run - can't check dependencies
		return nil
	}

	var missing []DependencyError

	// Check requires_tools: look for any successful run of each tool
	for _, toolName := range caps.RequiresTools {
		if !hasSuccessfulRun(packSidecar, toolName) {
			missing = append(missing, DependencyError{Tool: toolName})
		}
	}

	// Check requires_outputs: look for specific output files
	for _, outputPath := range caps.RequiresOutputs {
		fullPath := filepath.Join(packSidecar, "tools", outputPath)
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			// Extract tool name from path (first component)
			toolName := ""
			parts := splitPath(outputPath)
			if len(parts) > 0 {
				toolName = parts[0]
			}
			missing = append(missing, DependencyError{Tool: toolName, Output: outputPath})
		}
	}

	return missing
}

// hasSuccessfulRun checks if a tool has at least one successful run.
// Looks for any run directory containing a result.json with status "success".
func hasSuccessfulRun(packSidecar, toolName string) bool {
	toolDir := filepath.Join(packSidecar, "tools", toolName)
	entries, err := os.ReadDir(toolDir)
	if err != nil {
		return false
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		resultPath := filepath.Join(toolDir, entry.Name(), "result.json")
		result, err := ReadResult(resultPath)
		if err != nil {
			continue
		}
		if result.Status == StatusSuccess {
			return true
		}
	}
	return false
}

// splitPath splits a path into components.
func splitPath(path string) []string {
	var parts []string
	for path != "" {
		dir, file := filepath.Split(path)
		if file != "" {
			parts = append(parts, file)
		}
		path = filepath.Clean(dir)
		if path == "." || path == "/" {
			break
		}
	}
	// Reverse to get correct order
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return parts
}

// FormatDependencyErrors formats missing dependencies into a human-readable error message.
func FormatDependencyErrors(missing []DependencyError) string {
	if len(missing) == 0 {
		return ""
	}

	// Group by tool
	toolSet := make(map[string]bool)
	var outputs []string
	for _, dep := range missing {
		if dep.Output != "" {
			outputs = append(outputs, dep.Output)
		}
		if dep.Tool != "" {
			toolSet[dep.Tool] = true
		}
	}

	var tools []string
	for t := range toolSet {
		tools = append(tools, t)
	}
	sort.Strings(tools)

	if len(tools) == 1 && len(outputs) == 0 {
		return fmt.Sprintf("required tool '%s' has not been run", tools[0])
	}

	if len(tools) == 1 && len(outputs) > 0 {
		return fmt.Sprintf("required output from '%s' not found: %v", tools[0], outputs)
	}

	if len(tools) > 1 {
		return fmt.Sprintf("required tools have not been run: %v", tools)
	}

	return fmt.Sprintf("required outputs not found: %v", outputs)
}

// LatestRunDir returns the path to the most recent run directory for a tool.
// Returns empty string if no runs exist.
func LatestRunDir(packSidecar, toolName string) string {
	toolDir := filepath.Join(packSidecar, "tools", toolName)
	entries, err := os.ReadDir(toolDir)
	if err != nil {
		return ""
	}

	// Run IDs are lexicographically sortable by design
	var runIDs []string
	for _, entry := range entries {
		if entry.IsDir() {
			runIDs = append(runIDs, entry.Name())
		}
	}

	if len(runIDs) == 0 {
		return ""
	}

	sort.Strings(runIDs)
	return filepath.Join(toolDir, runIDs[len(runIDs)-1])
}
