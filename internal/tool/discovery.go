//go:build components

package tool

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/component/sync"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/platform"
	"github.com/locktivity/epack/internal/project"
	"github.com/locktivity/epack/internal/toolprotocol"
)

// VerificationStatus indicates whether a tool is verified via lockfile.
type VerificationStatus string

const (
	// StatusVerified means the tool is in the lockfile with a valid digest.
	StatusVerified VerificationStatus = "verified"
	// StatusUnverified means the tool is in PATH but not in lockfile.
	StatusUnverified VerificationStatus = "unverified"
	// StatusManaged means the tool is managed (in lockfile) but not yet synced.
	StatusManaged VerificationStatus = "managed"
)

// DiscoveredTool represents a tool found in PATH or lockfile.
type DiscoveredTool struct {
	BinaryName   string                     `json:"binary_name"`            // e.g., "epack-tool-ai"
	BinaryPath   string                     `json:"binary_path"`            // Full path to binary (empty if not found)
	Capabilities *toolprotocol.Capabilities `json:"capabilities,omitempty"` // nil if --capabilities failed or not probed
	Error        string                     `json:"error,omitempty"`        // Error message if capabilities failed
	Status       VerificationStatus         `json:"status"`                 // verified, unverified, managed
	Source       string                     `json:"source"`                 // "path", "lockfile", or "both"
}

// DiscoverOptions configures tool discovery.
type DiscoverOptions struct {
	// ProbePATH enables probing --capabilities from PATH tools.
	// SECURITY: PATH tools are untrusted; probing executes arbitrary code.
	// This should only be enabled with explicit user opt-in.
	ProbePATH bool

	// ProbeManaged enables probing --capabilities from managed (lockfile) tools.
	// SECURITY: While managed tools are more trusted (in lockfile with digest),
	// probing still executes code. Default to false for safety in list commands.
	// When false, capabilities are derived from lockfile metadata instead.
	ProbeManaged bool

	// WorkDir is the working directory to search from.
	// If empty, uses current working directory.
	WorkDir string
}

// DiscoverTools finds tools from both PATH and lockfile, with verification status.
// By default, no tools are probed (capabilities come from lockfile metadata).
// Set opts.ProbeManaged to probe managed tools, opts.ProbePATH to probe PATH tools.
// SECURITY: Probing executes arbitrary binaries. Require explicit opt-in.
func DiscoverTools(opts DiscoverOptions) []DiscoveredTool {
	workDir := opts.WorkDir
	if workDir == "" {
		var err error
		workDir, err = os.Getwd()
		if err != nil {
			workDir = "."
		}
	}

	// Get tools from lockfile first
	lockfileTools := getToolsFromLockfile(workDir, opts.ProbeManaged)

	// Get tools from PATH
	pathTools := getToolsFromPATH(opts.ProbePATH)

	// Merge the two lists
	toolMap := make(map[string]*DiscoveredTool)

	// Add lockfile tools first
	for _, tool := range lockfileTools {
		t := tool // avoid aliasing
		toolMap[tool.BinaryName] = &t
	}

	// Merge PATH tools
	for _, tool := range pathTools {
		if existing, ok := toolMap[tool.BinaryName]; ok {
			// Tool exists in both - update with PATH info
			existing.BinaryPath = tool.BinaryPath
			existing.Capabilities = tool.Capabilities
			existing.Error = tool.Error
			existing.Source = "both"
			// Update status to verified if we have digest
			if existing.Status == StatusManaged {
				existing.Status = StatusVerified
			}
		} else {
			// Tool only in PATH - unverified
			t := tool
			t.Status = StatusUnverified
			t.Source = "path"
			toolMap[tool.BinaryName] = &t
		}
	}

	// Convert map to slice with deterministic ordering
	names := make([]string, 0, len(toolMap))
	for name := range toolMap {
		names = append(names, name)
	}
	sort.Strings(names)

	result := make([]DiscoveredTool, 0, len(toolMap))
	for _, name := range names {
		result = append(result, *toolMap[name])
	}

	return result
}

// getToolsFromLockfile reads tools from the project's lockfile.
// Searches upward from workDir to find project root.
// If probe is true, managed tools are probed for capabilities.
// If probe is false, capabilities are derived from lockfile metadata only.
func getToolsFromLockfile(workDir string, probe bool) []DiscoveredTool {
	// Search upward for epack.yaml to find project root
	projectRoot, err := project.FindRoot(workDir)
	if err != nil {
		return nil
	}

	lockfilePath := filepath.Join(projectRoot, lockfile.FileName)
	lf, err := lockfile.Load(lockfilePath)
	if err != nil {
		return nil
	}

	// Also load config to resolve tool paths
	configPath := filepath.Join(projectRoot, "epack.yaml")
	cfg, _ := config.Load(configPath) // Ignore error - just limits probing

	platform := platform.Key(runtime.GOOS, runtime.GOARCH)
	epackDir := filepath.Join(projectRoot, ".epack")

	// Sort tool names for deterministic ordering
	toolNames := make([]string, 0, len(lf.Tools))
	for name := range lf.Tools {
		toolNames = append(toolNames, name)
	}
	sort.Strings(toolNames)

	var tools []DiscoveredTool
	for _, name := range toolNames {
		locked := lf.Tools[name]
		tool := DiscoveredTool{
			BinaryName: componenttypes.ToolBinaryPrefix + name,
			Source:     "lockfile",
			Status:     StatusManaged,
		}

		// Check if platform entry exists with digest
		if entry, ok := locked.Platforms[platform]; ok && entry.Digest != "" {
			tool.Status = StatusVerified
		}

		// Try to find the installed binary path
		var binaryPath string
		if cfg != nil {
			if toolCfg, ok := cfg.Tools[name]; ok {
				binaryPath, _ = sync.ResolveToolBinaryPath(epackDir, name, toolCfg, lf)
			}
		}

		if binaryPath != "" {
			tool.BinaryPath = binaryPath

			// Only probe if explicitly requested
			// SECURITY: Even managed tools execute code when probed; require opt-in
			if probe {
				caps, err := ProbeCapabilities(context.Background(), binaryPath)
				if err != nil {
					tool.Error = err.Error()
				} else {
					tool.Capabilities = caps
				}
			}
		}

		// Fall back to lockfile info if no capabilities from probe
		if tool.Capabilities == nil && locked.Version != "" {
			tool.Capabilities = &toolprotocol.Capabilities{
				Name:    name,
				Version: locked.Version,
			}
		}

		tools = append(tools, tool)
	}

	return tools
}

// getToolsFromPATH finds tools in PATH, optionally probing capabilities.
func getToolsFromPATH(probe bool) []DiscoveredTool {
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		return nil
	}

	seen := make(map[string]bool)
	var tools []DiscoveredTool

	for _, dir := range filepath.SplitList(pathEnv) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			name := entry.Name()
			if !strings.HasPrefix(name, componenttypes.ToolBinaryPrefix) {
				continue
			}

			// Skip duplicates (first in PATH wins)
			if seen[name] {
				continue
			}
			seen[name] = true

			fullPath := filepath.Join(dir, name)
			info, err := entry.Info()
			if err != nil {
				continue
			}

			// Check if executable
			if info.Mode()&0111 == 0 {
				continue
			}

			tool := DiscoveredTool{
				BinaryName: name,
				BinaryPath: fullPath,
			}

			// Only probe capabilities if --probe flag is set
			if probe {
				caps, err := ProbeCapabilities(context.Background(), fullPath)
				if err != nil {
					tool.Error = err.Error()
				} else {
					tool.Capabilities = caps
				}
			}

			tools = append(tools, tool)
		}
	}

	return tools
}
