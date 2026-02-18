package remote

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/locktivity/epack/internal/componenttypes"
)

// AdapterStatus indicates the verification status of a remote adapter.
type AdapterStatus string

const (
	// StatusVerified means the adapter is in epack.lock.yaml with a valid digest.
	StatusVerified AdapterStatus = "verified"
	// StatusUnverified means the adapter is in PATH but not in lockfile.
	StatusUnverified AdapterStatus = "unverified"
	// StatusManaged means the adapter is managed (in lockfile) but not yet installed.
	StatusManaged AdapterStatus = "managed"
	// StatusNotFound means the adapter was configured but not found anywhere.
	StatusNotFound AdapterStatus = "not_found"
)

// DiscoveredAdapter represents a remote adapter found on the system.
type DiscoveredAdapter struct {
	// Name is the adapter name without prefix (e.g., "locktivity").
	Name string `json:"name"`

	// BinaryName is the full binary name (e.g., "epack-remote-locktivity").
	BinaryName string `json:"binary_name"`

	// BinaryPath is the full path to the binary (empty if not found).
	BinaryPath string `json:"binary_path,omitempty"`

	// Capabilities are the adapter capabilities (nil if not probed or failed).
	Capabilities *Capabilities `json:"capabilities,omitempty"`

	// Error contains the error message if capability probing failed.
	Error string `json:"error,omitempty"`

	// Status indicates verification status.
	Status AdapterStatus `json:"status"`

	// Source indicates where the adapter was found.
	// Values: "managed", "path", "both"
	Source string `json:"source"`
}

// DiscoverOptions configures adapter discovery.
type DiscoverOptions struct {
	// ProbePATH enables probing --capabilities from PATH adapters.
	// SECURITY: PATH adapters are untrusted; probing executes arbitrary code.
	// This should only be enabled with explicit user opt-in.
	ProbePATH bool

	// ProbeManaged enables probing --capabilities from managed adapters.
	// When false, capabilities must come from registry metadata.
	ProbeManaged bool

	// WorkDir is the working directory to search from.
	// If empty, uses current working directory.
	WorkDir string
}

// DiscoverAdapters finds remote adapters from managed directory and PATH.
// By default, no adapters are probed (requires explicit opt-in).
func DiscoverAdapters(ctx context.Context, opts DiscoverOptions) []DiscoveredAdapter {
	// Get adapters from managed directory first
	managedAdapters := getAdaptersFromManagedDir(ctx, opts.ProbeManaged)

	// Get adapters from project-local .epack/bin
	projectAdapters := getAdaptersFromProjectDir(ctx, opts.WorkDir, opts.ProbeManaged)

	// Get adapters from PATH
	pathAdapters := getAdaptersFromPATH(ctx, opts.ProbePATH)

	// Merge the lists (managed takes priority over PATH)
	adapterMap := make(map[string]*DiscoveredAdapter)

	// Add managed adapters first (highest priority)
	for _, adapter := range managedAdapters {
		a := adapter
		adapterMap[adapter.Name] = &a
	}

	// Add project-local adapters (override managed if binary found)
	for _, adapter := range projectAdapters {
		if existing, ok := adapterMap[adapter.Name]; ok {
			// Update with project-local info
			if adapter.BinaryPath != "" {
				existing.BinaryPath = adapter.BinaryPath
				existing.Capabilities = adapter.Capabilities
				existing.Error = adapter.Error
			}
			existing.Source = "both"
		} else {
			a := adapter
			adapterMap[adapter.Name] = &a
		}
	}

	// Merge PATH adapters
	for _, adapter := range pathAdapters {
		if existing, ok := adapterMap[adapter.Name]; ok {
			// Adapter exists in managed - update with PATH info if needed
			if existing.BinaryPath == "" {
				existing.BinaryPath = adapter.BinaryPath
				existing.Capabilities = adapter.Capabilities
				existing.Error = adapter.Error
			}
			existing.Source = "both"
		} else {
			// Adapter only in PATH - unverified
			a := adapter
			a.Status = StatusUnverified
			a.Source = "path"
			adapterMap[adapter.Name] = &a
		}
	}

	// Convert map to slice with deterministic ordering
	names := make([]string, 0, len(adapterMap))
	for name := range adapterMap {
		names = append(names, name)
	}
	sort.Strings(names)

	result := make([]DiscoveredAdapter, 0, len(adapterMap))
	for _, name := range names {
		result = append(result, *adapterMap[name])
	}

	return result
}

// FindAdapter finds a specific adapter by name.
// Returns nil if not found.
func FindAdapter(ctx context.Context, name string, opts DiscoverOptions) *DiscoveredAdapter {
	adapters := DiscoverAdapters(ctx, opts)
	for _, adapter := range adapters {
		if adapter.Name == name {
			return &adapter
		}
	}
	return nil
}

// LookupAdapterPath finds the binary path for a named adapter.
// It checks managed directory, project-local, and PATH in order.
// Returns empty string if not found.
func LookupAdapterPath(name string) string {
	binaryName := componenttypes.RemoteBinaryPrefix + name

	// Check managed directory first
	managedDir := getManagedPluginDir()
	if managedDir != "" {
		path := filepath.Join(managedDir, binaryName)
		if isExecutable(path) {
			return path
		}
	}

	// Check project-local .epack/bin
	if workDir, err := os.Getwd(); err == nil {
		projectPath := filepath.Join(workDir, ".epack", "bin", binaryName)
		if isExecutable(projectPath) {
			return projectPath
		}
	}

	// Check PATH
	pathEnv := os.Getenv("PATH")
	for _, dir := range filepath.SplitList(pathEnv) {
		path := filepath.Join(dir, binaryName)
		if isExecutable(path) {
			return path
		}
	}

	return ""
}

// getManagedPluginDir returns the platform-specific managed plugin directory.
func getManagedPluginDir() string {
	// XDG_DATA_HOME takes precedence on all Unix-like systems
	if runtime.GOOS != "windows" {
		if dataHome := os.Getenv("XDG_DATA_HOME"); dataHome != "" {
			return filepath.Join(dataHome, "epack", "bin")
		}
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	switch runtime.GOOS {
	case "darwin":
		// macOS: ~/Library/Application Support/epack/bin
		return filepath.Join(home, "Library", "Application Support", "epack", "bin")
	case "windows":
		// Windows: %LOCALAPPDATA%\epack\bin
		localAppData := os.Getenv("LOCALAPPDATA")
		if localAppData == "" {
			localAppData = filepath.Join(home, "AppData", "Local")
		}
		return filepath.Join(localAppData, "epack", "bin")
	default:
		// Linux and others: ~/.local/share/epack/bin (XDG default)
		return filepath.Join(home, ".local", "share", "epack", "bin")
	}
}

// getAdaptersFromManagedDir finds adapters in the managed plugin directory.
func getAdaptersFromManagedDir(ctx context.Context, probe bool) []DiscoveredAdapter {
	managedDir := getManagedPluginDir()
	if managedDir == "" {
		return nil
	}
	return scanDirForAdapters(ctx, managedDir, probe, StatusVerified, "managed")
}

// getAdaptersFromProjectDir finds adapters in the project's .epack/bin directory.
func getAdaptersFromProjectDir(ctx context.Context, workDir string, probe bool) []DiscoveredAdapter {
	if workDir == "" {
		var err error
		workDir, err = os.Getwd()
		if err != nil {
			return nil
		}
	}
	projectDir := filepath.Join(workDir, ".epack", "bin")
	return scanDirForAdapters(ctx, projectDir, probe, StatusVerified, "managed")
}

// getAdaptersFromPATH finds adapters in PATH.
func getAdaptersFromPATH(ctx context.Context, probe bool) []DiscoveredAdapter {
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		return nil
	}

	seen := make(map[string]bool)
	var adapters []DiscoveredAdapter

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
			if !strings.HasPrefix(name, componenttypes.RemoteBinaryPrefix) {
				continue
			}

			// Skip duplicates (first in PATH wins)
			if seen[name] {
				continue
			}
			seen[name] = true

			fullPath := filepath.Join(dir, name)
			if !isExecutable(fullPath) {
				continue
			}

			adapterName := strings.TrimPrefix(name, componenttypes.RemoteBinaryPrefix)
			adapter := DiscoveredAdapter{
				Name:       adapterName,
				BinaryName: name,
				BinaryPath: fullPath,
				Status:     StatusUnverified,
				Source:     "path",
			}

			// Only probe capabilities if explicitly requested
			if probe {
				caps, err := QueryCapabilities(ctx, fullPath)
				if err != nil {
					adapter.Error = err.Error()
				} else {
					adapter.Capabilities = caps
				}
			}

			adapters = append(adapters, adapter)
		}
	}

	return adapters
}

// scanDirForAdapters scans a directory for adapter binaries.
func scanDirForAdapters(ctx context.Context, dir string, probe bool, status AdapterStatus, source string) []DiscoveredAdapter {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	var adapters []DiscoveredAdapter
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !strings.HasPrefix(name, componenttypes.RemoteBinaryPrefix) {
			continue
		}

		fullPath := filepath.Join(dir, name)
		if !isExecutable(fullPath) {
			continue
		}

		adapterName := strings.TrimPrefix(name, componenttypes.RemoteBinaryPrefix)
		adapter := DiscoveredAdapter{
			Name:       adapterName,
			BinaryName: name,
			BinaryPath: fullPath,
			Status:     status,
			Source:     source,
		}

		// Only probe capabilities if explicitly requested
		if probe {
			caps, err := QueryCapabilities(ctx, fullPath)
			if err != nil {
				adapter.Error = err.Error()
			} else {
				adapter.Capabilities = caps
			}
		}

		adapters = append(adapters, adapter)
	}

	return adapters
}

// isExecutable checks if a file exists and is executable.
func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if info.IsDir() {
		return false
	}
	// On Windows, just check existence
	if runtime.GOOS == "windows" {
		return true
	}
	// On Unix, check execute permission
	return info.Mode()&0111 != 0
}
