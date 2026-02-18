//go:build components

package tool

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/component/sync"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/platform"
	"github.com/locktivity/epack/internal/project"
	"github.com/locktivity/epack/internal/toolprotocol"
)

// ToolInfo contains comprehensive information about a tool.
type ToolInfo struct {
	Name         string                     `json:"name"`
	BinaryPath   string                     `json:"binary_path,omitempty"`
	Capabilities *toolprotocol.Capabilities `json:"capabilities,omitempty"`
	Lockfile     *LockfileInfo              `json:"lockfile,omitempty"`
	Error        string                     `json:"error,omitempty"`
}

// LockfileInfo contains lockfile-related information about a tool.
type LockfileInfo struct {
	Version   string                  `json:"version"`
	Source    string                  `json:"source,omitempty"`
	Signer    *SignerInfo             `json:"signer,omitempty"`
	Platforms map[string]PlatformInfo `json:"platforms,omitempty"`
}

// SignerInfo contains signing identity information from the lockfile.
// This data comes from Sigstore verification at sync time and establishes
// the trusted identity for the tool's supply chain.
type SignerInfo struct {
	Issuer  string `json:"issuer"`            // OIDC issuer (e.g., "https://token.actions.githubusercontent.com")
	Subject string `json:"subject,omitempty"` // Certificate subject (e.g., workflow path)
}

// PlatformInfo contains platform-specific lockfile information.
type PlatformInfo struct {
	Digest string `json:"digest"`
	Asset  string `json:"asset,omitempty"`
}

// ToolVerification contains verification results for a tool.
type ToolVerification struct {
	Name            string `json:"name"`
	Platform        string `json:"platform"`
	Status          string `json:"status"` // "verified", "digest_mismatch", "not_installed", "not_locked"
	Installed       bool   `json:"installed"`
	InstallPath     string `json:"install_path,omitempty"`
	ExpectedDigest  string `json:"expected_digest,omitempty"`
	ActualDigest    string `json:"actual_digest,omitempty"`
	DigestMatch     bool   `json:"digest_match,omitempty"`
	Version         string `json:"version,omitempty"`
	Error           string `json:"error,omitempty"`
}

// GetToolInfo retrieves comprehensive information about a tool.
// It checks both PATH and lockfile for the tool.
func GetToolInfo(ctx context.Context, toolName string, workDir string) (*ToolInfo, error) {
	// Validate tool name
	if err := config.ValidateToolName(toolName); err != nil {
		return nil, fmt.Errorf("invalid tool name: %w", err)
	}

	info := &ToolInfo{Name: toolName}

	// Try to find the binary in PATH
	binaryPath := FindToolInPATH(toolName)
	if binaryPath != "" {
		info.BinaryPath = binaryPath

		// Query capabilities
		caps, err := ProbeCapabilities(ctx, binaryPath)
		if err != nil {
			info.Error = fmt.Sprintf("capabilities query failed: %v", err)
		} else {
			info.Capabilities = caps
		}
	}

	// Check for lockfile information
	if workDir == "" {
		var err error
		workDir, err = os.Getwd()
		if err != nil {
			workDir = "."
		}
	}

	lfInfo := getLockfileInfo(toolName, workDir)
	if lfInfo != nil {
		info.Lockfile = lfInfo
	}

	// If no binary found and no lockfile, error
	if info.BinaryPath == "" && info.Lockfile == nil {
		return nil, fmt.Errorf("tool %q not found in PATH and not configured in lockfile", toolName)
	}

	return info, nil
}

// getLockfileInfo retrieves lockfile information for a tool.
// Searches upward from workDir to find project root.
func getLockfileInfo(toolName, workDir string) *LockfileInfo {
	// Search upward for project root
	projectRoot, err := project.FindRoot(workDir)
	if err != nil {
		return nil
	}

	lockfilePath := filepath.Join(projectRoot, lockfile.FileName)

	lf, err := lockfile.Load(lockfilePath)
	if err != nil {
		return nil
	}

	locked, ok := lf.GetTool(toolName)
	if !ok {
		return nil
	}

	info := &LockfileInfo{
		Version:   locked.Version,
		Source:    locked.Source,
		Platforms: make(map[string]PlatformInfo),
	}

	// Include signing identity if present
	if locked.Signer != nil {
		info.Signer = &SignerInfo{
			Issuer:  locked.Signer.Issuer,
			Subject: locked.Signer.Subject,
		}
	}

	for platform, entry := range locked.Platforms {
		info.Platforms[platform] = PlatformInfo{
			Digest: entry.Digest,
			Asset:  entry.Asset,
		}
	}

	return info
}

// VerifyTool verifies a tool's installation against the lockfile.
// This checks that the installed binary matches what was locked during sync.
// It does NOT re-verify Sigstore signatures.
func VerifyTool(toolName string, workDir string) (*ToolVerification, error) {
	// Validate tool name
	if err := config.ValidateToolName(toolName); err != nil {
		return nil, fmt.Errorf("invalid tool name: %w", err)
	}

	platform := platform.Key(runtime.GOOS, runtime.GOARCH)
	result := &ToolVerification{
		Name:     toolName,
		Platform: platform,
	}

	// Find project root and load config/lockfile
	if workDir == "" {
		var err error
		workDir, err = os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("getting working directory: %w", err)
		}
	}

	projectRoot, err := project.FindRoot(workDir)
	if err != nil {
		result.Status = "not_locked"
		result.Error = "not in an epack project (no epack.yaml found)"
		return result, nil
	}

	// Load config to get tool definition
	configPath, err := findConfigFile(projectRoot)
	if err != nil {
		result.Status = "not_locked"
		result.Error = fmt.Sprintf("no config file found: %v", err)
		return result, nil
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		result.Status = "not_locked"
		result.Error = fmt.Sprintf("loading config: %v", err)
		return result, nil
	}

	toolCfg, ok := cfg.Tools[toolName]
	if !ok {
		result.Status = "not_locked"
		result.Error = "tool not configured in epack.yaml"
		return result, nil
	}

	// External tools are verified by existence only
	if toolCfg.Binary != "" {
		if _, err := os.Stat(toolCfg.Binary); err == nil {
			result.Status = "verified"
			result.Installed = true
			result.InstallPath = toolCfg.Binary
		} else {
			result.Status = "not_installed"
			result.Installed = false
			result.InstallPath = toolCfg.Binary
			result.Error = "external binary not found"
		}
		return result, nil
	}

	// Load lockfile
	lockfilePath := filepath.Join(projectRoot, lockfile.FileName)
	lf, err := lockfile.Load(lockfilePath)
	if err != nil {
		result.Status = "not_locked"
		result.Error = fmt.Sprintf("no lockfile found: %v", err)
		return result, nil
	}

	locked, ok := lf.GetTool(toolName)
	if !ok {
		result.Status = "not_locked"
		result.Error = "tool not found in lockfile"
		return result, nil
	}

	platformEntry, ok := locked.Platforms[platform]
	if !ok {
		result.Status = "not_locked"
		result.Error = fmt.Sprintf("platform %s not locked", platform)
		return result, nil
	}

	result.Version = locked.Version
	result.ExpectedDigest = platformEntry.Digest

	// Resolve install path
	baseDir := filepath.Join(projectRoot, ".epack")
	installPath, err := sync.InstallPath(baseDir, componenttypes.KindTool, toolName, locked.Version, toolName)
	if err != nil {
		result.Status = "not_installed"
		result.Error = fmt.Sprintf("resolving install path: %v", err)
		return result, nil
	}
	result.InstallPath = installPath

	// Check if installed
	if _, err := os.Stat(installPath); os.IsNotExist(err) {
		result.Status = "not_installed"
		result.Installed = false
		result.Error = "tool binary not installed"
		return result, nil
	}
	result.Installed = true

	// Compute actual digest
	actualDigest, err := toolprotocol.ComputeFileDigest(installPath)
	if err != nil {
		result.Status = "digest_mismatch"
		result.Error = fmt.Sprintf("computing digest: %v", err)
		return result, nil
	}
	result.ActualDigest = actualDigest

	// Compare digests
	if actualDigest == platformEntry.Digest {
		result.Status = "verified"
		result.DigestMatch = true
	} else {
		result.Status = "digest_mismatch"
		result.DigestMatch = false
		result.Error = "installed binary does not match lockfile digest"
	}

	return result, nil
}

// findConfigFile finds epack.yaml or collectors.yaml in the project root.
func findConfigFile(projectRoot string) (string, error) {
	for _, name := range []string{"epack.yaml", "collectors.yaml"} {
		path := filepath.Join(projectRoot, name)
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("no epack.yaml or collectors.yaml found")
}

// GetConfiguredToolNames returns the names of tools configured in epack.yaml.
// Searches upward from workDir to find project root.
// Returns nil if no epack.yaml is found or if there's an error loading it.
func GetConfiguredToolNames(workDir string) []string {
	if workDir == "" {
		var err error
		workDir, err = os.Getwd()
		if err != nil {
			return nil
		}
	}

	projectRoot, err := project.FindRoot(workDir)
	if err != nil {
		return nil
	}

	configPath := filepath.Join(projectRoot, "epack.yaml")
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil
	}

	names := make([]string, 0, len(cfg.Tools))
	for name := range cfg.Tools {
		names = append(names, name)
	}
	sort.Strings(names) // Deterministic ordering for tab completion
	return names
}

// ToolProvenance contains source/provenance information about a tool from the lockfile.
type ToolProvenance struct {
	Name         string              `json:"name"`
	Source       string              `json:"source,omitempty"`
	Version      string              `json:"version,omitempty"`
	ResolvedFrom *ProvenanceResolved `json:"resolved_from,omitempty"`
	Signing      *ProvenanceSigning  `json:"signing,omitempty"`
	Verification *ProvenanceVerify   `json:"verification,omitempty"`
}

// ProvenanceResolved contains resolution provenance.
type ProvenanceResolved struct {
	Registry   string `json:"registry,omitempty"`
	Descriptor string `json:"descriptor,omitempty"`
}

// ProvenanceSigning contains signing identity information.
type ProvenanceSigning struct {
	Issuer              string `json:"issuer,omitempty"`
	Subject             string `json:"subject,omitempty"`
	SourceRepositoryURI string `json:"source_repository_uri,omitempty"`
	SourceRepositoryRef string `json:"source_repository_ref,omitempty"`
}

// ProvenanceVerify contains verification status.
type ProvenanceVerify struct {
	Status     string `json:"status,omitempty"`
	VerifiedAt string `json:"verified_at,omitempty"`
}

// GetToolProvenance retrieves provenance information for a tool from the lockfile.
// Searches upward from workDir to find project root.
// Returns an error if the tool is not found in the lockfile.
func GetToolProvenance(toolName, workDir string) (*ToolProvenance, error) {
	// Validate tool name
	if err := config.ValidateToolName(toolName); err != nil {
		return nil, fmt.Errorf("invalid tool name: %w", err)
	}

	if workDir == "" {
		var err error
		workDir, err = os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("getting working directory: %w", err)
		}
	}

	projectRoot, err := project.FindRoot(workDir)
	if err != nil {
		return nil, fmt.Errorf("not in an epack project (no epack.yaml found)")
	}

	lockfilePath := filepath.Join(projectRoot, lockfile.FileName)
	lf, err := lockfile.Load(lockfilePath)
	if err != nil {
		return nil, fmt.Errorf("no lockfile found: %w", err)
	}

	locked, ok := lf.GetTool(toolName)
	if !ok {
		return nil, fmt.Errorf("tool not found in lockfile")
	}

	prov := &ToolProvenance{
		Name:    toolName,
		Source:  locked.Source,
		Version: locked.Version,
	}

	// Populate resolved_from
	if locked.ResolvedFrom != nil {
		prov.ResolvedFrom = &ProvenanceResolved{
			Registry:   locked.ResolvedFrom.Registry,
			Descriptor: locked.ResolvedFrom.Descriptor,
		}
	}

	// Populate signing
	if locked.Signer != nil {
		prov.Signing = &ProvenanceSigning{
			Issuer:              locked.Signer.Issuer,
			Subject:             locked.Signer.Subject,
			SourceRepositoryURI: locked.Signer.SourceRepositoryURI,
			SourceRepositoryRef: locked.Signer.SourceRepositoryRef,
		}
	}

	// Populate verification
	if locked.Verification != nil {
		prov.Verification = &ProvenanceVerify{
			Status:     locked.Verification.Status,
			VerifiedAt: locked.Verification.VerifiedAt,
		}
	}

	return prov, nil
}
