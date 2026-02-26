package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/locktivity/epack/internal/execsafe"
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/safeyaml"
)

// JobConfig is the top-level epack.yaml model for collector and tool configuration.
// Note: The file may be named collectors.yaml (legacy) or epack.yaml (preferred).
type JobConfig struct {
	Stream     string                     `yaml:"stream"`
	Output     string                     `yaml:"output,omitempty"`
	Platforms  []string                   `yaml:"platforms,omitempty"`
	Signing    SigningConfig              `yaml:"signing"`
	Collectors map[string]CollectorConfig `yaml:"collectors"`
	Tools      map[string]ToolConfig      `yaml:"tools,omitempty"`

	// Remotes configures remote registries for push/pull operations.
	// Each remote maps a name to its configuration.
	Remotes map[string]RemoteConfig `yaml:"remotes,omitempty"`

	// Environments provides per-environment config overrides.
	// Used with --env flag to override remote targets, labels, etc.
	Environments map[string]EnvironmentConfig `yaml:"environments,omitempty"`

	// Registry specifies an alternative registry for resolving collector/tool sources.
	// If empty, sources are resolved from GitHub releases. Not yet implemented.
	Registry string `yaml:"registry,omitempty"`

	// Registries specifies multiple registries for resolution with priority order.
	// First registry to resolve a component wins. Not yet implemented.
	Registries []RegistryConfig `yaml:"registries,omitempty"`

	// ToolPolicy configures tool access restrictions.
	// Not yet implemented - reserved for future use.
	ToolPolicy *ToolPolicy `yaml:"tool_policy,omitempty"`
}

// RegistryConfig configures a component registry.
// Reserved for future multi-registry support.
type RegistryConfig struct {
	// Name is the registry identifier (e.g., "locktivity", "github").
	Name string `yaml:"name"`

	// URL is the registry endpoint URL.
	URL string `yaml:"url,omitempty"`

	// Priority determines resolution order (lower = higher priority).
	// If not specified, order in the registries array is used.
	Priority int `yaml:"priority,omitempty"`

	// Auth specifies authentication method.
	// Options: "none", "token", "oidc". Not yet implemented.
	Auth string `yaml:"auth,omitempty"`
}

// ToolPolicy configures tool access restrictions.
// Reserved for future tool policy support.
type ToolPolicy struct {
	// Mode specifies the policy enforcement mode.
	// Options: "permissive" (allow unknown, warn), "strict" (deny unknown).
	// Not yet implemented.
	Mode string `yaml:"mode,omitempty"`

	// Allow specifies tools that are always allowed.
	// Supports glob patterns (e.g., "locktivity/*").
	// Not yet implemented.
	Allow []string `yaml:"allow,omitempty"`

	// Deny specifies tools that are always denied.
	// Takes precedence over Allow. Supports glob patterns.
	// Not yet implemented.
	Deny []string `yaml:"deny,omitempty"`
}

// SigningConfig configures pack signing.
type SigningConfig struct {
	Enabled bool   `yaml:"enabled"`
	Method  string `yaml:"method"`
}

// CollectorConfig declares either a source-based collector or an external binary.
type CollectorConfig struct {
	Source  string         `yaml:"source,omitempty"`
	Binary  string         `yaml:"binary,omitempty"`
	Config  map[string]any `yaml:"config,omitempty"`
	Secrets []string       `yaml:"secrets,omitempty"` // Env var names to pass through to collector
}

// ToolConfig declares a source-based tool.
// Tools are binaries that operate on packs (e.g., epack-tool-ai, epack-tool-policy).
type ToolConfig struct {
	Source  string         `yaml:"source,omitempty"`
	Binary  string         `yaml:"binary,omitempty"`
	Config  map[string]any `yaml:"config,omitempty"`  // Config values passed as EPACK_CFG_* env vars
	Secrets []string       `yaml:"secrets,omitempty"` // Env var names to pass as EPACK_SECRET_* vars
}

// RemoteConfig configures a remote registry for push/pull operations.
type RemoteConfig struct {
	// Source is the component source reference (e.g., "locktivity/epack-remote-locktivity@v1").
	// When set, the adapter binary is managed through the lockfile and sync system.
	// Mutually exclusive with Binary.
	Source string `yaml:"source,omitempty"`

	// Binary is the path to an external adapter binary.
	// Use this for locally-built or unmanaged adapters.
	// Mutually exclusive with Source.
	Binary string `yaml:"binary,omitempty"`

	// Adapter is the adapter name (e.g., "locktivity", "s3", "filesystem").
	// Maps to binary epack-remote-<adapter>.
	// If Source is set and Adapter is empty, it's inferred from the source.
	Adapter string `yaml:"adapter,omitempty"`

	// Target specifies the default target workspace/environment.
	Target RemoteTarget `yaml:"target,omitempty"`

	// Endpoint is an optional endpoint URL override.
	// Useful for enterprise deployments or regional control planes.
	Endpoint string `yaml:"endpoint,omitempty"`

	// Auth configures authentication preferences.
	Auth RemoteAuth `yaml:"auth,omitempty"`

	// Verify configures pre-push verification.
	Verify RemoteVerify `yaml:"verify,omitempty"`

	// Release configures default release metadata.
	Release RemoteRelease `yaml:"release,omitempty"`

	// Runs configures run syncing behavior.
	Runs RemoteRuns `yaml:"runs,omitempty"`

	// Extensions contains adapter-specific configuration.
	Extensions map[string]any `yaml:"extensions,omitempty"`

	// Transport configures transport-level security for adapter URLs.
	// SECURITY: Controls file:// URL confinement and loopback HTTP permissions.
	Transport RemoteTransport `yaml:"transport,omitempty"`

	// Secrets is a list of env var names to pass through to the remote adapter.
	// These are passed as-is (not renamed) to allow adapter-specific auth.
	Secrets []string `yaml:"secrets,omitempty"`
}

// RemoteTarget specifies the target workspace/environment.
type RemoteTarget struct {
	// Workspace is the target workspace (e.g., "acme").
	Workspace string `yaml:"workspace,omitempty"`

	// Environment is the target environment (e.g., "prod", "staging").
	Environment string `yaml:"environment,omitempty"`
}

// RemoteAuth configures authentication preferences.
type RemoteAuth struct {
	// Mode is the authentication mode.
	// Values: "device_code", "oidc", "api_key"
	Mode string `yaml:"mode,omitempty"`

	// Profile is an optional named credential profile (adapter-specific).
	Profile string `yaml:"profile,omitempty"`

	// OIDC contains OIDC-specific settings.
	OIDC *RemoteAuthOIDC `yaml:"oidc,omitempty"`

	// APIKey contains API key settings.
	APIKey *RemoteAuthAPIKey `yaml:"api_key,omitempty"`
}

// RemoteAuthOIDC contains OIDC authentication settings.
type RemoteAuthOIDC struct {
	// Provider is the OIDC provider name.
	// Values: "github_actions", "circleci", "generic"
	Provider string `yaml:"provider,omitempty"`

	// Audience is the expected audience claim.
	Audience string `yaml:"audience,omitempty"`
}

// RemoteAuthAPIKey contains API key authentication settings.
type RemoteAuthAPIKey struct {
	// Env is the environment variable containing the API key.
	// epack never stores the key; the adapter reads the env var.
	Env string `yaml:"env,omitempty"`
}

// RemoteVerify configures pre-push verification.
type RemoteVerify struct {
	// Pack enables pack verification before upload.
	Pack bool `yaml:"pack,omitempty"`

	// Strict fails on warnings (not just errors).
	Strict bool `yaml:"strict,omitempty"`
}

// RemoteRelease configures default release metadata.
type RemoteRelease struct {
	// Labels are default labels to apply to releases.
	Labels []string `yaml:"labels,omitempty"`

	// Notes are default release notes.
	Notes string `yaml:"notes,omitempty"`

	// Source configures source control metadata.
	Source *RemoteReleaseSource `yaml:"source,omitempty"`
}

// RemoteReleaseSource configures source control metadata for releases.
type RemoteReleaseSource struct {
	// Git contains Git source settings.
	Git *RemoteSourceGit `yaml:"git,omitempty"`

	// CI contains CI source settings.
	CI *RemoteSourceCI `yaml:"ci,omitempty"`
}

// RemoteSourceGit configures Git source metadata.
type RemoteSourceGit struct {
	// SHAEnv is the env var containing the Git SHA.
	SHAEnv string `yaml:"sha_env,omitempty"`

	// RepoEnv is the env var containing the repository name.
	RepoEnv string `yaml:"repo_env,omitempty"`
}

// RemoteSourceCI configures CI source metadata.
type RemoteSourceCI struct {
	// RunURLEnv is the env var containing the CI run URL.
	RunURLEnv string `yaml:"run_url_env,omitempty"`
}

// RemoteRuns configures run syncing behavior.
type RemoteRuns struct {
	// Sync enables automatic run syncing after push.
	// Defaults to true.
	Sync *bool `yaml:"sync,omitempty"`

	// Paths specifies glob patterns for finding result.json files.
	// Defaults to [".epack/runs/**/result.json"]
	Paths []string `yaml:"paths,omitempty"`

	// RequireSuccess fails push if run sync fails.
	RequireSuccess bool `yaml:"require_success,omitempty"`
}

// RemoteTransport configures transport-level security for adapter URLs.
type RemoteTransport struct {
	// FileRoot constrains file:// URLs from this adapter to this directory.
	// If set, any file:// URL path must be under this root directory.
	// SECURITY: Prevents adapters from directing reads/writes outside expected areas.
	FileRoot string `yaml:"file_root,omitempty"`

	// AllowLoopbackHTTP permits http:// URLs to localhost/127.0.0.1/::1.
	// SECURITY WARNING: Only enable for local development remotes.
	// Default: false (loopback HTTP is rejected).
	AllowLoopbackHTTP bool `yaml:"allow_loopback_http,omitempty"`
}

// SyncEnabled returns true if run syncing is enabled (default true).
func (r *RemoteRuns) SyncEnabled() bool {
	if r.Sync == nil {
		return true // Default to enabled
	}
	return *r.Sync
}

// EffectiveAdapter returns the adapter name for this remote.
// If Adapter is explicitly set, it's returned.
// If Source is set, the adapter name is inferred from the source repo name
// (e.g., "locktivity/epack-remote-locktivity@v1" -> "locktivity").
// Returns empty string if neither Source nor Adapter is set.
func (r *RemoteConfig) EffectiveAdapter() string {
	if r.Adapter != "" {
		return r.Adapter
	}
	if r.Source != "" {
		return inferAdapterFromSource(r.Source)
	}
	return ""
}

// inferAdapterFromSource extracts the adapter name from a source reference.
// For "locktivity/epack-remote-locktivity@v1", returns "locktivity".
// For "org/custom-adapter@v1", returns "custom-adapter".
func inferAdapterFromSource(source string) string {
	// Remove version suffix
	s := source
	if idx := strings.Index(s, "@"); idx != -1 {
		s = s[:idx]
	}
	// Get the repo name (after the last /)
	if idx := strings.LastIndex(s, "/"); idx != -1 {
		s = s[idx+1:]
	}
	// Remove "epack-remote-" prefix if present
	s = strings.TrimPrefix(s, "epack-remote-")
	return s
}

// EnvironmentConfig provides per-environment config overrides.
type EnvironmentConfig struct {
	// Remotes overrides remote configurations for this environment.
	Remotes map[string]RemoteConfig `yaml:"remotes,omitempty"`
}

// Load reads and validates an epack config file (collectors and tools).
func Load(path string) (*JobConfig, error) {
	// Check file size before reading to prevent DoS via large files
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	if info.Size() > limits.ConfigFile.Bytes() {
		return nil, fmt.Errorf("config file too large: %d bytes exceeds limit of %d bytes",
			info.Size(), limits.ConfigFile.Bytes())
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	return Parse(data)
}

// Parse validates raw epack config YAML and enforces size/structure limits
// before returning a JobConfig for collectors and tools.
func Parse(data []byte) (*JobConfig, error) {
	// SECURITY: Use safeyaml which validates size and alias bombs BEFORE parsing.
	var cfg JobConfig
	if err := safeyaml.Unmarshal(data, limits.ConfigFile, &cfg); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}

	// NOTE: We intentionally do NOT expand ${VAR} patterns in config values.
	// This was removed for security reasons:
	// 1. Config values containing secrets could leak via error messages or logs
	// 2. The secrets: block provides better auditability
	// 3. Only explicitly listed secrets are passed to collectors/tools

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate checks required fields and source/binary exclusivity.
func (c *JobConfig) Validate() error {
	// At least one collector, tool, or remote must be defined
	if len(c.Collectors) == 0 && len(c.Tools) == 0 && len(c.Remotes) == 0 {
		return fmt.Errorf("config: at least one collector, tool, or remote is required")
	}

	// SECURITY: Enforce collector count limit to prevent DoS
	if len(c.Collectors) > limits.MaxCollectorCount {
		return fmt.Errorf("collectors: count %d exceeds limit of %d",
			len(c.Collectors), limits.MaxCollectorCount)
	}

	// SECURITY: Enforce tool count limit to prevent DoS
	if len(c.Tools) > limits.MaxToolCount {
		return fmt.Errorf("tools: count %d exceeds limit of %d",
			len(c.Tools), limits.MaxToolCount)
	}

	// SECURITY: Enforce remote count limit to prevent DoS
	if len(c.Remotes) > limits.MaxRemoteCount {
		return fmt.Errorf("remotes: count %d exceeds limit of %d",
			len(c.Remotes), limits.MaxRemoteCount)
	}

	if err := c.validatePlatforms(); err != nil {
		return err
	}
	if err := c.validateCollectors(); err != nil {
		return err
	}
	if err := c.validateTools(); err != nil {
		return err
	}
	if err := c.validateRemotes(); err != nil {
		return err
	}
	return c.validateEnvironmentOverrides()
}

func (c *JobConfig) validatePlatforms() error {
	for _, platform := range c.Platforms {
		if err := ValidatePlatform(platform); err != nil {
			return err
		}
	}
	return nil
}

func (c *JobConfig) validateCollectors() error {
	for name, collector := range c.Collectors {
		// Validate collector name to prevent path traversal
		if err := ValidateCollectorName(name); err != nil {
			return fmt.Errorf("collector %q: %w", name, err)
		}

		switch {
		case collector.Source == "" && collector.Binary == "":
			return fmt.Errorf("collector %q: exactly one of source or binary must be set", name)
		case collector.Source != "" && collector.Binary != "":
			return fmt.Errorf("collector %q: source and binary are mutually exclusive", name)
		}

		// SECURITY: Validate secret names to prevent passing dangerous env vars
		// like PATH, LD_PRELOAD, or EPACK_* protocol variables.
		if err := execsafe.ValidateSecretNames(collector.Secrets); err != nil {
			return fmt.Errorf("collector %q: %w", name, err)
		}
	}
	return nil
}

func (c *JobConfig) validateTools() error {
	for name, tool := range c.Tools {
		// Validate tool name to prevent path traversal
		if err := ValidateToolName(name); err != nil {
			return fmt.Errorf("tool %q: %w", name, err)
		}

		switch {
		case tool.Source == "" && tool.Binary == "":
			return fmt.Errorf("tool %q: exactly one of source or binary must be set", name)
		case tool.Source != "" && tool.Binary != "":
			return fmt.Errorf("tool %q: source and binary are mutually exclusive", name)
		}

		// SECURITY: Validate secret names to prevent passing dangerous env vars
		// like PATH, LD_PRELOAD, or EPACK_* protocol variables.
		if err := execsafe.ValidateSecretNames(tool.Secrets); err != nil {
			return fmt.Errorf("tool %q: %w", name, err)
		}
	}
	return nil
}

func (c *JobConfig) validateRemotes() error {
	for name, remote := range c.Remotes {
		if err := ValidateRemoteName(name); err != nil {
			return fmt.Errorf("remote %q: %w", name, err)
		}

		// Validate source/binary exclusivity (same pattern as collectors/tools)
		switch {
		case remote.Source == "" && remote.Binary == "":
			// Adapter-only mode: adapter name is required if no source/binary
			if remote.Adapter == "" {
				return fmt.Errorf("remote %q: one of source, binary, or adapter must be set", name)
			}
		case remote.Source != "" && remote.Binary != "":
			return fmt.Errorf("remote %q: source and binary are mutually exclusive", name)
		}

		// Validate adapter name if explicitly set
		if remote.Adapter != "" {
			if err := ValidateRemoteName(remote.Adapter); err != nil {
				return fmt.Errorf("remote %q: invalid adapter name: %w", name, err)
			}
		}

		// SECURITY: Validate secret names to prevent passing dangerous env vars
		// like PATH, LD_PRELOAD, or EPACK_* protocol variables.
		if err := execsafe.ValidateSecretNames(remote.Secrets); err != nil {
			return fmt.Errorf("remote %q: %w", name, err)
		}
	}
	return nil
}

func (c *JobConfig) validateEnvironmentOverrides() error {
	for envName, envCfg := range c.Environments {
		if err := ValidateEnvironmentName(envName); err != nil {
			return fmt.Errorf("environment %q: %w", envName, err)
		}
		for remoteName, remote := range envCfg.Remotes {
			if err := ValidateRemoteName(remoteName); err != nil {
				return fmt.Errorf("environment %q remote %q: %w", envName, remoteName, err)
			}
			// Adapter is optional in overrides (inherits from base)
			if remote.Adapter != "" {
				if err := ValidateRemoteName(remote.Adapter); err != nil {
					return fmt.Errorf("environment %q remote %q: invalid adapter name: %w", envName, remoteName, err)
				}
			}
		}
	}
	return nil
}

// HasSourceCollectors returns true if any collectors use source (not external binary).
func (c *JobConfig) HasSourceCollectors() bool {
	for _, collector := range c.Collectors {
		if collector.Source != "" {
			return true
		}
	}
	return false
}

// HasSourceTools returns true if any tools use source (not external binary).
func (c *JobConfig) HasSourceTools() bool {
	for _, tool := range c.Tools {
		if tool.Source != "" {
			return true
		}
	}
	return false
}

// HasSourceRemotes returns true if any remotes use source (not external binary).
func (c *JobConfig) HasSourceRemotes() bool {
	for _, remote := range c.Remotes {
		if remote.Source != "" {
			return true
		}
	}
	return false
}

// HasSourceComponents returns true if any collectors, tools, or remotes use source.
func (c *JobConfig) HasSourceComponents() bool {
	return c.HasSourceCollectors() || c.HasSourceTools() || c.HasSourceRemotes()
}

// EffectiveRegistry returns the registry to use for component resolution.
// Precedence: EPACK_REGISTRY env > project config > global config > "github" default.
// globalRegistry is loaded from ~/.config/epack/config.yaml (not yet implemented).
func (c *JobConfig) EffectiveRegistry(globalRegistry string) string {
	// Environment variable takes highest precedence
	if envRegistry := os.Getenv("EPACK_REGISTRY"); envRegistry != "" {
		return envRegistry
	}

	// Project config (epack.yaml registry field)
	if c.Registry != "" {
		return c.Registry
	}

	// Global config (~/.config/epack/config.yaml)
	if globalRegistry != "" {
		return globalRegistry
	}

	// Default to GitHub
	return "github"
}
