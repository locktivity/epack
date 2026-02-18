package remote

// Capabilities describes what features a remote adapter supports.
// This is returned by the --capabilities command.
type Capabilities struct {
	// Name is the adapter name (e.g., "locktivity").
	Name string `json:"name"`

	// Kind identifies this as a deploy adapter.
	Kind string `json:"kind"` // "remote_adapter"

	// DeployProtocolVersion is the protocol version supported by this adapter.
	DeployProtocolVersion int `json:"deploy_protocol_version"`

	// Features indicates which optional features are supported.
	Features CapabilityFeatures `json:"features"`

	// Auth describes authentication options.
	Auth CapabilityAuth `json:"auth,omitempty"`

	// Limits describes operational limits.
	Limits CapabilityLimits `json:"limits,omitempty"`

	// Extensions contains adapter-specific capabilities.
	Extensions map[string]any `json:"extensions,omitempty"`
}

// CapabilityFeatures indicates which protocol features are supported.
type CapabilityFeatures struct {
	// PrepareFinalize indicates support for the two-phase upload protocol.
	// If true, adapter supports push.prepare + push.finalize.
	// If false, adapter uses direct upload (not recommended).
	PrepareFinalize bool `json:"prepare_finalize"`

	// DirectUpload indicates the adapter handles upload itself.
	// Mutually exclusive with PrepareFinalize for primary upload mode.
	DirectUpload bool `json:"direct_upload"`

	// Pull indicates support for the two-phase download protocol.
	// If true, adapter supports pull.prepare + pull.finalize.
	Pull bool `json:"pull"`

	// RunsSync indicates support for run ledger syncing.
	RunsSync bool `json:"runs_sync"`

	// AuthLogin indicates support for interactive authentication.
	AuthLogin bool `json:"auth_login"`

	// Whoami indicates support for identity query.
	Whoami bool `json:"whoami"`
}

// CapabilityAuth describes authentication options.
type CapabilityAuth struct {
	// Modes lists supported authentication methods.
	// Values: "device_code", "oidc_token", "api_key"
	Modes []string `json:"modes,omitempty"`

	// TokenStorage describes how tokens are stored.
	// Values: "os_keychain", "encrypted_file", "env_var"
	TokenStorage string `json:"token_storage,omitempty"`
}

// CapabilityLimits describes operational limits.
type CapabilityLimits struct {
	// MaxPackBytes is the maximum pack size supported (0 = unlimited).
	MaxPackBytes int64 `json:"max_pack_bytes,omitempty"`

	// MaxRunsPerSync is the maximum runs per sync request (0 = unlimited).
	MaxRunsPerSync int `json:"max_runs_per_sync,omitempty"`
}

// SupportsProtocolVersion returns true if the adapter supports the given protocol version.
func (c *Capabilities) SupportsProtocolVersion(version int) bool {
	return c.DeployProtocolVersion >= version
}

// SupportsPrepareFinalize returns true if the adapter uses the two-phase upload protocol.
func (c *Capabilities) SupportsPrepareFinalize() bool {
	return c.Features.PrepareFinalize
}

// SupportsRunsSync returns true if the adapter supports run syncing.
func (c *Capabilities) SupportsRunsSync() bool {
	return c.Features.RunsSync
}

// SupportsPull returns true if the adapter supports the two-phase download protocol.
func (c *Capabilities) SupportsPull() bool {
	return c.Features.Pull
}

// SupportsAuthLogin returns true if the adapter supports interactive authentication.
func (c *Capabilities) SupportsAuthLogin() bool {
	return c.Features.AuthLogin
}

// SupportsWhoami returns true if the adapter supports identity query.
func (c *Capabilities) SupportsWhoami() bool {
	return c.Features.Whoami
}

// SupportsAuthMode returns true if the adapter supports the given auth mode.
func (c *Capabilities) SupportsAuthMode(mode string) bool {
	for _, m := range c.Auth.Modes {
		if m == mode {
			return true
		}
	}
	return false
}
