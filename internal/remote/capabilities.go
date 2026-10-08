package remote

import (
	"fmt"
	"strings"
	"unicode"
)

// Capabilities describes what features a remote adapter supports.
// This is returned by the --capabilities command.
type Capabilities struct {
	// Name is the adapter name (e.g., "locktivity").
	Name string `json:"name"`

	// Kind identifies this as a deploy adapter.
	Kind string `json:"kind"` // "remote_adapter"

	// DeployProtocolVersion is the protocol version supported by this adapter.
	DeployProtocolVersion int `json:"deploy_protocol_version"`

	// Version is the adapter's release, as the adapter reports it.
	Version string `json:"version,omitempty"`

	// Features indicates which optional features are supported.
	Features CapabilityFeatures `json:"features"`

	// Auth describes authentication options.
	Auth CapabilityAuth `json:"auth,omitempty"`

	// Limits describes operational limits.
	Limits CapabilityLimits `json:"limits,omitempty"`

	// Extensions contains adapter-specific capabilities.
	Extensions map[string]any `json:"extensions,omitempty"`

	// FilesDir is the one hidden folder a fetched configuration from this
	// remote may carry, for the remote's own bookkeeping (Locktivity's
	// ".locktivity"). Every other hidden path in a pull is refused.
	FilesDir string `json:"files_dir,omitempty"`
}

// MaxFilesDirLength bounds the folder name a remote may declare.
const MaxFilesDirLength = 64

// ValidateFilesDir checks a declared files folder: one hidden segment that
// is not epack's or git's own.
func ValidateFilesDir(name string) error {
	switch {
	case name == "":
		return nil
	case len(name) > MaxFilesDirLength:
		return fmt.Errorf("files_dir %q is longer than %d characters", name, MaxFilesDirLength)
	case !strings.HasPrefix(name, "."):
		return fmt.Errorf("files_dir %q must be a hidden folder", name)
	case name == "." || name == ".." || name == ".epack" || name == ".git":
		return fmt.Errorf("files_dir %q is reserved", name)
	case strings.ContainsAny(name, "/\\"):
		return fmt.Errorf("files_dir %q must be a single folder name", name)
	}
	for _, r := range name {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return fmt.Errorf("files_dir %q contains a character epack does not accept", name)
		}
	}
	return nil
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

	// LockReport indicates support for lockfile provenance reports.
	LockReport bool `json:"lock_report"`

	// AuthLogin indicates support for interactive authentication.
	AuthLogin bool `json:"auth_login"`

	// AuthBrowser indicates auth.login starts a browser sign-in that returns
	// to a loopback redirect, and auth.complete finishes it.
	AuthBrowser bool `json:"auth_browser,omitempty"`

	// Whoami indicates support for identity query.
	Whoami bool `json:"whoami"`

	// ConfigPull indicates the adapter can hand over a named configuration
	// (config.pull).
	ConfigPull bool `json:"config_pull,omitempty"`

	// Keys indicates the adapter can register, list, retire, and revoke the
	// signing keys a pipeline accepts (key.register, key.list, key.retire,
	// key.revoke).
	Keys bool `json:"keys,omitempty"`

	// CredentialsResolve indicates the adapter resolves a configuration's
	// managed credentials with its sign-in (credentials.resolve).
	CredentialsResolve bool `json:"credentials_resolve,omitempty"`
}

// CapabilityAuth describes authentication options.
type CapabilityAuth struct {
	// Modes lists supported authentication methods.
	// Values: "browser" (the browser sign-in with a loopback redirect),
	// "oidc_token", "api_key"
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

// SupportsLockReport returns true if the adapter supports lockfile provenance reports.
func (c *Capabilities) SupportsLockReport() bool {
	return c.Features.LockReport
}

// SupportsKeys returns true if the adapter manages signing keys.
func (c *Capabilities) SupportsKeys() bool {
	return c.Features.Keys
}

// SupportsCredentialsResolve returns true if the adapter resolves managed
// credentials with its sign-in.
func (c *Capabilities) SupportsCredentialsResolve() bool {
	return c.Features.CredentialsResolve
}

// SupportsPull returns true if the adapter supports the two-phase download protocol.
func (c *Capabilities) SupportsPull() bool {
	return c.Features.Pull
}

// SupportsAuthLogin returns true if the adapter supports interactive authentication.
func (c *Capabilities) SupportsAuthLogin() bool {
	return c.Features.AuthLogin
}

// SupportsAuthBrowser returns true if the adapter signs in through the browser
// with a loopback redirect (auth.login and auth.complete).
func (c *Capabilities) SupportsAuthBrowser() bool {
	return c.Features.AuthBrowser
}

// SupportsWhoami returns true if the adapter supports identity query.
func (c *Capabilities) SupportsWhoami() bool {
	return c.Features.Whoami
}

// SupportsConfigPull returns true if the adapter can hand over a named configuration.
func (c *Capabilities) SupportsConfigPull() bool {
	return c.Features.ConfigPull
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
