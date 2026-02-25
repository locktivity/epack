// Package remote implements the Remote Adapter Protocol v1 for epack push/pull operations.
//
// Remote adapters are external binaries (epack-remote-<name>) that handle communication
// with remote registries. The protocol uses JSON over stdin/stdout for all commands.
//
// Commands:
//   - --capabilities: Returns adapter capabilities (required)
//   - push.prepare: Get presigned upload URL
//   - push.finalize: Finalize upload and create release
//   - pull.prepare: Get presigned download URL
//   - pull.finalize: Confirm download completion
//   - runs.sync: Sync run ledgers to remote
//   - auth.login: Authenticate with remote (adapter-managed)
//   - auth.whoami: Show current identity
package remote

import (
	"time"
)

// ProtocolVersion is the current version of the Remote Adapter Protocol.
const ProtocolVersion = 1

// Command types for adapter invocation.
const (
	CommandCapabilities = "--capabilities"
	CommandPushPrepare  = "push.prepare"
	CommandPushFinalize = "push.finalize"
	CommandPullPrepare  = "pull.prepare"
	CommandPullFinalize = "pull.finalize"
	CommandRunsSync     = "runs.sync"
	CommandAuthLogin    = "auth.login"
	CommandAuthWhoami   = "auth.whoami"
)

// Request type strings.
const (
	TypePushPrepare  = "push.prepare"
	TypePushFinalize = "push.finalize"
	TypePullPrepare  = "pull.prepare"
	TypePullFinalize = "pull.finalize"
	TypeRunsSync     = "runs.sync"
	TypeAuthLogin    = "auth.login"
	TypeAuthWhoami   = "auth.whoami"
)

// Response type strings.
const (
	TypePushPrepareResult  = "push.prepare.result"
	TypePushFinalizeResult = "push.finalize.result"
	TypePullPrepareResult  = "pull.prepare.result"
	TypePullFinalizeResult = "pull.finalize.result"
	TypeRunsSyncResult     = "runs.sync.result"
	TypeAuthLoginResult    = "auth.login.result"
	TypeAuthWhoamiResult   = "auth.whoami.result"
	TypeError              = "error"
)

// Error codes returned by adapters.
const (
	ErrCodeUnsupportedProtocol = "unsupported_protocol"
	ErrCodeInvalidRequest      = "invalid_request"
	ErrCodeAuthRequired        = "auth_required"
	ErrCodeForbidden           = "forbidden"
	ErrCodeNotFound            = "not_found"
	ErrCodeConflict            = "conflict"
	ErrCodeRateLimited         = "rate_limited"
	ErrCodeServerError         = "server_error"
	ErrCodeNetworkError        = "network_error"
)

// TargetConfig specifies the remote target (workspace/environment).
type TargetConfig struct {
	Workspace   string `json:"workspace,omitempty"`
	Environment string `json:"environment,omitempty"`
}

// PackInfo contains pack metadata for push operations.
type PackInfo struct {
	Path      string `json:"path"`
	Digest    string `json:"digest"`
	SizeBytes int64  `json:"size_bytes"`
}

// ReleaseInfo contains release metadata for push operations.
type ReleaseInfo struct {
	Labels []string    `json:"labels,omitempty"`
	Notes  string      `json:"notes,omitempty"`
	Source *SourceInfo `json:"source,omitempty"`
}

// SourceInfo contains source control metadata.
type SourceInfo struct {
	GitSHA   string `json:"git_sha,omitempty"`
	CIRunURL string `json:"ci_run_url,omitempty"`
}

// AuthHints contains authentication hints for adapter requests.
// This is passed to adapters to help them authenticate with remotes.
type AuthHints struct {
	Mode   string            `json:"mode,omitempty"`   // oidc_token, api_key, etc.
	Token  string            `json:"token,omitempty"`  // For OIDC mode
	Claims map[string]string `json:"claims,omitempty"` // OIDC claims
}

// RunInfo contains metadata about a single run to sync.
type RunInfo struct {
	RunID        string `json:"run_id"`
	ResultPath   string `json:"result_path"`
	ResultDigest string `json:"result_digest"`
}

// UploadInfo contains presigned upload details.
type UploadInfo struct {
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers,omitempty"`
	ExpiresAt *time.Time        `json:"expires_at,omitempty"`
}

// DownloadInfo contains presigned download details.
type DownloadInfo struct {
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers,omitempty"`
	ExpiresAt *time.Time        `json:"expires_at,omitempty"`
}

// PackRef specifies how to reference a pack for pull operations.
type PackRef struct {
	// Exactly one of these should be set
	Digest    string `json:"digest,omitempty"`     // Pull by exact digest (immutable)
	ReleaseID string `json:"release_id,omitempty"` // Pull by release ID
	Version   string `json:"version,omitempty"`    // Pull by semantic version
	Latest    bool   `json:"latest,omitempty"`     // Pull latest release
}

// PackMetadata contains pack information returned from pull.prepare.
type PackMetadata struct {
	Digest    string    `json:"digest"`
	SizeBytes int64     `json:"size_bytes"`
	Stream    string    `json:"stream"`
	CreatedAt time.Time `json:"created_at"`
	ReleaseID string    `json:"release_id,omitempty"`
	Version   string    `json:"version,omitempty"`
	Labels    []string  `json:"labels,omitempty"`
}

// ReleaseResult contains the result of a successful push.
type ReleaseResult struct {
	ReleaseID    string    `json:"release_id"`
	PackDigest   string    `json:"pack_digest"`
	CreatedAt    time.Time `json:"created_at"`
	CanonicalRef string    `json:"canonical_ref"`
}

// RunSyncItem contains the result of syncing a single run.
type RunSyncItem struct {
	RunID  string `json:"run_id"`
	Status string `json:"status"` // accepted, rejected, duplicate
}

// ActionHint provides guidance on how to resolve an error.
type ActionHint struct {
	Type    string `json:"type"` // run_command, open_url, etc.
	Command string `json:"command,omitempty"`
	URL     string `json:"url,omitempty"`
}

// AuthLoginInstructions provides device code flow instructions.
type AuthLoginInstructions struct {
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresInSecs   int    `json:"expires_in_seconds"`
}

// IdentityResult contains current authentication identity.
type IdentityResult struct {
	Authenticated bool   `json:"authenticated"`
	Subject       string `json:"subject,omitempty"`
	Issuer        string `json:"issuer,omitempty"`
	ExpiresAt     string `json:"expires_at,omitempty"`
}

// --- Request Types ---

// PrepareRequest is sent to initiate a push operation.
type PrepareRequest struct {
	Type            string       `json:"type"` // "push.prepare"
	ProtocolVersion int          `json:"protocol_version"`
	RequestID       string       `json:"request_id"`
	Remote          string       `json:"remote"`
	Target          TargetConfig `json:"target"`
	Pack            PackInfo     `json:"pack"`
	Release         ReleaseInfo  `json:"release"`
	Identity        *AuthHints   `json:"identity,omitempty"`
}

// FinalizeRequest is sent after successful upload to create the release.
type FinalizeRequest struct {
	Type            string       `json:"type"` // "push.finalize"
	ProtocolVersion int          `json:"protocol_version"`
	RequestID       string       `json:"request_id"`
	Remote          string       `json:"remote"`
	Target          TargetConfig `json:"target"`
	Pack            PackInfo     `json:"pack"`
	FinalizeToken   string       `json:"finalize_token"`
}

// RunsSyncRequest is sent to sync run ledgers to the remote.
type RunsSyncRequest struct {
	Type            string       `json:"type"` // "runs.sync"
	ProtocolVersion int          `json:"protocol_version"`
	RequestID       string       `json:"request_id"`
	Target          TargetConfig `json:"target"`
	PackDigest      string       `json:"pack_digest"`
	Runs            []RunInfo    `json:"runs"`
}

// AuthLoginRequest initiates authentication with the remote.
type AuthLoginRequest struct {
	Type            string `json:"type"` // "auth.login"
	ProtocolVersion int    `json:"protocol_version"`
	RequestID       string `json:"request_id"`
}

// AuthWhoamiRequest queries the current authentication state.
type AuthWhoamiRequest struct {
	Type            string `json:"type"` // "auth.whoami"
	ProtocolVersion int    `json:"protocol_version"`
	RequestID       string `json:"request_id"`
}

// PullPrepareRequest is sent to initiate a pull operation.
type PullPrepareRequest struct {
	Type            string       `json:"type"` // "pull.prepare"
	ProtocolVersion int          `json:"protocol_version"`
	RequestID       string       `json:"request_id"`
	Remote          string       `json:"remote"`
	Target          TargetConfig `json:"target"`
	Ref             PackRef      `json:"ref"`
	Identity        *AuthHints   `json:"identity,omitempty"`
}

// PullFinalizeRequest is sent after successful download to confirm completion.
type PullFinalizeRequest struct {
	Type            string       `json:"type"` // "pull.finalize"
	ProtocolVersion int          `json:"protocol_version"`
	RequestID       string       `json:"request_id"`
	Remote          string       `json:"remote"`
	Target          TargetConfig `json:"target"`
	Digest          string       `json:"digest"`
	FinalizeToken   string       `json:"finalize_token"`
}

// --- Response Types ---

// PrepareResponse is returned from push.prepare.
type PrepareResponse struct {
	OK            bool       `json:"ok"`
	Type          string     `json:"type"` // "push.prepare.result"
	RequestID     string     `json:"request_id"`
	Upload        UploadInfo `json:"upload"`
	FinalizeToken string     `json:"finalize_token"`
}

// FinalizeResponse is returned from push.finalize.
type FinalizeResponse struct {
	OK         bool              `json:"ok"`
	Type       string            `json:"type"` // "push.finalize.result"
	RequestID  string            `json:"request_id"`
	Release    ReleaseResult     `json:"release"`
	Links      map[string]string `json:"links,omitempty"`
	Extensions map[string]any    `json:"extensions,omitempty"`
}

// PullPrepareResponse is returned from pull.prepare.
type PullPrepareResponse struct {
	OK            bool         `json:"ok"`
	Type          string       `json:"type"` // "pull.prepare.result"
	RequestID     string       `json:"request_id"`
	Download      DownloadInfo `json:"download"`
	Pack          PackMetadata `json:"pack"`
	FinalizeToken string       `json:"finalize_token"`
}

// PullFinalizeResponse is returned from pull.finalize.
type PullFinalizeResponse struct {
	OK        bool   `json:"ok"`
	Type      string `json:"type"` // "pull.finalize.result"
	RequestID string `json:"request_id"`
}

// RunsSyncResponse is returned from runs.sync.
type RunsSyncResponse struct {
	OK        bool          `json:"ok"`
	Type      string        `json:"type"` // "runs.sync.result"
	RequestID string        `json:"request_id"`
	Accepted  int           `json:"accepted"`
	Rejected  int           `json:"rejected"`
	Items     []RunSyncItem `json:"items"`
}

// AuthLoginResponse is returned from auth.login.
type AuthLoginResponse struct {
	OK           bool                  `json:"ok"`
	Type         string                `json:"type"` // "auth.login.result"
	RequestID    string                `json:"request_id"`
	Instructions AuthLoginInstructions `json:"instructions"`
}

// AuthWhoamiResponse is returned from auth.whoami.
type AuthWhoamiResponse struct {
	OK        bool           `json:"ok"`
	Type      string         `json:"type"` // "auth.whoami.result"
	RequestID string         `json:"request_id"`
	Identity  IdentityResult `json:"identity"`
}

// ErrorResponse is returned when an operation fails.
type ErrorResponse struct {
	OK        bool      `json:"ok"`   // Always false
	Type      string    `json:"type"` // "error"
	RequestID string    `json:"request_id"`
	Error     ErrorInfo `json:"error"`
}

// ErrorInfo contains error details.
type ErrorInfo struct {
	Code      string      `json:"code"`
	Message   string      `json:"message"`
	Retryable bool        `json:"retryable"`
	Action    *ActionHint `json:"action,omitempty"`
}

// IsRetryable returns true if the error is retryable.
func (e *ErrorInfo) IsRetryable() bool {
	return e.Retryable
}

// IsAuthRequired returns true if authentication is required.
func (e *ErrorInfo) IsAuthRequired() bool {
	return e.Code == ErrCodeAuthRequired
}
