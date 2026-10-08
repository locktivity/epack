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
//   - lock.report: Report lockfile provenance without pushing a pack
//   - auth.login: Start a browser sign-in that returns to a loopback redirect
//   - auth.complete: Finish a browser sign-in with the code the browser returned
//   - auth.whoami: Show current identity
//   - config.pull: Fetch a named configuration (files, shas, revision) from the remote
package remote

import (
	"time"

	"github.com/locktivity/epack/internal/lockprovenance"
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
	CommandLockReport   = "lock.report"
	CommandAuthLogin    = "auth.login"
	CommandAuthComplete = "auth.complete"
	CommandAuthWhoami   = "auth.whoami"
	CommandConfigPull   = "config.pull"
)

// Request type strings.
const (
	TypePushPrepare  = "push.prepare"
	TypePushFinalize = "push.finalize"
	TypePullPrepare  = "pull.prepare"
	TypePullFinalize = "pull.finalize"
	TypeRunsSync     = "runs.sync"
	TypeLockReport   = "lock.report"
	TypeAuthLogin    = "auth.login"
	TypeAuthComplete = "auth.complete"
	TypeAuthWhoami   = "auth.whoami"
	TypeConfigPull   = "config.pull"
)

// Response type strings.
const (
	TypePushPrepareResult  = "push.prepare.result"
	TypePushFinalizeResult = "push.finalize.result"
	TypePullPrepareResult  = "pull.prepare.result"
	TypePullFinalizeResult = "pull.finalize.result"
	TypeRunsSyncResult     = "runs.sync.result"
	TypeLockReportResult   = "lock.report.result"
	TypeAuthLoginResult    = "auth.login.result"
	TypeAuthCompleteResult = "auth.complete.result"
	TypeAuthWhoamiResult   = "auth.whoami.result"
	TypeConfigPullResult   = "config.pull.result"
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

// TargetConfig specifies the remote target (workspace/environment/stream).
type TargetConfig struct {
	Workspace   string `json:"workspace,omitempty"`
	Environment string `json:"environment,omitempty"`
	Stream      string `json:"stream,omitempty"`
}

// PackInfo contains pack metadata for push operations.
type PackInfo struct {
	Path           string `json:"path"`
	Digest         string `json:"digest"`                    // pack_digest: SHA256 of artifact content
	ManifestDigest string `json:"manifest_digest,omitempty"` // SHA256 of JCS-canonicalized manifest (primary identity)
	FileDigest     string `json:"file_digest,omitempty"`     // SHA256 of .epack file (differs from Digest when attestations added)
	SizeBytes      int64  `json:"size_bytes"`
	Checksum       string `json:"checksum,omitempty"` // Base64-encoded MD5 for upload verification
}

// ReleaseInfo contains release metadata for push operations.
type ReleaseInfo struct {
	Labels         []string                   `json:"labels,omitempty"`
	Notes          string                     `json:"notes,omitempty"`
	BuildContext   map[string]string          `json:"build_context,omitempty"`
	LockProvenance *lockprovenance.Provenance `json:"lock_provenance,omitempty"`
}

// AuthHints contains authentication hints for adapter requests.
// This is passed to adapters to help them authenticate with remotes.
type AuthHints struct {
	Mode  string `json:"mode,omitempty"`  // oidc_token, api_key, etc.
	Token string `json:"token,omitempty"` // For OIDC mode
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
	ExpiresAt string            `json:"expires_at,omitempty"`
}

// DownloadInfo contains presigned download details.
type DownloadInfo struct {
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers,omitempty"`
	ExpiresAt string            `json:"expires_at,omitempty"`
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

// AuthLoginInstructions start a browser sign-in. AuthorizationURL is the page
// the person allows epack on; State is also carried in that URL and comes back
// with the redirect. Session is the adapter's handle for the sign-in in
// flight: epack passes it back to auth.complete unchanged and never shows it.
type AuthLoginInstructions struct {
	AuthorizationURL string `json:"authorization_url"`
	State            string `json:"state"`
	Session          string `json:"session"`
	ExpiresInSecs    int    `json:"expires_in_seconds"`
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
	Release         ReleaseInfo  `json:"release,omitempty"`
	FinalizeToken   string       `json:"finalize_token"`
}

// RunsSyncRequest is sent to sync run ledgers to the remote.
type RunsSyncRequest struct {
	Type            string       `json:"type"` // "runs.sync"
	ProtocolVersion int          `json:"protocol_version"`
	RequestID       string       `json:"request_id"`
	Target          TargetConfig `json:"target"`
	FileDigest      string       `json:"file_digest"` // SHA256 of .epack file (unique pack identifier)
	Runs            []RunInfo    `json:"runs"`
}

// LockReportRequest is sent to report lockfile provenance without pushing a pack.
type LockReportRequest struct {
	Type            string                    `json:"type"` // "lock.report"
	ProtocolVersion int                       `json:"protocol_version"`
	RequestID       string                    `json:"request_id"`
	Remote          string                    `json:"remote"`
	Target          TargetConfig              `json:"target"`
	LockProvenance  lockprovenance.Provenance `json:"lock_provenance"`
	Identity        *AuthHints                `json:"identity,omitempty"`
}

// AuthLoginRequest starts a browser sign-in. RedirectURI is the loopback
// address epack listens on for the browser to return to.
type AuthLoginRequest struct {
	Type            string `json:"type"` // "auth.login"
	ProtocolVersion int    `json:"protocol_version"`
	RequestID       string `json:"request_id"`
	RedirectURI     string `json:"redirect_uri"`
}

// AuthCompleteRequest finishes a browser sign-in with the code and state the
// browser returned. The adapter exchanges the code and stores the credentials
// it gets.
type AuthCompleteRequest struct {
	Type            string `json:"type"` // "auth.complete"
	ProtocolVersion int    `json:"protocol_version"`
	RequestID       string `json:"request_id"`
	Session         string `json:"session"`
	Code            string `json:"code"`
	State           string `json:"state"`
}

// AuthWhoamiRequest queries the current authentication state.
type AuthWhoamiRequest struct {
	Type            string `json:"type"` // "auth.whoami"
	ProtocolVersion int    `json:"protocol_version"`
	RequestID       string `json:"request_id"`
}

// ConfigPullRequest asks the remote for a named configuration: the files a
// project folder is made of, with their shas and the revision they came from.
type ConfigPullRequest struct {
	Type            string           `json:"type"` // "config.pull"
	ProtocolVersion int              `json:"protocol_version"`
	RequestID       string           `json:"request_id"`
	Remote          string           `json:"remote"`
	Target          TargetConfig     `json:"target"`
	Config          ConfigPullTarget `json:"config"`
}

// ConfigPullTarget names the configuration to pull.
type ConfigPullTarget struct {
	Name string `json:"name"`
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
	Confirmed bool   `json:"confirmed"`
}

// RunsSyncResponse is returned from runs.sync.
type RunsSyncResponse struct {
	OK            bool           `json:"ok"`
	Type          string         `json:"type"` // "runs.sync.result"
	RequestID     string         `json:"request_id"`
	Accepted      int            `json:"accepted"`
	Rejected      int            `json:"rejected"`
	Items         []RunSyncItem  `json:"items"`
	FailedOutputs []FailedOutput `json:"failed_outputs,omitempty"`
}

// LockReportResponse is returned from lock.report.
type LockReportResponse struct {
	OK             bool   `json:"ok"`
	Type           string `json:"type"` // "lock.report.result"
	RequestID      string `json:"request_id"`
	Status         string `json:"status"`
	Outcome        string `json:"outcome,omitempty"`
	LockfileSHA256 string `json:"lockfile_sha256,omitempty"`
	RevisionID     string `json:"revision_id,omitempty"`
	PipelineURL    string `json:"pipeline_url,omitempty"`
}

// FailedOutput describes an output file that failed to upload or confirm.
type FailedOutput struct {
	RunID  string `json:"run_id"`
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// AuthLoginResponse is returned from auth.login.
type AuthLoginResponse struct {
	OK           bool                  `json:"ok"`
	Type         string                `json:"type"` // "auth.login.result"
	RequestID    string                `json:"request_id"`
	Instructions AuthLoginInstructions `json:"instructions"`
}

// AuthCompleteResponse is returned from auth.complete once the adapter has
// stored the credentials.
type AuthCompleteResponse struct {
	OK        bool           `json:"ok"`
	Type      string         `json:"type"` // "auth.complete.result"
	RequestID string         `json:"request_id"`
	Identity  IdentityResult `json:"identity"`
}

// AuthWhoamiResponse is returned from auth.whoami.
type AuthWhoamiResponse struct {
	OK        bool           `json:"ok"`
	Type      string         `json:"type"` // "auth.whoami.result"
	RequestID string         `json:"request_id"`
	Identity  IdentityResult `json:"identity"`
}

// ConfigPullResponse is returned from config.pull.
type ConfigPullResponse struct {
	OK        bool             `json:"ok"`
	Type      string           `json:"type"` // "config.pull.result"
	RequestID string           `json:"request_id"`
	Config    ConfigPullResult `json:"config"`
}

// ConfigPullResult is one revision of a named configuration. Files are keyed
// by path relative to the project folder and shas are SHA-256 hex digests of
// the managed files. Folder is where the same files live in a repository the
// remote also generates for, when it does.
type ConfigPullResult struct {
	ID       string            `json:"id,omitempty"`
	Name     string            `json:"name"`
	Title    string            `json:"title,omitempty"`
	Stream   string            `json:"stream,omitempty"`
	RunsIn   string            `json:"runs_in,omitempty"`
	Revision int               `json:"revision"`
	Folder   string            `json:"folder,omitempty"`
	Files    map[string]string `json:"files"`
	Shas     map[string]string `json:"shas,omitempty"`
	Lockfile string            `json:"lockfile,omitempty"`
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

// Signing key operations, for a remote that keeps the list of keys a
// pipeline accepts signatures from. Only a signed-in person may use them.
const (
	CommandKeyRegister = "key.register"
	CommandKeyList     = "key.list"
	CommandKeyRetire   = "key.retire"
	CommandKeyRevoke   = "key.revoke"
	TypeKeyRegister    = "key.register"
	TypeKeyList        = "key.list"
	TypeKeyRetire      = "key.retire"
	TypeKeyRevoke      = "key.revoke"
)

// KeyRegisterRequest asks the remote to accept a signing key for a
// configuration, named as the remote knows it.
type KeyRegisterRequest struct {
	Type            string `json:"type"` // "key.register"
	ProtocolVersion int    `json:"protocol_version"`
	RequestID       string `json:"request_id"`
	Config          string `json:"config"`
	PublicKeyPEM    string `json:"public_key_pem"`
	Name            string `json:"name,omitempty"`
	ExpiresInDays   int    `json:"expires_in_days,omitempty"`
}

// Signing key statuses. Only a usable key is safe to sign with. A pending
// key waits for a person to approve it and turns lapsed when nobody does in
// time; denied, expired, retired, and revoked are final. Packs a key signed
// before it expired or was retired stay trusted; revoking a key withdraws
// trust from every pack it signed.
const (
	KeyStatusPending = "pending"
	KeyStatusLapsed  = "lapsed"
	KeyStatusUsable  = "usable"
	KeyStatusDenied  = "denied"
	KeyStatusExpired = "expired"
	KeyStatusRetired = "retired"
	KeyStatusRevoked = "revoked"
)

// SigningKey is one key a configuration accepts signatures from. Machine
// names the machine that registered it. Approval comes only from
// key.register, for a key that is pending.
type SigningKey struct {
	ID           string       `json:"id"`
	Name         string       `json:"name,omitempty"`
	Fingerprint  string       `json:"fingerprint"`
	Algorithm    string       `json:"algorithm,omitempty"`
	Status       string       `json:"status"`
	RegisteredBy string       `json:"registered_by,omitempty"`
	CreatedAt    string       `json:"created_at,omitempty"`
	ExpiresAt    string       `json:"expires_at,omitempty"`
	RevokedAt    string       `json:"revoked_at,omitempty"`
	RetiredAt    string       `json:"retired_at,omitempty"`
	Machine      string       `json:"machine,omitempty"`
	Approval     *KeyApproval `json:"approval,omitempty"`
}

// KeyApproval is how a person approves a pending key: they type Code at URL
// before ExpiresAt. Interval is how often to check back, in seconds.
type KeyApproval struct {
	Code      string `json:"code"`
	URL       string `json:"url"`
	ExpiresAt string `json:"expires_at"`
	Interval  int    `json:"interval,omitempty"`
}

// KeyRegisterResponse is the response for key.register operations. Created
// is false when the remote already held the key.
type KeyRegisterResponse struct {
	OK          bool       `json:"ok"`
	Type        string     `json:"type"` // "key.register.result"
	RequestID   string     `json:"request_id"`
	Key         SigningKey `json:"key"`
	Created     bool       `json:"created"`
	PipelineURL string     `json:"pipeline_url,omitempty"`
}

// KeyListRequest asks for the keys a configuration accepts.
type KeyListRequest struct {
	Type            string `json:"type"` // "key.list"
	ProtocolVersion int    `json:"protocol_version"`
	RequestID       string `json:"request_id"`
	Config          string `json:"config"`
}

// KeyListResponse is the response for key.list operations.
type KeyListResponse struct {
	OK        bool         `json:"ok"`
	Type      string       `json:"type"` // "key.list.result"
	RequestID string       `json:"request_id"`
	Keys      []SigningKey `json:"keys"`
}

// KeyRevokeRequest asks the remote to stop trusting a key, including the
// packs it already signed.
type KeyRevokeRequest struct {
	Type            string `json:"type"` // "key.revoke"
	ProtocolVersion int    `json:"protocol_version"`
	RequestID       string `json:"request_id"`
	Config          string `json:"config"`
	ID              string `json:"id"`
}

// KeyRevokeResponse is the response for key.revoke operations.
type KeyRevokeResponse struct {
	OK        bool       `json:"ok"`
	Type      string     `json:"type"` // "key.revoke.result"
	RequestID string     `json:"request_id"`
	Key       SigningKey `json:"key"`
}

// KeyRetireRequest asks the remote to stop accepting new signatures from a
// key while still trusting the packs it signed, as a rotation does.
type KeyRetireRequest struct {
	Type            string `json:"type"` // "key.retire"
	ProtocolVersion int    `json:"protocol_version"`
	RequestID       string `json:"request_id"`
	Config          string `json:"config"`
	ID              string `json:"id"`
}

// KeyRetireResponse is the response for key.retire operations.
type KeyRetireResponse struct {
	OK        bool       `json:"ok"`
	Type      string     `json:"type"` // "key.retire.result"
	RequestID string     `json:"request_id"`
	Key       SigningKey `json:"key"`
}

// Credential resolution, for a run with no CI identity of its own: the
// remote resolves a configuration's managed credentials with the person's
// sign-in, which never leaves the adapter.
const (
	CommandCredentialsResolve = "credentials.resolve"
	TypeCredentialsResolve    = "credentials.resolve"
)

// CredentialsResolveRequest asks the remote for a configuration's managed
// credentials by the credential set IDs the configuration names.
type CredentialsResolveRequest struct {
	Type            string   `json:"type"` // "credentials.resolve"
	ProtocolVersion int      `json:"protocol_version"`
	RequestID       string   `json:"request_id"`
	Config          string   `json:"config,omitempty"`
	CredentialSets  []string `json:"credential_sets"`
}

// CredentialsResolveResponse carries the env the components receive.
type CredentialsResolveResponse struct {
	OK        bool              `json:"ok"`
	Type      string            `json:"type"` // "credentials.resolve.result"
	RequestID string            `json:"request_id"`
	Env       map[string]string `json:"env"`
	ExpiresAt string            `json:"expires_at,omitempty"`
}
