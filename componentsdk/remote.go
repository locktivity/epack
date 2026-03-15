package componentsdk

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

// RemoteSpec defines the remote adapter's metadata and capabilities.
type RemoteSpec struct {
	// Name is the adapter name (without epack-remote- prefix).
	// Must match ^[a-z0-9][a-z0-9._-]{0,63}$
	Name string

	// Version is the semantic version (e.g., "1.0.0").
	Version string

	// Description is a human-readable description.
	Description string

	// Features describes which operations the adapter supports.
	Features RemoteFeatures

	// Auth describes supported authentication modes.
	Auth *RemoteAuth

	// Limits describes any size or rate limits.
	Limits *RemoteLimits
}

// RemoteFeatures describes which operations a remote adapter supports.
type RemoteFeatures struct {
	// PrepareFinalize indicates support for push.prepare/push.finalize.
	PrepareFinalize bool `json:"prepare_finalize"`

	// Pull indicates support for pull.prepare/pull.finalize.
	Pull bool `json:"pull"`

	// RunsSync indicates support for runs.sync.
	RunsSync bool `json:"runs_sync,omitempty"`

	// AuthLogin indicates support for auth.login.
	AuthLogin bool `json:"auth_login,omitempty"`

	// Whoami indicates support for auth.whoami.
	Whoami bool `json:"whoami,omitempty"`
}

// RemoteAuth describes authentication capabilities.
type RemoteAuth struct {
	Modes []string `json:"modes"` // e.g., ["device_code", "oidc_token", "api_key"]
}

// RemoteLimits describes size and rate limits.
type RemoteLimits struct {
	MaxPackSize int64 `json:"max_pack_size,omitempty"` // bytes
}

// RemoteHandler handles incoming requests from epack.
type RemoteHandler interface {
	// PushPrepare handles push.prepare requests.
	// Returns upload instructions or an error.
	PushPrepare(req PushPrepareRequest) (*PushPrepareResponse, error)

	// PushFinalize handles push.finalize requests.
	// Returns release information or an error.
	PushFinalize(req PushFinalizeRequest) (*PushFinalizeResponse, error)

	// PullPrepare handles pull.prepare requests.
	// Returns download instructions or an error.
	PullPrepare(req PullPrepareRequest) (*PullPrepareResponse, error)

	// PullFinalize handles pull.finalize requests.
	// Returns confirmation or an error.
	PullFinalize(req PullFinalizeRequest) (*PullFinalizeResponse, error)
}

// Request types

type PushPrepareRequest struct {
	RequestID string       `json:"request_id"`
	Remote    string       `json:"remote"`
	Target    RemoteTarget `json:"target"`
	Pack      PackInfo     `json:"pack"`
	Release   ReleaseInfo  `json:"release"`
	Identity  *AuthHints   `json:"identity,omitempty"`
}

type PushFinalizeRequest struct {
	RequestID     string       `json:"request_id"`
	Remote        string       `json:"remote"`
	Target        RemoteTarget `json:"target"`
	Pack          PackInfo     `json:"pack"`
	FinalizeToken string       `json:"finalize_token"`
}

type PullPrepareRequest struct {
	RequestID string       `json:"request_id"`
	Remote    string       `json:"remote"`
	Target    RemoteTarget `json:"target"`
	Ref       PullRef      `json:"ref"`
	Identity  *AuthHints   `json:"identity,omitempty"`
}

type PullFinalizeRequest struct {
	RequestID     string       `json:"request_id"`
	Remote        string       `json:"remote"`
	Target        RemoteTarget `json:"target"`
	FinalizeToken string       `json:"finalize_token"`
	Digest        string       `json:"digest,omitempty"`
	PackDigest    string       `json:"pack_digest,omitempty"` // Deprecated: use Digest.
}

// Response types

type PushPrepareResponse struct {
	Upload        UploadInfo `json:"upload"`
	FinalizeToken string     `json:"finalize_token"`
}

type PushFinalizeResponse struct {
	Release ReleaseResult `json:"release"`
	Links   *Links        `json:"links,omitempty"`
}

type PullPrepareResponse struct {
	Download      DownloadInfo `json:"download"`
	Pack          PackResult   `json:"pack"`
	FinalizeToken string       `json:"finalize_token"`
}

type PullFinalizeResponse struct {
	Confirmed bool `json:"confirmed"`
}

// Shared types

type RemoteTarget struct {
	Workspace   string `json:"workspace,omitempty"`
	Environment string `json:"environment,omitempty"`
	Stream      string `json:"stream,omitempty"`
}

type PackInfo struct {
	Path           string `json:"path,omitempty"`
	Digest         string `json:"digest"`                    // pack_digest: SHA256 of artifact content
	ManifestDigest string `json:"manifest_digest,omitempty"` // SHA256 of JCS-canonicalized manifest
	FileDigest     string `json:"file_digest,omitempty"`     // SHA256 of .epack file
	SizeBytes      int64  `json:"size_bytes"`
	Checksum       string `json:"checksum,omitempty"` // Base64-encoded MD5 for upload verification
}

type ReleaseInfo struct {
	Version      string            `json:"version,omitempty"`
	Notes        string            `json:"notes,omitempty"`
	Labels       []string          `json:"labels,omitempty"`
	BuildContext map[string]string `json:"build_context,omitempty"`
}

type AuthHints struct {
	Mode  string `json:"mode,omitempty"`
	Token string `json:"token,omitempty"`
}

type PullRef struct {
	Digest    string `json:"digest,omitempty"`
	ReleaseID string `json:"release_id,omitempty"`
	Version   string `json:"version,omitempty"`
	Latest    bool   `json:"latest,omitempty"`
}

type UploadInfo struct {
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers,omitempty"`
	ExpiresAt string            `json:"expires_at,omitempty"`
}

type DownloadInfo struct {
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers,omitempty"`
	ExpiresAt string            `json:"expires_at,omitempty"`
}

type PackResult struct {
	Digest    string   `json:"digest"`
	SizeBytes int64    `json:"size_bytes,omitempty"`
	Stream    string   `json:"stream,omitempty"`
	CreatedAt string   `json:"created_at,omitempty"`
	ReleaseID string   `json:"release_id,omitempty"`
	Version   string   `json:"version,omitempty"`
	Labels    []string `json:"labels,omitempty"`
}

type ReleaseResult struct {
	ReleaseID    string `json:"release_id"`
	PackDigest   string `json:"pack_digest"`
	Version      string `json:"version,omitempty"`
	CreatedAt    string `json:"created_at,omitempty"`
	CanonicalRef string `json:"canonical_ref,omitempty"`
}

type Links struct {
	Release string `json:"release,omitempty"`
	Pack    string `json:"pack,omitempty"`
}

// RemoteError represents an error response.
type RemoteError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable,omitempty"`
	Action    string `json:"action,omitempty"`
}

func (r *PullFinalizeRequest) UnmarshalJSON(data []byte) error {
	var aux struct {
		RequestID     string       `json:"request_id"`
		Remote        string       `json:"remote"`
		Target        RemoteTarget `json:"target"`
		FinalizeToken string       `json:"finalize_token"`
		Digest        string       `json:"digest,omitempty"`
		PackDigest    string       `json:"pack_digest,omitempty"`
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	*r = PullFinalizeRequest{
		RequestID:     aux.RequestID,
		Remote:        aux.Remote,
		Target:        aux.Target,
		FinalizeToken: aux.FinalizeToken,
		Digest:        aux.Digest,
		PackDigest:    aux.PackDigest,
	}
	if r.Digest == "" {
		r.Digest = aux.PackDigest
	}
	if r.PackDigest == "" {
		r.PackDigest = r.Digest
	}
	return nil
}

func (e RemoteError) Error() string { return e.Message }

// Common error constructors
func ErrAuthRequired(message string) RemoteError {
	return RemoteError{Code: "auth_required", Message: message, Retryable: false}
}

func ErrForbidden(message string) RemoteError {
	return RemoteError{Code: "forbidden", Message: message, Retryable: false}
}

func ErrNotFound(message string) RemoteError {
	return RemoteError{Code: "not_found", Message: message, Retryable: false}
}

func ErrConflict(message string) RemoteError {
	return RemoteError{Code: "conflict", Message: message, Retryable: false}
}

func ErrRateLimited(message string) RemoteError {
	return RemoteError{Code: "rate_limited", Message: message, Retryable: true}
}

func ErrServerError(message string) RemoteError {
	return RemoteError{Code: "server_error", Message: message, Retryable: true}
}

func ErrNetworkError(message string) RemoteError {
	return RemoteError{Code: "network_error", Message: message, Retryable: true}
}

// RunRemote executes the remote adapter with full protocol compliance.
// It handles --capabilities, --version, JSON stdin/stdout protocol, and error formatting.
// This function does not return.
func RunRemote(spec RemoteSpec, handler RemoteHandler) {
	os.Exit(runRemoteInternal(spec, handler))
}

func runRemoteInternal(spec RemoteSpec, handler RemoteHandler) int {
	// Check for --capabilities and --version flags
	for _, arg := range os.Args[1:] {
		switch arg {
		case "--capabilities":
			return outputRemoteCapabilities(spec)
		case "--version":
			fmt.Println(spec.Version)
			return 0
		}
	}

	// Process requests from stdin
	scanner := bufio.NewScanner(os.Stdin)
	// Increase buffer size for large requests
	scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		response := processRemoteRequest(line, spec, handler)

		enc := json.NewEncoder(os.Stdout)
		if err := enc.Encode(response); err != nil {
			fmt.Fprintf(os.Stderr, "error encoding response: %v\n", err)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "error reading stdin: %v\n", err)
		return 1
	}

	return 0
}

func outputRemoteCapabilities(spec RemoteSpec) int {
	caps := map[string]any{
		"name":                    spec.Name,
		"kind":                    "remote_adapter",
		"deploy_protocol_version": 1,
		"version":                 spec.Version,
		"description":             spec.Description,
		"features":                spec.Features,
	}

	if spec.Auth != nil {
		caps["auth"] = spec.Auth
	}
	if spec.Limits != nil {
		caps["limits"] = spec.Limits
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(caps); err != nil {
		fmt.Fprintf(os.Stderr, "error encoding capabilities: %v\n", err)
		return 1
	}
	return 0
}

func processRemoteRequest(data []byte, spec RemoteSpec, handler RemoteHandler) map[string]any {
	// Parse the request to get type and request_id
	var base struct {
		Type      string `json:"type"`
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(data, &base); err != nil {
		return errorResponse("", RemoteError{
			Code:    "invalid_request",
			Message: "failed to parse request JSON",
		})
	}

	switch base.Type {
	case "push.prepare":
		return handleTypedRemoteRequest(data, base.RequestID, "push.prepare request", "push.prepare", handler.PushPrepare)
	case "push.finalize":
		return handleTypedRemoteRequest(data, base.RequestID, "push.finalize request", "push.finalize", handler.PushFinalize)
	case "pull.prepare":
		return handleTypedRemoteRequest(data, base.RequestID, "pull.prepare request", "pull.prepare", handler.PullPrepare)
	case "pull.finalize":
		return handleTypedRemoteRequest(data, base.RequestID, "pull.finalize request", "pull.finalize", handler.PullFinalize)
	default:
		return errorResponse(base.RequestID, RemoteError{
			Code:    "unsupported_protocol",
			Message: fmt.Sprintf("unknown request type: %s", base.Type),
		})
	}
}

func handleTypedRemoteRequest[T any, R any](data []byte, requestID, parseTarget, responseType string, fn func(T) (R, error)) map[string]any {
	var req T
	if err := json.Unmarshal(data, &req); err != nil {
		return errorResponse(requestID, RemoteError{
			Code:    "invalid_request",
			Message: "failed to parse " + parseTarget,
		})
	}
	resp, err := fn(req)
	if err != nil {
		return errorResponse(requestID, toRemoteError(err))
	}
	return successResponse(requestID, responseType, resp)
}

func successResponse(requestID, responseType string, data any) map[string]any {
	// Flatten the response data into the response map
	result := map[string]any{
		"type":       responseType,
		"ok":         true,
		"request_id": requestID,
	}

	// Merge in the response fields
	if data != nil {
		dataBytes, _ := json.Marshal(data)
		var dataMap map[string]any
		_ = json.Unmarshal(dataBytes, &dataMap)
		for k, v := range dataMap {
			result[k] = v
		}
	}

	return result
}

func errorResponse(requestID string, err RemoteError) map[string]any {
	return map[string]any{
		"type":       "error",
		"ok":         false,
		"request_id": requestID,
		"error":      err,
	}
}

func toRemoteError(err error) RemoteError {
	if re, ok := err.(RemoteError); ok {
		return re
	}
	return RemoteError{
		Code:    "server_error",
		Message: err.Error(),
	}
}
