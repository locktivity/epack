package componentsdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"testing"
)

type apiErr struct {
	status int
	header http.Header
	vendor string
}

func (e *apiErr) Error() string           { return fmt.Sprintf("status %d", e.status) }
func (e *apiErr) HTTPStatus() int         { return e.status }
func (e *apiErr) HTTPHeader() http.Header { return e.header }
func (e *apiErr) VendorCode() string      { return e.vendor }

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestClassify(t *testing.T) {
	var syntaxErr *json.SyntaxError
	_ = json.Unmarshal([]byte("{nope"), &struct{}{})
	if err := json.Unmarshal([]byte("{nope"), &struct{}{}); !errors.As(err, &syntaxErr) {
		t.Fatalf("expected a json.SyntaxError, got %T", err)
	}
	throttledHeader := http.Header{"X-Ratelimit-Remaining": []string{"0"}}
	cases := []struct {
		name string
		err  error
		want Code
	}{
		{"nil", nil, ""},
		{"401", &apiErr{status: 401}, CodeAuthFailed},
		{"403", &apiErr{status: 403}, CodePermissionDenied},
		{"throttled 403", &apiErr{status: 403, header: throttledHeader}, CodeRateLimited},
		{"403 with Retry-After", &apiErr{status: 403, header: http.Header{"Retry-After": []string{"30"}}}, CodeRateLimited},
		{"404", &apiErr{status: 404}, CodeInvalidResponse},
		{"400", &apiErr{status: 400}, CodeInvalidResponse},
		{"408", &apiErr{status: 408}, CodeTimeout},
		{"429", &apiErr{status: 429}, CodeRateLimited},
		{"500", &apiErr{status: 500}, CodeVendorError},
		{"503 wrapped", fmt.Errorf("listing users: %w", &apiErr{status: 503}), CodeVendorError},
		{"status beats typed auth error", NewAuthError("listing users: %w", &apiErr{status: 403}), CodePermissionDenied},
		{"carried code wins", CodeError(CodeNotLicensed, &apiErr{status: 403}), CodeNotLicensed},
		{"refused host", fmt.Errorf("next page: %w", &RefusedHostError{Host: "evil.example"}), CodeInvalidResponse},
		{"config error", NewConfigError("tenant_id is required"), CodeConfigInvalid},
		{"auth error", NewAuthError("token rejected"), CodeAuthFailed},
		{"network error", NewNetworkError("dial failed"), CodeVendorError},
		{"deadline", context.DeadlineExceeded, CodeTimeout},
		{"cancelled", context.Canceled, CodeTimeout},
		{"net timeout", &url.Error{Op: "Get", URL: "https://x", Err: timeoutErr{}}, CodeTimeout},
		{"timeout wrapped inside a url.Error", &url.Error{Op: "Get", URL: "https://x", Err: fmt.Errorf("token: %w", timeoutErr{})}, CodeTimeout},
		{"timeout joined with another error", errors.Join(errors.New("closing"), fmt.Errorf("token: %w", timeoutErr{})), CodeTimeout},
		{"connection reset", &url.Error{Op: "Get", URL: "https://x", Err: syscall.ECONNRESET}, CodeVendorError},
		{"dial error", &net.OpError{Op: "dial", Err: errors.New("refused")}, CodeVendorError},
		{"bad json", fmt.Errorf("decoding: %w", syntaxErr), CodeInvalidResponse},
		{"truncated body", fmt.Errorf("decoding: %w", io.ErrUnexpectedEOF), CodeInvalidResponse},
		{"connection closed before the response", &url.Error{Op: "Post", URL: "https://x", Err: io.EOF}, CodeVendorError},
		{"connection closed mid-response", &url.Error{Op: "Get", URL: "https://x", Err: fmt.Errorf("transport connection broken: %w", io.ErrUnexpectedEOF)}, CodeVendorError},
		{"plain", errors.New("boom"), CodeInternal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.err); got != tc.want {
				t.Errorf("Classify() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestVendorCodeOf(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", &apiErr{status: 403, vendor: "Authorization_RequestDenied"})
	if got := VendorCodeOf(err); got != "Authorization_RequestDenied" {
		t.Errorf("VendorCodeOf() = %q", got)
	}
	if got := VendorCodeOf(errors.New("plain")); got != "" {
		t.Errorf("VendorCodeOf(plain) = %q, want empty", got)
	}
}

func TestOAuthErrorCode(t *testing.T) {
	want := map[string]Code{
		"invalid_client":          CodeAuthFailed,
		"invalid_grant":           CodeAuthFailed,
		"unauthorized_client":     CodeAuthFailed,
		"invalid_dpop_proof":      CodeAuthFailed,
		"expired_token":           CodeAuthFailed,
		"invalid_scope":           CodePermissionDenied,
		"access_denied":           CodePermissionDenied,
		"invalid_request":         CodeConfigInvalid,
		"unsupported_grant_type":  CodeConfigInvalid,
		"temporarily_unavailable": CodeVendorError,
		"server_error":            CodeVendorError,
		"slow_down":               CodeRateLimited,
	}
	for oauthError, code := range want {
		if got, ok := OAuthErrorCode(oauthError); !ok || got != code {
			t.Errorf("OAuthErrorCode(%q) = %q, %v; want %q", oauthError, got, ok, code)
		}
	}
	for _, unknown := range []string{"", "authorization_pending", "Invalid_Client"} {
		if got, ok := OAuthErrorCode(unknown); ok || got != "" {
			t.Errorf("OAuthErrorCode(%q) = %q, %v; want no code", unknown, got, ok)
		}
	}
}

func TestCodes(t *testing.T) {
	owners := map[Code]Owner{
		CodeAuthFailed:       OwnerCustomer,
		CodePermissionDenied: OwnerCustomer,
		CodeConfigInvalid:    OwnerCustomer,
		CodeNotLicensed:      OwnerNobody,
		CodeRateLimited:      OwnerVendor,
		CodeVendorError:      OwnerVendor,
		CodeTimeout:          OwnerVendorOrRunner,
		CodeInvalidResponse:  OwnerPublisher,
		CodeInternal:         OwnerPublisher,
	}
	if len(Codes()) != len(owners) {
		t.Fatalf("Codes() lists %d codes, want %d", len(Codes()), len(owners))
	}
	for _, c := range Codes() {
		if !c.Valid() {
			t.Errorf("%q should be valid", c)
		}
		if c.Owner() != owners[c] {
			t.Errorf("%q owner = %q, want %q", c, c.Owner(), owners[c])
		}
	}
	if Code("nope").Valid() || Code("nope").Owner() != OwnerPublisher {
		t.Error("an unknown code is invalid and belongs to the publisher")
	}
	exits := map[Code]int{
		CodeConfigInvalid: 2, CodeAuthFailed: 3, CodePermissionDenied: 3,
		CodeRateLimited: 4, CodeVendorError: 4, CodeTimeout: 4,
		CodeNotLicensed: 1, CodeInvalidResponse: 1, CodeInternal: 1,
	}
	for c, want := range exits {
		if got := c.ExitCode(); got != want {
			t.Errorf("%q exit = %d, want %d", c, got, want)
		}
	}
}
