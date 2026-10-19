package componentsdk

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"syscall"

	"github.com/locktivity/epack/internal/componenttypes"
)

// Coded is an error that carries its own code, such as a license error a
// collector recognizes in a vendor's response body. Classify trusts it over
// anything else in the chain.
type Coded interface {
	error
	CollectionCode() Code
}

// StatusCoder is an API error that keeps the HTTP status of the response
// that caused it.
type StatusCoder interface {
	HTTPStatus() int
}

// HeaderCarrier is an API error that keeps the response headers, so Classify
// can tell a throttled 403 from a denied one.
type HeaderCarrier interface {
	HTTPHeader() http.Header
}

// VendorCoder is an API error that keeps the vendor's own error code, which
// records carry verbatim.
type VendorCoder interface {
	VendorCode() string
}

// CodeError gives err a code. Use it when the collector knows better than
// the status, for example a 403 whose body says the tenant lacks a license.
func CodeError(code Code, err error) error {
	return &codeError{code: code, err: err}
}

type codeError struct {
	code Code
	err  error
}

func (e *codeError) Error() string        { return e.err.Error() }
func (e *codeError) Unwrap() error        { return e.err }
func (e *codeError) CollectionCode() Code { return e.code }

// Classify returns the code for err, or "" when err is nil. It looks, in
// order, for a code the error carries, an HTTP status, the SDK's typed
// errors, and finally timeouts, transport failures, and malformed JSON.
// Anything else is internal.
func Classify(err error) Code {
	if err == nil {
		return ""
	}
	var coded Coded
	if errors.As(err, &coded) && coded.CollectionCode().Valid() {
		return coded.CollectionCode()
	}
	var refused *RefusedHostError
	if errors.As(err, &refused) {
		return CodeInvalidResponse
	}
	var status StatusCoder
	if errors.As(err, &status) {
		var header http.Header
		var carrier HeaderCarrier
		if errors.As(err, &carrier) {
			header = carrier.HTTPHeader()
		}
		if code := classifyStatus(status.HTTPStatus(), header); code != "" {
			return code
		}
	}
	var typed exitCoder
	if errors.As(err, &typed) {
		switch typed.exitCode() {
		case componenttypes.ExitConfigError:
			return CodeConfigInvalid
		case componenttypes.ExitAuthError:
			return CodeAuthFailed
		}
	}
	if code := classifyCause(err); code != "" {
		return code
	}
	if errors.As(err, &typed) {
		return CodeVendorError
	}
	return CodeInternal
}

func classifyCause(err error) Code {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || timedOut(err) {
		return CodeTimeout
	}
	var opErr *net.OpError
	var dnsErr *net.DNSError
	if errors.As(err, &opErr) || errors.As(err, &dnsErr) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.EPIPE) {
		return CodeVendorError
	}
	// Only http.Client.Do returns a *url.Error, so an EOF inside one is the
	// connection closing, not a body the collector found truncated.
	var urlErr *url.Error
	if errors.As(err, &urlErr) && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
		return CodeVendorError
	}
	var syntaxErr *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &syntaxErr) || errors.As(err, &typeErr) || errors.Is(err, io.ErrUnexpectedEOF) {
		return CodeInvalidResponse
	}
	return ""
}

// timedOut reports whether any error in err's tree says it timed out. Each
// one is asked, since an error's Timeout method can look only at its direct
// cause, as *url.Error's does.
func timedOut(err error) bool {
	if t, ok := err.(interface{ Timeout() bool }); ok && t.Timeout() {
		return true
	}
	switch u := err.(type) {
	case interface{ Unwrap() error }:
		return timedOut(u.Unwrap())
	case interface{ Unwrap() []error }:
		for _, inner := range u.Unwrap() {
			if timedOut(inner) {
				return true
			}
		}
	}
	return false
}

// ClassifyResponse returns the code for a failed response, or "" for a
// success or redirect. The code is the one HTTPOptions.ClassifyResponse gave
// the response, if it gave one, and otherwise the one its status and headers
// call for. A success the hook gave a code, as HTTPOptions.ClassifySuccess
// allows, returns that code. It does not read the body.
func ClassifyResponse(resp *http.Response) Code {
	if resp == nil {
		return ""
	}
	if resp.Request != nil {
		if code, ok := resp.Request.Context().Value(responseCodeKey{}).(Code); ok {
			return code
		}
	}
	return classifyStatus(resp.StatusCode, resp.Header)
}

func classifyStatus(status int, header http.Header) Code {
	switch {
	case status == http.StatusUnauthorized:
		return CodeAuthFailed
	case status == http.StatusForbidden:
		if throttled(header) {
			return CodeRateLimited
		}
		return CodePermissionDenied
	case status == http.StatusRequestTimeout:
		return CodeTimeout
	case status == http.StatusTooManyRequests:
		return CodeRateLimited
	case status >= 500 && status <= 599:
		return CodeVendorError
	case status >= 400 && status <= 499:
		return CodeInvalidResponse
	default:
		return ""
	}
}

// throttled reports whether headers mark a response as rate limited. GitHub
// and others answer an exhausted rate limit with 403 rather than 429.
func throttled(header http.Header) bool {
	if header == nil {
		return false
	}
	return header.Get("Retry-After") != "" ||
		header.Get("X-RateLimit-Remaining") == "0" ||
		header.Get("X-Rate-Limit-Remaining") == "0"
}

// VendorCodeOf returns the vendor's own error code from err's chain, or "".
func VendorCodeOf(err error) string {
	var vc VendorCoder
	if errors.As(err, &vc) {
		return vc.VendorCode()
	}
	return ""
}

// OAuthErrorCode returns the code for an error an OAuth 2.0 token endpoint
// answers with: those RFC 6749 section 5.2 defines, such as invalid_client,
// and common extensions, such as invalid_dpop_proof. It returns false for an
// error it does not know. Token endpoints send most of these with a 400,
// whose status alone reads as invalid_response, so a collector's token error
// can return this code from CollectionCode.
func OAuthErrorCode(oauthError string) (Code, bool) {
	switch oauthError {
	case "invalid_client", "invalid_grant", "unauthorized_client", "invalid_dpop_proof", "expired_token":
		return CodeAuthFailed, true
	case "invalid_scope", "access_denied":
		return CodePermissionDenied, true
	case "invalid_request", "unsupported_grant_type":
		return CodeConfigInvalid, true
	case "temporarily_unavailable", "server_error":
		return CodeVendorError, true
	case "slow_down":
		return CodeRateLimited, true
	}
	return "", false
}
