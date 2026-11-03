package componentsdk

import (
	"errors"
	"net/http"
)

// callError is an error from one of the run's calls. The SDK's transport
// returns one, and ResponseError builds one from a collector's error about
// the call's response. A gap recorded from it includes the call.
type callError struct {
	err error
	responseCall
}

func (e *callError) Error() string { return e.err.Error() }

func (e *callError) Unwrap() error { return e.err }

// Timeout and Temporary return the wrapped error's result, as net/url's Error
// does. url.Error calls these methods only on the error it wraps directly, so
// callError has to pass them through.
func (e *callError) Timeout() bool {
	t, ok := e.err.(interface{ Timeout() bool })
	return ok && t.Timeout()
}

func (e *callError) Temporary() bool {
	t, ok := e.err.(interface{ Temporary() bool })
	return ok && t.Temporary()
}

// VendorCode returns the code HTTPOptions.VendorCode read from the call's
// response. When that is empty, it returns the wrapped error's vendor code.
func (e *callError) VendorCode() string {
	if e.vendorCode != "" {
		return e.vendorCode
	}
	return VendorCodeOf(e.err)
}

// callOf returns the callError in err's chain when it has a call number.
func callOf(err error) (*callError, bool) {
	var ce *callError
	if errors.As(err, &ce) && ce.call > 0 {
		return ce, true
	}
	return nil, false
}

// ResponseError wraps err with the call that returned resp. A gap recorded
// from the result includes that call and the vendor code HTTPOptions.VendorCode
// read from resp. Errors that the SDK's client returns already include their
// call. Use ResponseError for an error the collector builds from a response,
// such as an unexpected status or a body it cannot decode. ResponseError
// returns err unchanged when resp did not come through the SDK's client, and
// it returns nil when err is nil.
func ResponseError(resp *http.Response, err error) error {
	if err == nil || resp == nil || resp.Request == nil {
		return err
	}
	info, ok := resp.Request.Context().Value(responseCallKey{}).(responseCall)
	if !ok {
		return err
	}
	return &callError{err: err, responseCall: info}
}
