package componentsdk

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// classifyLimit is the most bytes of a response's body that the
// ClassifyResponse, VendorCode, and NamesPermission hooks get.
const classifyLimit = 64 << 10

type (
	responseCodeKey struct{}
	responseCallKey struct{}
)

// responseCall describes the call that a response or an error belongs to.
// markResponse stores it on the response's request, and a callError
// carries it.
type responseCall struct {
	operation  string
	call       int
	vendorCode string
	// permission is the call's Operation.Permission when the response
	// denied the call because the credential lacks that permission.
	permission string
}

// deniedPermission returns op's permission when resp is a permission_denied
// response. If NamesPermission is set, it must also return true for resp.
// Otherwise deniedPermission returns "".
func (t *transport) deniedPermission(op Operation, resp *http.Response, code Code) string {
	if op.Permission == "" {
		return ""
	}
	if code == "" {
		code = classifyStatus(resp.StatusCode, resp.Header)
	}
	if code != CodePermissionDenied {
		return ""
	}
	if t.namesPermission != nil && !t.namesPermission(resp, peek(resp)) {
		return ""
	}
	return op.Permission
}

// inspect reads the start of a response's body when the ClassifyResponse or
// VendorCode hook applies to the response. It returns the code
// ClassifyResponse gave the response and the vendor code VendorCode read.
// Each is "" when there is none. The hooks read the first classifyLimit
// bytes of the body, and the caller reads those bytes again before the rest.
func (t *transport) inspect(resp *http.Response) (Code, string) {
	if resp == nil || (!t.classifies(resp) && !t.readsVendorCode(resp, "")) {
		return "", ""
	}
	head := peek(resp)
	code := t.classify(resp, head)
	return code, t.readVendorCode(resp, head, code)
}

// classifies reports whether ClassifyResponse applies to resp. It applies to
// a failed response, and to a successful one when ClassifySuccess is set.
func (t *transport) classifies(resp *http.Response) bool {
	success := resp.StatusCode >= 200 && resp.StatusCode <= 299
	return t.classifyResponse != nil && (resp.StatusCode >= 400 || (t.classifySuccess && success))
}

// classify returns the code ClassifyResponse gives resp, or "" if there is
// none. head is the start of resp's body.
func (t *transport) classify(resp *http.Response, head []byte) Code {
	if !t.classifies(resp) {
		return ""
	}
	if c, ok := t.classifyResponse(resp, head); ok && c.Valid() {
		return c
	}
	return ""
}

// readsVendorCode reports whether VendorCode applies to resp. It applies to
// a failed response and to one that ClassifyResponse gave a code.
func (t *transport) readsVendorCode(resp *http.Response, code Code) bool {
	return t.vendorCode != nil && (resp.StatusCode >= 400 || code != "")
}

// readVendorCode returns the vendor code VendorCode reads from resp, or ""
// if there is none. head is the start of resp's body.
func (t *transport) readVendorCode(resp *http.Response, head []byte, code Code) string {
	if !t.readsVendorCode(resp, code) {
		return ""
	}
	return cleanVendorCode(t.vendorCode(resp, head), t.run.secrets.list())
}

// peek returns up to the first classifyLimit bytes of resp's body. It
// replaces the body so that a reader gets those bytes again before the rest.
func peek(resp *http.Response) []byte {
	if resp.Body == nil {
		return nil
	}
	head, err := io.ReadAll(io.LimitReader(resp.Body, classifyLimit))
	var rest io.Reader = resp.Body
	if err != nil {
		rest = failedRead{err}
	}
	resp.Body = &peekedBody{Reader: io.MultiReader(bytes.NewReader(head), rest), body: resp.Body}
	return head
}

// markResponse stores on resp the call it belongs to and the code the
// ClassifyResponse hook gave it. The ClassifyResponse function and
// ResponseError read them back. They are stored on the response's request,
// because clients and vendor SDKs wrap or replace a response's body but keep
// its request.
func markResponse(resp *http.Response, sent *http.Request, code Code, info responseCall) {
	if resp.Request != nil {
		sent = resp.Request
	}
	ctx := context.WithValue(sent.Context(), responseCallKey{}, info)
	if code != "" {
		ctx = context.WithValue(ctx, responseCodeKey{}, code)
	}
	resp.Request = sent.WithContext(ctx)
}

// vendorCodePattern matches a vendor's error code, such as E0000047,
// invalid_client, or Authorization_RequestDenied. The SDK does not record a
// value that does not match, such as a sentence, so a row never holds a
// vendor's message.
var vendorCodePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}$`)

func cleanVendorCode(code string, secrets []string) string {
	code = strings.TrimSpace(code)
	if !vendorCodePattern.MatchString(code) || carriesSecret(code, secrets) {
		return ""
	}
	return code
}

// peekedBody reads the bytes peek read, then the rest of the body.
type peekedBody struct {
	io.Reader
	body io.Closer
}

func (b *peekedBody) Close() error { return b.body.Close() }

// failedRead returns the error that stopped peek's read. The caller gets the
// error at the same point in the body where peek got it.
type failedRead struct{ err error }

func (f failedRead) Read([]byte) (int, error) { return 0, f.err }
