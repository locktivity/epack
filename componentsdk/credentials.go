package componentsdk

import (
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// RefusedHostError reports a request that would have sent credentials to a
// host outside HTTPOptions.CredentialHosts, or over plain http.
type RefusedHostError struct {
	Host string
	// Plaintext is true when the SDK refused a plain http request to a
	// listed host that is not a loopback host.
	Plaintext bool
}

func (e *RefusedHostError) Error() string {
	if e.Plaintext {
		return "refused to send credentials to " + e.Host + " over plain http"
	}
	return "refused to send credentials to " + e.Host
}

var defaultCredentialHeaders = []string{
	"Authorization", "Proxy-Authorization", "Cookie",
	"PRIVATE-TOKEN", "X-API-Key", "X-Auth-Token", "Api-Key", "Ocp-Apim-Subscription-Key",
}

// checkCredentials refuses a request that would send a credential to a host
// outside CredentialHosts. It also refuses a request that would send a
// credential over plain http to a host that is not a loopback host. A
// credential is a credential header, or a value the collector read through
// Secret that appears in the URL or the body. A client secret in a token
// request's form is one example, and net/http resends that form when a 307
// redirects elsewhere. checkCredentials may read the body to look inside it,
// so it returns the request to send.
func (t *transport) checkCredentials(req *http.Request, op Operation) (*http.Request, error) {
	if req.URL == nil {
		return req, nil
	}
	if t.credentialHost.empty() && t.credentialHeader(req) {
		t.run.noteUnlistedCredentials(op.Name)
	}
	host := strings.ToLower(req.URL.Hostname())
	unlisted := !t.credentialHost.empty() && !t.credentialHost.allows(host)
	plaintext := strings.EqualFold(req.URL.Scheme, "http") && !loopbackHost(host)
	if !unlisted && !plaintext {
		return req, nil
	}
	refuse := func() (*http.Request, error) {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, &RefusedHostError{Host: host, Plaintext: !unlisted}
	}
	if t.credentialHeader(req) {
		return refuse()
	}
	secrets := t.run.secrets.list()
	if len(secrets) == 0 {
		return req, nil
	}
	if carriesSecret(req.URL.String(), secrets) {
		return refuse()
	}
	if req.Body == nil || req.Body == http.NoBody {
		return req, nil
	}
	held, err := holdBody(req)
	if err != nil {
		return nil, err
	}
	if carriesSecret(string(held), secrets) {
		return refuse()
	}
	return withHeldBody(req, held), nil
}

func (t *transport) credentialHeader(req *http.Request) bool {
	for _, name := range t.credentialHdrs {
		if req.Header.Get(name) != "" {
			return true
		}
	}
	return false
}

// carriesSecret reports whether s contains a secret value, either as written
// or as a form, a URL, or a JSON string escapes it. Percent-encoding escapes
// the +, /, and = of a base64 secret. JSON escapes quotes and backslashes, and
// Go's encoder also escapes <, >, and &. carriesSecret skips values shorter
// than six characters, as redaction does, because they match too much
// ordinary text.
func carriesSecret(s string, secrets []string) bool {
	forms := unescapedForms(s)
	for _, v := range secrets {
		if len(v) < 6 {
			continue
		}
		for _, f := range forms {
			if strings.Contains(f, v) {
				return true
			}
		}
	}
	return false
}

// unescapedForms returns s, s percent-decoded as a form, and s percent-decoded
// as a path. It also returns each of those with JSON string escapes decoded,
// for JSON sent in a form field. Each distinct form appears once.
func unescapedForms(s string) []string {
	forms := make([]string, 0, 6)
	for _, p := range []string{s, unescapeLoosely(s, true), unescapeLoosely(s, false)} {
		for _, f := range []string{p, unescapeJSONLoosely(p)} {
			if !slices.Contains(forms, f) {
				forms = append(forms, f)
			}
		}
	}
	return forms
}

// unescapeLoosely percent-decodes s and accepts either case of hex. It leaves
// a malformed escape as written, where url.QueryUnescape would fail, so one
// stray % cannot hide the rest of a body. With plus set, it decodes + as a
// space, as forms and queries do. Paths keep the +.
func unescapeLoosely(s string, plus bool) string {
	if !strings.ContainsAny(s, "%+") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '%' && i+2 < len(s):
			if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i += 2
				continue
			}
			b.WriteByte(c)
		case c == '+' && plus:
			b.WriteByte(' ')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// unescapeJSONLoosely decodes JSON string escapes wherever they appear in s.
// It handles \" \\ \/ \b \f \n \r \t, and \uXXXX in either case of hex, and
// it decodes a surrogate pair as one character. It leaves a malformed escape
// as written. The result is the same whichever characters an encoder chose
// to escape.
func unescapeJSONLoosely(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 == len(s) {
			b.WriteByte(s[i])
			continue
		}
		switch c := s[i+1]; c {
		case '"', '\\', '/':
			b.WriteByte(c)
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'u':
			r, n := jsonEscapedRune(s[i:])
			if n == 0 {
				b.WriteByte('\\')
				continue
			}
			b.WriteRune(r)
			i += n - 1
			continue
		default:
			b.WriteByte('\\')
			continue
		}
		i++
	}
	return b.String()
}

// jsonEscapedRune decodes the \uXXXX escape at the start of s. When the next
// escape completes a surrogate pair, it decodes the two together. It returns
// the rune and the number of bytes the escapes span. It returns 0 bytes when
// s does not start with an escape.
func jsonEscapedRune(s string) (rune, int) {
	r, ok := jsonEscapedUnit(s)
	if !ok {
		return 0, 0
	}
	if utf16.IsSurrogate(r) {
		if low, ok := jsonEscapedUnit(s[6:]); ok {
			if pair := utf16.DecodeRune(r, low); pair != utf8.RuneError {
				return pair, 12
			}
		}
	}
	return r, 6
}

func jsonEscapedUnit(s string) (rune, bool) {
	if len(s) < 6 || s[0] != '\\' || s[1] != 'u' {
		return 0, false
	}
	v, err := strconv.ParseUint(s[2:6], 16, 16)
	return rune(v), err == nil
}

// loopbackHost reports whether host is localhost or a loopback address.
// Plain http to such a host never leaves the machine.
func loopbackHost(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

type hostSet struct {
	exact    map[string]bool
	suffixes []string
}

func newHostSet(hosts []string) hostSet {
	set := hostSet{exact: map[string]bool{}}
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		switch {
		case h == "":
		case strings.HasPrefix(h, "*."):
			set.suffixes = append(set.suffixes, h[1:])
		default:
			set.exact[h] = true
		}
	}
	return set
}

func (s hostSet) empty() bool { return len(s.exact) == 0 && len(s.suffixes) == 0 }

func (s hostSet) allows(host string) bool {
	if s.exact[host] {
		return true
	}
	for _, suffix := range s.suffixes {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}
