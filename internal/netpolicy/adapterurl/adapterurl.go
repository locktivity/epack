package adapterurl

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/netpolicy"
)

// Validate checks a URL provided by an untrusted adapter.
// Non-loopback URLs must use HTTPS. Loopback HTTP requires explicit opt-in.
func Validate(rawURL string, allowLoopbackHTTP bool) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", rawURL, err)
	}
	if parsed.Scheme == "" {
		return fmt.Errorf("URL missing scheme: %q", rawURL)
	}
	if parsed.Host == "" {
		return fmt.Errorf("URL missing host: %q", rawURL)
	}

	hostname := parsed.Hostname()
	isLoopback := netpolicy.IsLoopback(hostname)

	switch parsed.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopback && allowLoopbackHTTP {
			return nil
		}
		if isLoopback {
			return fmt.Errorf("HTTP to localhost requires allow_loopback_http: true in remote transport config")
		}
		return fmt.Errorf("HTTP scheme not allowed for non-localhost URL %q; HTTPS required", hostname)
	default:
		return fmt.Errorf("scheme %q not allowed; must be https", parsed.Scheme)
	}
}

// ValidateFileRoot checks that filePath is contained within fileRoot.
func ValidateFileRoot(filePath, fileRoot string) error {
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return fmt.Errorf("resolving file path: %w", err)
	}

	absRoot, err := filepath.Abs(fileRoot)
	if err != nil {
		return fmt.Errorf("resolving file root: %w", err)
	}

	rootWithSep := absRoot
	if !strings.HasSuffix(rootWithSep, string(filepath.Separator)) {
		rootWithSep += string(filepath.Separator)
	}

	if !strings.HasPrefix(absPath, rootWithSep) && absPath != absRoot {
		return errors.E(errors.PathTraversal,
			fmt.Sprintf("file path %q escapes configured file_root %q", filePath, fileRoot), nil)
	}

	return nil
}
