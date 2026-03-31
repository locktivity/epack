package broker

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

// InsecureCredentialBrokerURLEnvVar is the env var for custom credential broker override.
// SECURITY: Setting this redirects credential requests to a custom endpoint.
const InsecureCredentialBrokerURLEnvVar = "EPACK_INSECURE_CREDENTIAL_BROKER_URL"

// ResolveCustomCredentialBrokerURL returns the custom credential broker URL if set.
// Returns (url, true, nil) if override is active, ("", false, nil) if not set,
// or an error if the URL is invalid.
func ResolveCustomCredentialBrokerURL(getenv func(string) string) (string, bool, error) {
	if getenv == nil {
		getenv = os.Getenv
	}

	rawURL := strings.TrimSpace(getenv(InsecureCredentialBrokerURLEnvVar))
	if rawURL == "" {
		return "", false, nil
	}

	if err := ValidateCustomCredentialBrokerURL(rawURL); err != nil {
		return "", false, err
	}
	return rawURL, true, nil
}

// ValidateCustomCredentialBrokerURL ensures the custom credential broker URL is
// safe for explicit opt-in use.
func ValidateCustomCredentialBrokerURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%s: invalid URL: %w", InsecureCredentialBrokerURLEnvVar, err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("%s: must use HTTPS (got %q)", InsecureCredentialBrokerURLEnvVar, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("%s: missing host", InsecureCredentialBrokerURLEnvVar)
	}
	if u.User != nil {
		return fmt.Errorf("%s: userinfo is not allowed", InsecureCredentialBrokerURLEnvVar)
	}
	if u.RawQuery != "" {
		return fmt.Errorf("%s: query is not allowed", InsecureCredentialBrokerURLEnvVar)
	}
	if u.Fragment != "" {
		return fmt.Errorf("%s: fragment is not allowed", InsecureCredentialBrokerURLEnvVar)
	}
	return nil
}

// CustomCredentialBrokerAuditAttrs returns structured audit attributes for a
// validated custom broker override.
func CustomCredentialBrokerAuditAttrs(rawURL string) map[string]string {
	attrs := map[string]string{
		"insecure_custom_credential_broker": "true",
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return attrs
	}
	if host := strings.TrimSpace(u.Host); host != "" {
		attrs["credential_broker_host"] = host
	}
	if strings.TrimSpace(u.Path) != "" && u.Path != "/" {
		attrs["credential_broker_has_path"] = "true"
	} else {
		attrs["credential_broker_has_path"] = "false"
	}
	return attrs
}
