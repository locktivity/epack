package remote

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/locktivity/epack/internal/component/config"
)

const (
	// RemoteEndpointEnvVar passes a resolved custom API endpoint to remote adapters.
	RemoteEndpointEnvVar = "EPACK_REMOTE_ENDPOINT"
	// RemoteAuthEndpointEnvVar passes a resolved custom auth endpoint to remote adapters.
	RemoteAuthEndpointEnvVar = "EPACK_REMOTE_AUTH_ENDPOINT"
)

// CustomEndpointOverride captures validated custom endpoint configuration for a remote adapter.
type CustomEndpointOverride struct {
	Endpoint     string
	AuthEndpoint string
}

// Active reports whether any custom endpoint override is configured.
func (o CustomEndpointOverride) Active() bool {
	return o.Endpoint != "" || o.AuthEndpoint != ""
}

// ExplicitEnv returns the trusted env bundle that should be passed to the adapter.
func (o CustomEndpointOverride) ExplicitEnv() map[string]string {
	if !o.Active() {
		return nil
	}
	env := map[string]string{}
	if o.Endpoint != "" {
		env[RemoteEndpointEnvVar] = o.Endpoint
	}
	if o.AuthEndpoint != "" {
		env[RemoteAuthEndpointEnvVar] = o.AuthEndpoint
	}
	return env
}

// AuditAttrs returns audit metadata describing the active custom endpoint override.
func (o CustomEndpointOverride) AuditAttrs() map[string]string {
	if !o.Active() {
		return nil
	}
	attrs := map[string]string{
		"insecure_custom_endpoint": "true",
	}
	if o.Endpoint != "" {
		attrs["remote_endpoint_host"] = endpointHost(o.Endpoint)
		attrs["remote_endpoint_has_path"] = boolString(endpointHasPath(o.Endpoint))
	}
	if o.AuthEndpoint != "" {
		attrs["remote_auth_endpoint_host"] = endpointHost(o.AuthEndpoint)
		attrs["remote_auth_endpoint_has_path"] = boolString(endpointHasPath(o.AuthEndpoint))
	}
	return attrs
}

// ResolveCustomEndpointOverride validates remote endpoint overrides declared in config.
func ResolveCustomEndpointOverride(cfg *config.RemoteConfig) (CustomEndpointOverride, error) {
	if cfg == nil {
		return CustomEndpointOverride{}, nil
	}

	endpoint := strings.TrimSpace(cfg.InsecureEndpoint)
	authEndpoint := strings.TrimSpace(cfg.Auth.InsecureEndpoint)

	if endpoint == "" && authEndpoint == "" {
		return CustomEndpointOverride{}, nil
	}

	validatedEndpoint, err := validateCustomEndpointURL("insecure_endpoint", endpoint)
	if err != nil {
		return CustomEndpointOverride{}, err
	}
	validatedAuthEndpoint, err := validateCustomEndpointURL("auth.insecure_endpoint", authEndpoint)
	if err != nil {
		return CustomEndpointOverride{}, err
	}

	return CustomEndpointOverride{
		Endpoint:     validatedEndpoint,
		AuthEndpoint: validatedAuthEndpoint,
	}, nil
}

func validateCustomEndpointURL(field, rawURL string) (string, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", nil
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("remote %s: invalid URL: %w", field, err)
	}
	if parsed.Scheme != "https" {
		return "", fmt.Errorf("remote %s: must use HTTPS (got %q)", field, parsed.Scheme)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("remote %s: missing host", field)
	}
	if parsed.User != nil {
		return "", fmt.Errorf("remote %s: userinfo is not allowed", field)
	}
	if parsed.RawQuery != "" {
		return "", fmt.Errorf("remote %s: query parameters are not allowed", field)
	}
	if parsed.Fragment != "" {
		return "", fmt.Errorf("remote %s: fragments are not allowed", field)
	}

	return parsed.String(), nil
}

func endpointHost(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsed.Host
}

func endpointHasPath(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return parsed.Path != "" && parsed.Path != "/"
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}
