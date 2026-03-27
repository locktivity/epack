package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/locktivity/epack/internal/limits"
)

const (
	// DefaultAPIBase is the fixed Locktivity broker base for managed credential resolution.
	DefaultAPIBase = "https://api.locktivity.com"
	resolvePath    = "/oidc/v1/credential_sets/resolve"
)

var (
	// ErrOIDCUnavailable indicates the runtime cannot present workload identity to the broker.
	ErrOIDCUnavailable = errors.New("github actions oidc is not available")
)

// CredentialBroker resolves Locktivity-managed credential-set IDs into an env bundle.
type CredentialBroker interface {
	Resolve(ctx context.Context, req ResolveRequest, rt RuntimeContext) (ResolvedEnv, error)
}

// RuntimeContext describes the current execution environment.
type RuntimeContext struct {
	InGitHubActions bool
	OIDCAvailable   bool
}

// ResolveRequest is sent to the Locktivity credential broker.
type ResolveRequest struct {
	CredentialSets []string `json:"credential_sets"`
}

// ResolvedEnv is the broker's env bundle response.
type ResolvedEnv struct {
	Env       map[string]string `json:"env"`
	ExpiresAt time.Time         `json:"expires_at"`
}

// OIDCTokenSource mints a runtime identity token for the configured audience.
type OIDCTokenSource interface {
	Token(ctx context.Context, audience string) (string, error)
}

// Client calls the trusted credential broker using a GitHub Actions OIDC token.
type Client struct {
	APIBase     string
	HTTPClient  *http.Client
	TokenSource OIDCTokenSource
}

// NewClient returns a broker client with secure defaults.
func NewClient(apiBase string) *Client {
	if strings.TrimSpace(apiBase) == "" {
		apiBase = DefaultAPIBase
	}
	httpClient := &http.Client{Timeout: limits.DefaultHTTPTimeout}
	return &Client{
		APIBase:    strings.TrimRight(strings.TrimSpace(apiBase), "/"),
		HTTPClient: httpClient,
		TokenSource: GitHubActionsTokenSource{
			HTTPClient: httpClient,
			Getenv:     getenv,
		},
	}
}

func getenv(name string) string {
	return os.Getenv(name)
}

// Resolve calls the Locktivity credential broker and returns the resolved env bundle.
func (c *Client) Resolve(ctx context.Context, req ResolveRequest, rt RuntimeContext) (ResolvedEnv, error) {
	if len(req.CredentialSets) == 0 {
		return ResolvedEnv{}, nil
	}

	client, err := c.withDefaults()
	if err != nil {
		return ResolvedEnv{}, err
	}
	if err := validateResolveRuntime(rt); err != nil {
		return ResolvedEnv{}, err
	}
	token, err := client.resolveToken(ctx)
	if err != nil {
		return ResolvedEnv{}, err
	}
	httpReq, err := client.newResolveRequest(ctx, req, token)
	if err != nil {
		return ResolvedEnv{}, err
	}
	return client.doResolve(httpReq)
}

func (c *Client) withDefaults() (*Client, error) {
	if c == nil {
		return nil, fmt.Errorf("credential broker client is nil")
	}
	clone := *c
	clone.APIBase = strings.TrimRight(strings.TrimSpace(clone.APIBase), "/")
	if clone.APIBase == "" {
		clone.APIBase = DefaultAPIBase
	}
	if clone.HTTPClient == nil {
		clone.HTTPClient = &http.Client{Timeout: limits.DefaultHTTPTimeout}
	}
	if clone.TokenSource == nil {
		clone.TokenSource = GitHubActionsTokenSource{
			HTTPClient: clone.HTTPClient,
			Getenv:     getenv,
		}
	}
	return &clone, nil
}

func validateResolveRuntime(rt RuntimeContext) error {
	if !rt.InGitHubActions || !rt.OIDCAvailable {
		return ErrOIDCUnavailable
	}
	return nil
}

func (c *Client) resolveToken(ctx context.Context) (string, error) {
	token, err := c.TokenSource.Token(ctx, c.audience())
	if err != nil {
		return "", fmt.Errorf("requesting oidc token: %w", err)
	}
	return token, nil
}

func (c *Client) newResolveRequest(ctx context.Context, req ResolveRequest, token string) (*http.Request, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encoding broker request: %w", err)
	}
	resolveURL, err := c.resolveURL()
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, resolveURL, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("creating broker request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")
	return httpReq, nil
}

func (c *Client) doResolve(httpReq *http.Request) (ResolvedEnv, error) {
	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return ResolvedEnv{}, fmt.Errorf("calling credential broker: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if err := checkHTTPStatus("credential broker", resp); err != nil {
		return ResolvedEnv{}, err
	}
	resolved, err := decodeResolvedEnv(resp.Body)
	if err != nil {
		return ResolvedEnv{}, err
	}
	return resolved, nil
}

func (c *Client) audience() string {
	base := strings.TrimRight(strings.TrimSpace(c.APIBase), "/")
	if base == "" {
		base = DefaultAPIBase
	}
	return base
}

func (c *Client) resolveURL() (string, error) {
	u, err := url.Parse(c.audience())
	if err != nil {
		return DefaultAPIBase + resolvePath, nil
	}
	u.Path = path.Join(u.Path, strings.TrimPrefix(resolvePath, "/"))
	return u.String(), nil
}

// GitHubActionsTokenSource exchanges the ambient GitHub OIDC request vars for a JWT.
type GitHubActionsTokenSource struct {
	HTTPClient *http.Client
	Getenv     func(string) string
}

// Token requests an audience-scoped OIDC token from GitHub Actions.
func (s GitHubActionsTokenSource) Token(ctx context.Context, audience string) (string, error) {
	requestURL, requestToken, err := s.requestVars()
	if err != nil {
		return "", err
	}
	audienceURL, err := buildAudienceURL(requestURL, audience)
	if err != nil {
		return "", err
	}
	httpReq, err := newGitHubOIDCRequest(ctx, audienceURL, requestToken)
	if err != nil {
		return "", err
	}
	return s.doTokenRequest(httpReq)
}

func (s GitHubActionsTokenSource) requestVars() (string, string, error) {
	getenv := s.getenv()
	requestURL := strings.TrimSpace(getenv("ACTIONS_ID_TOKEN_REQUEST_URL"))
	requestToken := strings.TrimSpace(getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN"))
	if requestURL == "" || requestToken == "" {
		return "", "", ErrOIDCUnavailable
	}
	return requestURL, requestToken, nil
}

func buildAudienceURL(rawURL, audience string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parsing ACTIONS_ID_TOKEN_REQUEST_URL: %w", err)
	}
	query := u.Query()
	query.Set("audience", audience)
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func newGitHubOIDCRequest(ctx context.Context, requestURL, requestToken string) (*http.Request, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating oidc token request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+requestToken)
	return httpReq, nil
}

func (s GitHubActionsTokenSource) doTokenRequest(httpReq *http.Request) (string, error) {
	resp, err := s.httpClient().Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("calling github oidc endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if err := checkHTTPStatus("github oidc endpoint", resp); err != nil {
		return "", err
	}
	return decodeGitHubOIDCToken(resp.Body)
}

func (s GitHubActionsTokenSource) getenv() func(string) string {
	if s.Getenv != nil {
		return s.Getenv
	}
	return os.Getenv
}

func checkHTTPStatus(kind string, resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	msg := strings.TrimSpace(string(body))
	if msg == "" {
		msg = resp.Status
	}
	return fmt.Errorf("%s returned %s: %s", kind, resp.Status, msg)
}

func decodeResolvedEnv(body io.Reader) (ResolvedEnv, error) {
	var resolved ResolvedEnv
	if err := json.NewDecoder(io.LimitReader(body, limits.BrokerResponse.Bytes())).Decode(&resolved); err != nil {
		return ResolvedEnv{}, fmt.Errorf("decoding broker response: %w", err)
	}
	if resolved.Env == nil {
		resolved.Env = map[string]string{}
	}
	return resolved, nil
}

func decodeGitHubOIDCToken(body io.Reader) (string, error) {
	var payload struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(io.LimitReader(body, limits.BrokerResponse.Bytes())).Decode(&payload); err != nil {
		return "", fmt.Errorf("decoding github oidc response: %w", err)
	}
	if strings.TrimSpace(payload.Value) == "" {
		return "", fmt.Errorf("github oidc response did not include a token")
	}
	return payload.Value, nil
}

func (s GitHubActionsTokenSource) httpClient() *http.Client {
	if s.HTTPClient != nil {
		return s.HTTPClient
	}
	return &http.Client{Timeout: limits.DefaultHTTPTimeout}
}
