package credentials

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/locktivity/epack/internal/broker"
	"github.com/locktivity/epack/internal/component/config"
)

// Resolver resolves Locktivity-managed credential refs for a component at runtime.
type Resolver struct {
	Broker broker.CredentialBroker
	Getenv func(string) string
}

// ResolveComponentEnv resolves Locktivity-managed credential refs to the env bundle
// injected into a component.
func (r Resolver) ResolveComponentEnv(ctx context.Context, cfg *config.JobConfig, refs []string) (map[string]string, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	if cfg == nil {
		return nil, fmt.Errorf("job config is required")
	}

	ids, err := cfg.ResolveCredentialSetIDs(refs)
	if err != nil {
		return nil, err
	}
	getenv := r.getenv()
	rt := DetectRuntimeContext(getenv)
	resolved, err := r.broker().Resolve(ctx, broker.ResolveRequest{CredentialSets: ids}, rt)
	if err != nil {
		if errors.Is(err, broker.ErrOIDCUnavailable) {
			if rt.InGitHubActions {
				return nil, fmt.Errorf("locktivity-managed credentials require GitHub Actions OIDC; ensure workflow permissions include id-token: write")
			}
			return nil, fmt.Errorf("locktivity-managed credentials require GitHub Actions OIDC at runtime")
		}
		return nil, err
	}

	return cloneEnv(resolved.Env), nil
}

// DetectRuntimeContext inspects the ambient environment for GitHub Actions OIDC support.
func DetectRuntimeContext(getenv func(string) string) broker.RuntimeContext {
	if getenv == nil {
		getenv = os.Getenv
	}
	inGitHubActions := strings.EqualFold(strings.TrimSpace(getenv("GITHUB_ACTIONS")), "true")
	return broker.RuntimeContext{
		InGitHubActions: inGitHubActions,
		OIDCAvailable: inGitHubActions &&
			strings.TrimSpace(getenv("ACTIONS_ID_TOKEN_REQUEST_URL")) != "" &&
			strings.TrimSpace(getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")) != "",
	}
}

func (r Resolver) broker() broker.CredentialBroker {
	if r.Broker != nil {
		return r.Broker
	}

	apiBase, _, err := broker.ResolveCustomCredentialBrokerURL(r.getenv())
	if err != nil {
		return errorBroker{err: err}
	}
	return broker.NewClient(apiBase)
}

func (r Resolver) getenv() func(string) string {
	if r.Getenv != nil {
		return r.Getenv
	}
	return os.Getenv
}

func cloneEnv(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

type errorBroker struct {
	err error
}

func (b errorBroker) Resolve(context.Context, broker.ResolveRequest, broker.RuntimeContext) (broker.ResolvedEnv, error) {
	return broker.ResolvedEnv{}, b.err
}
