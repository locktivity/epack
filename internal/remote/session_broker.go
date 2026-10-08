package remote

import (
	"context"

	"github.com/locktivity/epack/internal/broker"
)

// SessionBroker resolves managed credentials through a signed-in remote, for
// a run with no CI identity of its own.
type SessionBroker struct {
	Executor *Executor
}

// Resolve asks the remote for the credential sets of the configuration the
// request names.
func (b SessionBroker) Resolve(ctx context.Context, req broker.ResolveRequest, _ broker.RuntimeContext) (broker.ResolvedEnv, error) {
	resp, err := b.Executor.CredentialsResolve(ctx, req.PipelineID, req.CredentialSets)
	if err != nil {
		return broker.ResolvedEnv{}, err
	}
	if resp.Env == nil {
		return broker.ResolvedEnv{Env: map[string]string{}}, nil
	}
	return broker.ResolvedEnv{Env: resp.Env}, nil
}
