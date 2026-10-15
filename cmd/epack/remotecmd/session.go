//go:build components

package remotecmd

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/locktivity/epack/internal/broker"
	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/credentials"
	"github.com/locktivity/epack/internal/remote"
	"github.com/locktivity/epack/internal/securityaudit"
	"github.com/locktivity/epack/internal/securitypolicy"
	"github.com/locktivity/epack/internal/trustedpublishers"
)

// Operators point an adapter installed for the user at another instance of
// its remote with these, the way insecure_endpoint does for a project's.
const (
	InsecureRemoteEndpointEnvVar     = "EPACK_INSECURE_REMOTE_ENDPOINT"
	InsecureRemoteAuthEndpointEnvVar = "EPACK_INSECURE_REMOTE_AUTH_ENDPOINT"
)

// pipelineIdentity is what a fetch for purpose signs in for its pipeline
// with, read once from the job's environment: nil for a setup clone, or
// for a run with no job identity, which signs in on its own.
func pipelineIdentity(purpose remote.ConfigPurpose) *broker.PipelineIdentity {
	if !purpose.SignsInForPipeline() {
		return nil
	}
	identity, ok := broker.PipelineIdentityFor(credentials.DetectRuntimeContext(os.Getenv), os.Getenv)
	if !ok {
		return nil
	}
	return &identity
}

// admitForPipeline refuses an adapter from a publisher the run does not
// trust.
func admitForPipeline(remoteName, publisher, pipelineID string, trusted func() (trustedpublishers.Set, error)) error {
	set, err := trusted()
	if err != nil {
		return err
	}
	if publisher == "" || !set.Has(publisher) {
		return fmt.Errorf("signing in for pipeline %s: the %s adapter comes from a publisher this run does not trust. Add its owner to %s", pipelineID, remoteName, trustedpublishers.EnvVar)
	}
	return nil
}

// pipelineSession exchanges the job's identity at the credential broker for
// the session of its pipeline, handed to the adapter the way a folder's
// managed credentials are.
func pipelineSession(ctx context.Context, remoteName string, identity broker.PipelineIdentity, stderr io.Writer) (map[string]string, error) {
	apiBase, _, err := broker.ResolveCustomCredentialBrokerURL(os.Getenv)
	if err != nil {
		return nil, err
	}
	if err := credentials.EnforceCustomCredentialBroker(stderr, identity.Presents(), credentials.BrokerOverridePolicy{
		StrictProductionComponent: "remote_session",
		AuditComponent:            "remote",
		AuditName:                 remoteName,
		AuditDescription:          "remote sign-in running with insecure custom credential broker override",
	}); err != nil {
		return nil, err
	}
	session, err := broker.NewSessionClient(apiBase, identity).Session(ctx, identity.ID)
	if err != nil {
		return nil, fmt.Errorf("signing in for pipeline %s: %w", identity.ID, err)
	}
	return session.Env, nil
}

// userRemoteEndpoints is the endpoint override an operator set for adapters
// installed for the user.
func userRemoteEndpoints(stderr io.Writer, remoteName string) (map[string]string, error) {
	cfg := config.RemoteConfig{InsecureEndpoint: os.Getenv(InsecureRemoteEndpointEnvVar)}
	cfg.Auth.InsecureEndpoint = os.Getenv(InsecureRemoteAuthEndpointEnvVar)
	override, err := remote.ResolveCustomEndpointOverride(&cfg)
	if err != nil {
		return nil, err
	}
	if !override.Active() {
		return nil, nil
	}
	if err := validateInsecureEndpointFlags(stderr, remoteName, override, "remote adapter installed for the user running with insecure custom endpoints"); err != nil {
		return nil, err
	}
	return override.ExplicitEnv(), nil
}

// validateInsecureEndpointFlags warns about each endpoint an override points an
// adapter at, refuses the override in strict production builds, and records
// it wherever it is used.
func validateInsecureEndpointFlags(stderr io.Writer, remoteName string, override remote.CustomEndpointOverride, description string) error {
	warnRemoteCustomEndpoints(stderr, override)
	if err := securitypolicy.EnforceStrictProduction("remote_cli", true); err != nil {
		return err
	}
	securityaudit.Emit(securityaudit.Event{
		Type:        securityaudit.EventInsecureBypass,
		Component:   "remote",
		Name:        remoteName,
		Description: description,
		Attrs:       override.AuditAttrs(),
	})
	return nil
}
