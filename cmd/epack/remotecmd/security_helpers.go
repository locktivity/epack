//go:build components

package remotecmd

import (
	"fmt"
	"io"
	"path/filepath"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/project"
	"github.com/locktivity/epack/internal/remote"
)

type remoteInsecureState struct {
	override remote.CustomEndpointOverride
	attrs    map[string]string
}

func resolveRemoteConfigForCommand(remoteName, envName string) (*config.RemoteConfig, error) {
	projectRoot, err := project.FindRoot("")
	if err != nil {
		return nil, fmt.Errorf("not in an epack project: %w", err)
	}

	configPath := filepath.Join(projectRoot, project.ConfigFileName)
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}

	remoteCfg, err := remote.ResolveRemoteConfig(cfg, remoteName, envName)
	if err != nil {
		return nil, err
	}
	return remoteCfg, nil
}

func inspectRemoteInsecureState(remoteCfg *config.RemoteConfig) (remoteInsecureState, error) {
	override, err := remote.ResolveCustomEndpointOverride(remoteCfg)
	if err != nil {
		return remoteInsecureState{}, err
	}
	return remoteInsecureState{
		override: override,
		attrs:    override.AuditAttrs(),
	}, nil
}

func warnRemoteCustomEndpoints(stderr io.Writer, override remote.CustomEndpointOverride) {
	if stderr == nil || !override.Active() {
		return
	}
	if override.Endpoint != "" {
		_, _ = fmt.Fprintf(stderr, "WARNING: Running with custom remote endpoint %s.\n", override.Endpoint)
	}
	if override.AuthEndpoint != "" {
		_, _ = fmt.Fprintf(stderr, "WARNING: Running with custom remote auth endpoint %s.\n", override.AuthEndpoint)
	}
}

func mergeAuditAttrs(dst, src map[string]string) {
	for key, value := range src {
		dst[key] = value
	}
}
