package remote_test

import (
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/remote"
)

func TestResolveCustomEndpointOverride(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		cfg       *config.RemoteConfig
		wantError string
		want      remote.CustomEndpointOverride
	}{
		{
			name: "no override",
			cfg:  &config.RemoteConfig{},
			want: remote.CustomEndpointOverride{},
		},
		{
			name: "insecure endpoint only",
			cfg: &config.RemoteConfig{
				InsecureEndpoint: "https://api.dev.example/v1",
			},
			want: remote.CustomEndpointOverride{
				Endpoint: "https://api.dev.example/v1",
			},
		},
		{
			name: "insecure endpoint and auth endpoint",
			cfg: &config.RemoteConfig{
				InsecureEndpoint: "https://api.dev.example/v1",
				Auth: config.RemoteAuth{
					InsecureEndpoint: "https://auth.dev.example",
				},
			},
			want: remote.CustomEndpointOverride{
				Endpoint:     "https://api.dev.example/v1",
				AuthEndpoint: "https://auth.dev.example",
			},
		},
		{
			name: "invalid scheme",
			cfg: &config.RemoteConfig{
				InsecureEndpoint: "http://api.dev.example",
			},
			wantError: "must use HTTPS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := remote.ResolveCustomEndpointOverride(tt.cfg)
			if tt.wantError != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantError)
				}
				if !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("error = %q, want substring %q", err.Error(), tt.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveCustomEndpointOverride() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("ResolveCustomEndpointOverride() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestCustomEndpointOverride_ExplicitEnv(t *testing.T) {
	t.Parallel()

	override := remote.CustomEndpointOverride{
		Endpoint:     "https://api.dev.example",
		AuthEndpoint: "https://auth.dev.example",
	}
	env := override.ExplicitEnv()
	if env[remote.RemoteEndpointEnvVar] != "https://api.dev.example" {
		t.Fatalf("RemoteEndpointEnvVar = %q", env[remote.RemoteEndpointEnvVar])
	}
	if env[remote.RemoteAuthEndpointEnvVar] != "https://auth.dev.example" {
		t.Fatalf("RemoteAuthEndpointEnvVar = %q", env[remote.RemoteAuthEndpointEnvVar])
	}
}
