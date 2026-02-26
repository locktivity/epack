//go:build components

package utilitycmd

import (
	"sync"
	"testing"

	"github.com/locktivity/epack/internal/catalog"
	"github.com/locktivity/epack/internal/securityaudit"
)

type installAuditSink struct {
	mu     sync.Mutex
	events []securityaudit.Event
}

func (s *installAuditSink) HandleSecurityEvent(evt securityaudit.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, evt)
}

func (s *installAuditSink) Snapshot() []securityaudit.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]securityaudit.Event, len(s.events))
	copy(out, s.events)
	return out
}

func TestExtractRepoPath(t *testing.T) {
	tests := []struct {
		name    string
		repoURL string
		want    string
		wantErr bool
	}{
		{
			name:    "basic GitHub URL",
			repoURL: "https://github.com/locktivity/epack-tools-viewer",
			want:    "locktivity/epack-tools-viewer",
		},
		{
			name:    "GitHub URL with trailing slash",
			repoURL: "https://github.com/locktivity/epack-tools-viewer/",
			want:    "locktivity/epack-tools-viewer",
		},
		{
			name:    "GitHub URL with extra path segments",
			repoURL: "https://github.com/locktivity/epack-tools-viewer/releases",
			want:    "locktivity/epack-tools-viewer",
		},
		{
			name:    "empty URL",
			repoURL: "",
			wantErr: true,
		},
		{
			name:    "non-GitHub URL",
			repoURL: "https://gitlab.com/owner/repo",
			wantErr: true,
		},
		{
			name:    "missing repo part",
			repoURL: "https://github.com/owner",
			wantErr: true,
		},
		{
			name:    "HTTP instead of HTTPS",
			repoURL: "http://github.com/owner/repo",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractRepoPath(tt.repoURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractRepoPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("extractRepoPath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildSourceString(t *testing.T) {
	tests := []struct {
		name       string
		component  catalog.CatalogComponent
		constraint string
		want       string
		wantErr    bool
	}{
		{
			name: "no constraint",
			component: catalog.CatalogComponent{
				Name:    "viewer",
				RepoURL: "https://github.com/locktivity/epack-tools-viewer",
				Latest:  "v1.2.0",
			},
			constraint: "",
			want:       "locktivity/epack-tools-viewer@v1.2.0",
		},
		{
			name: "latest constraint",
			component: catalog.CatalogComponent{
				Name:    "viewer",
				RepoURL: "https://github.com/locktivity/epack-tools-viewer",
				Latest:  "v1.2.0",
			},
			constraint: "latest",
			want:       "locktivity/epack-tools-viewer@v1.2.0",
		},
		{
			name: "version constraint",
			component: catalog.CatalogComponent{
				Name:    "viewer",
				RepoURL: "https://github.com/locktivity/epack-tools-viewer",
			},
			constraint: "v1.0.0",
			want:       "locktivity/epack-tools-viewer@v1.0.0",
		},
		{
			name: "caret constraint",
			component: catalog.CatalogComponent{
				Name:    "viewer",
				RepoURL: "https://github.com/locktivity/epack-tools-viewer",
			},
			constraint: "^1.0",
			want:       "locktivity/epack-tools-viewer@^1.0",
		},
		{
			name: "invalid repo URL",
			component: catalog.CatalogComponent{
				Name:    "viewer",
				RepoURL: "",
			},
			constraint: "",
			wantErr:    true,
		},
		{
			name: "no releases",
			component: catalog.CatalogComponent{
				Name:    "viewer",
				RepoURL: "https://github.com/locktivity/epack-tools-viewer",
				Latest:  "",
			},
			constraint: "latest",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildSourceString(tt.component, tt.constraint)
			if (err != nil) != tt.wantErr {
				t.Errorf("buildSourceString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("buildSourceString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestValidateUtilityName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid name",
			input:   "viewer",
			wantErr: false,
		},
		{
			name:    "valid name with dash",
			input:   "my-viewer",
			wantErr: false,
		},
		{
			name:    "valid name with underscore",
			input:   "my_viewer",
			wantErr: false,
		},
		{
			name:    "path traversal attack",
			input:   "../escape",
			wantErr: true,
		},
		{
			name:    "empty name",
			input:   "",
			wantErr: true,
		},
		{
			name:    "name with slash",
			input:   "viewer/bad",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateUtilityName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateUtilityName(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateInstallFlags_StrictProduction(t *testing.T) {
	t.Setenv("EPACK_STRICT_PRODUCTION", "1")

	origSkip := insecureSkipVerify
	origTrust := insecureTrustOnFirst
	t.Cleanup(func() {
		insecureSkipVerify = origSkip
		insecureTrustOnFirst = origTrust
	})

	insecureSkipVerify = true
	insecureTrustOnFirst = false
	if err := validateInstallFlags(); err == nil {
		t.Fatal("expected strict production rejection for --insecure-skip-verify")
	}

	insecureSkipVerify = false
	insecureTrustOnFirst = true
	if err := validateInstallFlags(); err == nil {
		t.Fatal("expected strict production rejection for --insecure-trust-on-first")
	}
}

func TestValidateInstallFlags_NonStrict(t *testing.T) {
	t.Setenv("EPACK_STRICT_PRODUCTION", "")

	origSkip := insecureSkipVerify
	origTrust := insecureTrustOnFirst
	t.Cleanup(func() {
		insecureSkipVerify = origSkip
		insecureTrustOnFirst = origTrust
	})

	insecureSkipVerify = true
	insecureTrustOnFirst = true
	if err := validateInstallFlags(); err != nil {
		t.Fatalf("expected insecure flags to be allowed when strict mode disabled, got: %v", err)
	}
}

func TestValidateInstallFlags_EmitsInsecureBypassWhenAllowed(t *testing.T) {
	t.Setenv("EPACK_STRICT_PRODUCTION", "")

	origSkip := insecureSkipVerify
	origTrust := insecureTrustOnFirst
	t.Cleanup(func() {
		insecureSkipVerify = origSkip
		insecureTrustOnFirst = origTrust
		securityaudit.SetSink(nil)
	})

	sink := &installAuditSink{}
	securityaudit.SetSink(sink)

	cases := []struct {
		skip  bool
		trust bool
	}{
		{skip: true, trust: false},
		{skip: false, trust: true},
		{skip: true, trust: true},
	}

	for _, tc := range cases {
		insecureSkipVerify = tc.skip
		insecureTrustOnFirst = tc.trust
		if err := validateInstallFlags(); err != nil {
			t.Fatalf("validateInstallFlags() error = %v", err)
		}
	}

	for _, evt := range sink.Snapshot() {
		if evt.Type == securityaudit.EventInsecureBypass && evt.Component == "utility_install" {
			return
		}
	}
	t.Fatalf("expected insecure bypass event, got: %+v", sink.Snapshot())
}
