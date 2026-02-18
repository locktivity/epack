package component

import (
	"testing"

	"github.com/locktivity/epack/internal/component/sync"
)

// TestSplitPlatform is in locker_test.go
// TestParseSourceURI is in sync_test.go

func TestSyncBuildSourceURI(t *testing.T) {
	tests := []struct {
		owner string
		repo  string
		want  string
	}{
		{"owner", "repo", "github.com/owner/repo"},
		{"my-org", "my-repo", "github.com/my-org/my-repo"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := sync.BuildSourceURI(tt.owner, tt.repo)
			if got != tt.want {
				t.Errorf("sync.BuildSourceURI(%q, %q) = %q, want %q", tt.owner, tt.repo, got, tt.want)
			}
		})
	}
}

func TestSyncBuildGitHubRepoURL(t *testing.T) {
	got := sync.BuildGitHubRepoURL("owner", "repo")
	want := "https://github.com/owner/repo"
	if got != want {
		t.Errorf("sync.BuildGitHubRepoURL() = %q, want %q", got, want)
	}
}

func TestSyncBuildGitHubRefTag(t *testing.T) {
	got := sync.BuildGitHubRefTag("v1.2.3")
	want := "refs/tags/v1.2.3"
	if got != want {
		t.Errorf("sync.BuildGitHubRefTag() = %q, want %q", got, want)
	}
}
