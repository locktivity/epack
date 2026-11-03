package component

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/github"
	"github.com/locktivity/epack/internal/component/sync"
)

// acceptingVerifier passes every binary as signed by the identity the lock
// expects.
type acceptingVerifier struct{}

func (acceptingVerifier) Verify(_, _ string, want *sync.ExpectedIdentity) (*sync.SigstoreResult, error) {
	return &sync.SigstoreResult{
		Issuer:              "https://token.actions.githubusercontent.com",
		SourceRepositoryURI: want.SourceRepositoryURI,
		SourceRepositoryRef: want.SourceRepositoryRef,
	}, nil
}

func TestLockRunsNoCollector(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the release binary is a shell script")
	}
	dir := lockerTestDirInCwd(t)
	marker := filepath.Join(dir, "ran")
	binary := "#!/bin/sh\ntouch " + marker + "\n"

	host := runtime.GOOS + "-" + runtime.GOARCH
	release := github.Release{TagName: "v1.2.3", Assets: []github.Asset{{Name: "aws-" + host}, {Name: "aws-" + host + ".sigstore.json"}}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/owner/repo/releases/tags/v1.2.3":
			_ = json.NewEncoder(w).Encode(release)
		case "/repos/owner/repo/releases":
			_ = json.NewEncoder(w).Encode([]github.Release{release})
		default:
			_, _ = w.Write([]byte(binary))
		}
	}))
	t.Cleanup(server.Close)
	for i := range release.Assets {
		release.Assets[i].BrowserDownloadURL = server.URL + "/assets/" + release.Assets[i].Name
	}
	locker := sync.NewLockerWithRegistry(sync.NewGitHubRegistryWithClient(github.NewClientForTest(server.Client(), server.URL)), dir)
	locker.Verifier = acceptingVerifier{}

	external := filepath.Join(dir, "external")
	if err := os.WriteFile(external, []byte(binary), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := &config.JobConfig{Collectors: map[string]config.CollectorConfig{
		"aws": {Source: "owner/repo@v1.2.3", Config: map[string]any{"collect": []any{"cloud-posture"}}},
		"tls": {Binary: external},
	}}
	if _, err := locker.Lock(context.Background(), cfg, sync.LockOpts{}); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("lock ran a collector binary, want it only to verify and hash each one")
	}
}
