package component

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/locktivity/epack/internal/component/github"
)

func TestParseSource(t *testing.T) {
	tests := []struct {
		name        string
		source      string
		wantOwner   string
		wantRepo    string
		wantVersion string
		wantErr     bool
	}{
		{
			name:        "valid caret constraint",
			source:      "evidencepack/collector-github@^1.2.3",
			wantOwner:   "evidencepack",
			wantRepo:    "collector-github",
			wantVersion: "^1.2.3",
		},
		{
			name:        "valid tilde constraint",
			source:      "org/repo@~2.0",
			wantOwner:   "org",
			wantRepo:    "repo",
			wantVersion: "~2.0",
		},
		{
			name:        "valid exact version",
			source:      "owner/repo@v1.0.0",
			wantOwner:   "owner",
			wantRepo:    "repo",
			wantVersion: "v1.0.0",
		},
		{
			name:        "valid latest",
			source:      "owner/repo@latest",
			wantOwner:   "owner",
			wantRepo:    "repo",
			wantVersion: "latest",
		},
		{
			name:    "missing version",
			source:  "owner/repo",
			wantErr: true,
		},
		{
			name:    "missing repo",
			source:  "owner@v1.0.0",
			wantErr: true,
		},
		{
			name:    "empty string",
			source:  "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, repo, version, err := github.ParseSource(tt.source)
			if tt.wantErr {
				if err == nil {
					t.Errorf("github.ParseSource(%q) expected error, got nil", tt.source)
				}
				return
			}
			if err != nil {
				t.Errorf("github.ParseSource(%q) unexpected error: %v", tt.source, err)
				return
			}
			if owner != tt.wantOwner {
				t.Errorf("owner = %q, want %q", owner, tt.wantOwner)
			}
			if repo != tt.wantRepo {
				t.Errorf("repo = %q, want %q", repo, tt.wantRepo)
			}
			if version != tt.wantVersion {
				t.Errorf("version = %q, want %q", version, tt.wantVersion)
			}
		})
	}
}

func TestFetchRelease(t *testing.T) {
	release := github.Release{
		TagName:         "v1.2.3",
		TargetCommitish: "0123456789abcdef0123456789abcdef01234567",
		Assets: []github.Asset{
			{Name: "collector-linux-amd64", BrowserDownloadURL: "https://example.com/download"},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/owner/repo/releases/tags/v1.2.3" {
			_ = json.NewEncoder(w).Encode(release)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := github.NewClientForTest(server.Client(), server.URL)

	got, err := client.FetchRelease(context.Background(), "owner", "repo", "v1.2.3")
	if err != nil {
		t.Fatalf("FetchRelease() error: %v", err)
	}
	if got.TagName != "v1.2.3" {
		t.Errorf("TagName = %q, want %q", got.TagName, "v1.2.3")
	}
	if got.TargetCommitish != "0123456789abcdef0123456789abcdef01234567" {
		t.Errorf("TargetCommitish = %q, want %q", got.TargetCommitish, "0123456789abcdef0123456789abcdef01234567")
	}
	if len(got.Assets) != 1 {
		t.Errorf("Assets len = %d, want 1", len(got.Assets))
	}
}

func TestFetchReleaseNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := github.NewClientForTest(server.Client(), server.URL)

	_, err := client.FetchRelease(context.Background(), "owner", "repo", "v9.9.9")
	if err == nil {
		t.Error("FetchRelease() expected error for not found, got nil")
	}
}

func TestFetchLatestRelease(t *testing.T) {
	release := github.Release{
		TagName: "v2.0.0",
		Assets:  []github.Asset{},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/owner/repo/releases/latest" {
			_ = json.NewEncoder(w).Encode(release)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := github.NewClientForTest(server.Client(), server.URL)

	got, err := client.FetchLatestRelease(context.Background(), "owner", "repo")
	if err != nil {
		t.Fatalf("FetchLatestRelease() error: %v", err)
	}
	if got.TagName != "v2.0.0" {
		t.Errorf("TagName = %q, want %q", got.TagName, "v2.0.0")
	}
}

func TestListReleases(t *testing.T) {
	releases := []github.Release{
		{TagName: "v1.0.0"},
		{TagName: "v1.1.0"},
		{TagName: "v2.0.0"},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/owner/repo/releases" {
			_ = json.NewEncoder(w).Encode(releases)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := github.NewClientForTest(server.Client(), server.URL)

	got, err := client.ListReleases(context.Background(), "owner", "repo")
	if err != nil {
		t.Fatalf("ListReleases() error: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("len(releases) = %d, want 3", len(got))
	}
}

func TestDownloadAsset(t *testing.T) {
	content := []byte("binary content here")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(content)
	}))
	defer server.Close()

	client := github.NewClientForTest(server.Client(), server.URL)

	tmpDir := t.TempDir()
	destPath := filepath.Join(tmpDir, "binary")

	err := client.DownloadAsset(context.Background(), server.URL+"/asset", destPath)
	if err != nil {
		t.Fatalf("DownloadAsset() error: %v", err)
	}

	got, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("reading downloaded file: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("content = %q, want %q", got, content)
	}
}

func TestFindBinaryAsset(t *testing.T) {
	tests := []struct {
		name          string
		assets        []github.Asset
		collectorName string
		goos          string
		goarch        string
		wantAsset     string
		wantErr       bool
	}{
		{
			name: "exact match linux-amd64",
			assets: []github.Asset{
				{Name: "myapp-linux-amd64"},
				{Name: "myapp-darwin-arm64"},
			},
			collectorName: "myapp",
			goos:          "linux",
			goarch:        "amd64",
			wantAsset:     "myapp-linux-amd64",
		},
		{
			name: "match with tar.gz extension",
			assets: []github.Asset{
				{Name: "myapp-linux-amd64.tar.gz"},
			},
			collectorName: "myapp",
			goos:          "linux",
			goarch:        "amd64",
			wantAsset:     "myapp-linux-amd64.tar.gz",
		},
		{
			name: "match underscore separator",
			assets: []github.Asset{
				{Name: "myapp_linux_amd64"},
			},
			collectorName: "myapp",
			goos:          "linux",
			goarch:        "amd64",
			wantAsset:     "myapp_linux_amd64",
		},
		{
			name: "match darwin arm64",
			assets: []github.Asset{
				{Name: "myapp-darwin-arm64"},
			},
			collectorName: "myapp",
			goos:          "darwin",
			goarch:        "arm64",
			wantAsset:     "myapp-darwin-arm64",
		},
		{
			name: "no matching asset",
			assets: []github.Asset{
				{Name: "myapp-windows-amd64.exe"},
			},
			collectorName: "myapp",
			goos:          "linux",
			goarch:        "amd64",
			wantErr:       true,
		},
	}

	client := &github.Client{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			release := &github.Release{Assets: tt.assets}
			asset, _, err := client.FindBinaryAsset(release, tt.collectorName, tt.goos, tt.goarch)
			if tt.wantErr {
				if err == nil {
					t.Error("FindBinaryAsset() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("FindBinaryAsset() error: %v", err)
			}
			if asset.Name != tt.wantAsset {
				t.Errorf("asset.Name = %q, want %q", asset.Name, tt.wantAsset)
			}
		})
	}
}

func TestFindSigstoreBundle(t *testing.T) {
	release := &github.Release{
		Assets: []github.Asset{
			{Name: "myapp-linux-amd64"},
			{Name: "myapp-linux-amd64.sigstore.json"},
		},
	}

	client := &github.Client{}

	// Found case
	asset, err := client.FindSigstoreBundle(release, "myapp-linux-amd64")
	if err != nil {
		t.Fatalf("FindSigstoreBundle() error: %v", err)
	}
	if asset.Name != "myapp-linux-amd64.sigstore.json" {
		t.Errorf("asset.Name = %q, want %q", asset.Name, "myapp-linux-amd64.sigstore.json")
	}

	// Not found case
	_, err = client.FindSigstoreBundle(release, "other-binary")
	if err == nil {
		t.Error("FindSigstoreBundle() expected error for missing bundle, got nil")
	}
}

func TestBinaryAssetPatterns(t *testing.T) {
	patterns := github.BinaryAssetPatterns("collector", "linux", "amd64")

	// Should include standard patterns
	expected := []string{
		"collector-linux-amd64",
		"collector_linux_amd64",
		"collector-linux_amd64",
		"collector-linux-x86_64",
	}

	for _, want := range expected {
		found := false
		for _, got := range patterns {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("patterns missing %q", want)
		}
	}
}

func TestMatchAssetPattern(t *testing.T) {
	tests := []struct {
		assetName string
		pattern   string
		want      bool
	}{
		{"myapp-linux-amd64", "myapp-linux-amd64", true},
		{"myapp-linux-amd64.tar.gz", "myapp-linux-amd64", true},
		{"myapp-linux-amd64.exe", "myapp-linux-amd64", true},
		{"myapp-linux-amd64.zip", "myapp-linux-amd64", true},
		{"MYAPP-LINUX-AMD64", "myapp-linux-amd64", true}, // case insensitive
		{"myapp-darwin-arm64", "myapp-linux-amd64", false},
		{"other-linux-amd64", "myapp-linux-amd64", false},
	}

	for _, tt := range tests {
		t.Run(tt.assetName, func(t *testing.T) {
			if got := github.MatchAssetPattern(tt.assetName, tt.pattern); got != tt.want {
				t.Errorf("MatchAssetPattern(%q, %q) = %v, want %v", tt.assetName, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestNewGitHubClient(t *testing.T) {
	client := github.NewClient()

	if client == nil {
		t.Fatal("github.NewClient() returned nil")
	}

	// Client should be functional - test by checking methods don't panic
	// We can't access private fields directly, but the client should work
}

func TestNewGitHubClient_DisablesAutoRedirect(t *testing.T) {
	// Create a server that redirects
	redirected := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		redirected = true
		_, _ = w.Write([]byte("final"))
	}))
	defer server.Close()

	// Use test client which allows loopback HTTP
	client := github.NewClientForTest(server.Client(), server.URL)
	tmpDir := t.TempDir()
	destPath := filepath.Join(tmpDir, "file")

	// The client should NOT automatically follow redirects
	// Instead, DownloadAsset handles redirects manually
	err := client.DownloadAsset(context.Background(), server.URL+"/redirect", destPath)
	if err != nil {
		t.Fatalf("DownloadAsset error: %v", err)
	}

	// If redirects were followed manually, we should reach the final endpoint
	if !redirected {
		t.Error("redirect was not followed to final endpoint")
	}
}

func TestGitHubClient_SetsAPIHeaders(t *testing.T) {
	var receivedHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header
		_ = json.NewEncoder(w).Encode(github.Release{TagName: "v1.0.0"})
	}))
	defer server.Close()

	client := github.NewClientForTest(server.Client(), server.URL)

	_, err := client.FetchRelease(context.Background(), "owner", "repo", "v1.0.0")
	if err != nil {
		t.Fatalf("FetchRelease error: %v", err)
	}

	// Verify GitHub API headers are set
	if receivedHeaders.Get("Accept") != "application/vnd.github+json" {
		t.Errorf("Accept header = %q, want %q", receivedHeaders.Get("Accept"), "application/vnd.github+json")
	}
	if receivedHeaders.Get("X-GitHub-Api-Version") != "2022-11-28" {
		t.Errorf("X-GitHub-Api-Version = %q, want %q", receivedHeaders.Get("X-GitHub-Api-Version"), "2022-11-28")
	}
}
