package component

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/locktivity/epack/internal/component/github"
	"github.com/locktivity/epack/internal/component/sync"
)

func TestGitHubRegistry_Name(t *testing.T) {
	r := sync.NewGitHubRegistry()
	if r.Name() != "github" {
		t.Errorf("expected name 'github', got %q", r.Name())
	}
}

func TestGitHubRegistry_ResolveVersion_Exact(t *testing.T) {
	r := sync.NewGitHubRegistry()
	ctx := context.Background()

	// Exact version should return normalized tag without API call
	version, err := r.ResolveVersion(ctx, "owner/repo", "v1.2.3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if version != "v1.2.3" {
		t.Errorf("expected 'v1.2.3', got %q", version)
	}

	// Without v prefix should still work
	version, err = r.ResolveVersion(ctx, "owner/repo", "1.2.3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if version != "v1.2.3" {
		t.Errorf("expected 'v1.2.3', got %q", version)
	}
}

func TestGitHubRegistry_ResolveVersion_Caret(t *testing.T) {
	// Create mock server
	releases := []github.Release{
		{TagName: "v1.0.0"},
		{TagName: "v1.2.0"},
		{TagName: "v1.2.5"},
		{TagName: "v2.0.0"},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(releases)
	}))
	defer server.Close()

	client := github.NewClientForTest(server.Client(), server.URL)
	registry := sync.NewGitHubRegistryWithClient(client)

	ctx := context.Background()
	version, err := registry.ResolveVersion(ctx, "owner/repo", "^1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if version != "v1.2.5" {
		t.Errorf("expected 'v1.2.5' (highest 1.x), got %q", version)
	}
}

func TestGitHubRegistry_FetchRelease(t *testing.T) {
	release := github.Release{
		TagName:         "v1.2.3",
		TargetCommitish: "A123456789ABCDEF0123456789abcdef01234567",
		Assets: []github.Asset{
			{Name: "tool-linux-amd64", BrowserDownloadURL: "https://example.com/tool-linux-amd64", Size: 1000},
			{Name: "tool-linux-amd64.sigstore.json", BrowserDownloadURL: "https://example.com/tool-linux-amd64.sigstore.json", Size: 500},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(release)
	}))
	defer server.Close()

	client := github.NewClientForTest(server.Client(), server.URL)
	registry := sync.NewGitHubRegistryWithClient(client)

	ctx := context.Background()
	info, err := registry.FetchRelease(ctx, "owner/repo", "v1.2.3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if info.Version != "v1.2.3" {
		t.Errorf("expected version 'v1.2.3', got %q", info.Version)
	}
	if info.Commit != "a123456789abcdef0123456789abcdef01234567" {
		t.Errorf("expected normalized commit SHA, got %q", info.Commit)
	}
	if len(info.Assets) != 2 {
		t.Fatalf("expected 2 assets, got %d", len(info.Assets))
	}

	// Check first asset is not marked as sigstore bundle
	if info.Assets[0].IsSigstoreBundle {
		t.Error("first asset should not be marked as sigstore bundle")
	}
	// Check second asset is marked as sigstore bundle
	if !info.Assets[1].IsSigstoreBundle {
		t.Error("second asset should be marked as sigstore bundle")
	}
}

func TestGitHubRegistry_FindBinaryAsset(t *testing.T) {
	release := &sync.ReleaseInfo{
		Version: "v1.2.3",
		Assets: []sync.AssetInfo{
			{Name: "tool-linux-amd64", URL: "https://example.com/tool-linux-amd64"},
			{Name: "tool-darwin-arm64", URL: "https://example.com/tool-darwin-arm64"},
		},
	}

	registry := sync.NewGitHubRegistry()

	asset, err := registry.FindBinaryAsset(release, "tool", "linux", "amd64")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if asset.Name != "tool-linux-amd64" {
		t.Errorf("expected 'tool-linux-amd64', got %q", asset.Name)
	}
	if asset.Platform != "linux/amd64" {
		t.Errorf("expected platform 'linux/amd64', got %q", asset.Platform)
	}
}

func TestGitHubRegistry_FindBinaryAsset_NotFound(t *testing.T) {
	release := &sync.ReleaseInfo{
		Version: "v1.2.3",
		Assets: []sync.AssetInfo{
			{Name: "tool-linux-amd64", URL: "https://example.com/tool-linux-amd64"},
		},
	}

	registry := sync.NewGitHubRegistry()

	_, err := registry.FindBinaryAsset(release, "tool", "windows", "amd64")
	if err == nil {
		t.Fatal("expected error for missing asset")
	}

	assetErr, ok := err.(*sync.AssetNotFoundError)
	if !ok {
		t.Fatalf("expected AssetNotFoundError, got %T", err)
	}
	if assetErr.Component != "tool" {
		t.Errorf("expected component 'tool', got %q", assetErr.Component)
	}
	if assetErr.Platform != "windows/amd64" {
		t.Errorf("expected platform 'windows/amd64', got %q", assetErr.Platform)
	}
}

func TestGitHubRegistry_FindSigstoreBundle(t *testing.T) {
	release := &sync.ReleaseInfo{
		Version: "v1.2.3",
		Assets: []sync.AssetInfo{
			{Name: "tool-linux-amd64", URL: "https://example.com/tool-linux-amd64"},
			{Name: "tool-linux-amd64.sigstore.json", URL: "https://example.com/tool-linux-amd64.sigstore.json"},
		},
	}

	registry := sync.NewGitHubRegistry()

	bundle, err := registry.FindSigstoreBundle(release, "tool-linux-amd64")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bundle.Name != "tool-linux-amd64.sigstore.json" {
		t.Errorf("expected 'tool-linux-amd64.sigstore.json', got %q", bundle.Name)
	}
}

func TestGitHubRegistry_FindSigstoreBundle_NotFound(t *testing.T) {
	release := &sync.ReleaseInfo{
		Version: "v1.2.3",
		Assets: []sync.AssetInfo{
			{Name: "tool-linux-amd64", URL: "https://example.com/tool-linux-amd64"},
		},
	}

	registry := sync.NewGitHubRegistry()

	_, err := registry.FindSigstoreBundle(release, "tool-linux-amd64")
	if err == nil {
		t.Fatal("expected error for missing bundle")
	}

	bundleErr, ok := err.(*sync.BundleNotFoundError)
	if !ok {
		t.Fatalf("expected BundleNotFoundError, got %T", err)
	}
	if bundleErr.BinaryAsset != "tool-linux-amd64" {
		t.Errorf("expected binary asset 'tool-linux-amd64', got %q", bundleErr.BinaryAsset)
	}
}

// Verify GitHubRegistry implements RegistryClient interface
var _ sync.RegistryClient = (*sync.GitHubRegistry)(nil)
