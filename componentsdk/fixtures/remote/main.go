// Minimal remote adapter fixture for SDK conformance testing.
// Build: go build -o epack-remote-sdk-fixture ./componentsdk/fixtures/remote
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/locktivity/epack/componentsdk"
)

func main() {
	componentsdk.RunRemote(componentsdk.RemoteSpec{
		Name:        "sdk-fixture",
		Version:     "1.0.0",
		Description: "Minimal remote adapter for SDK conformance testing",
		Features: componentsdk.RemoteFeatures{
			PrepareFinalize: true,
			Pull:            true,
		},
	}, &fixtureHandler{})
}

type fixtureHandler struct{}

func (h *fixtureHandler) PushPrepare(req componentsdk.PushPrepareRequest) (*componentsdk.PushPrepareResponse, error) {
	token := generateToken()
	return &componentsdk.PushPrepareResponse{
		Upload: componentsdk.UploadInfo{
			Method:    "PUT",
			URL:       fmt.Sprintf("https://fixture.example.com/upload/%s", token),
			ExpiresAt: time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339),
		},
		FinalizeToken: token,
	}, nil
}

func (h *fixtureHandler) PushFinalize(req componentsdk.PushFinalizeRequest) (*componentsdk.PushFinalizeResponse, error) {
	return &componentsdk.PushFinalizeResponse{
		Release: componentsdk.ReleaseResult{
			ReleaseID:  fmt.Sprintf("rel-%s", req.FinalizeToken[:8]),
			PackDigest: "sha256:example",
		},
	}, nil
}

func (h *fixtureHandler) PullPrepare(req componentsdk.PullPrepareRequest) (*componentsdk.PullPrepareResponse, error) {
	token := generateToken()
	return &componentsdk.PullPrepareResponse{
		Download: componentsdk.DownloadInfo{
			URL:       "https://fixture.example.com/download/example.epack",
			ExpiresAt: time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339),
		},
		Pack: componentsdk.PackResult{
			Digest:    "sha256:example",
			SizeBytes: 1024,
		},
		FinalizeToken: token,
	}, nil
}

func (h *fixtureHandler) PullFinalize(req componentsdk.PullFinalizeRequest) (*componentsdk.PullFinalizeResponse, error) {
	return &componentsdk.PullFinalizeResponse{
		Confirmed: true,
	}, nil
}

func generateToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}
