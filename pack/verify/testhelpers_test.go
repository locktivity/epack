package verify

import (
	"os"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"
)

func mustLoadTestTrustedRoot(t *testing.T) root.TrustedMaterial {
	t.Helper()

	data, err := os.ReadFile("testdata/public-good.json")
	if err != nil {
		t.Fatalf("failed to read trusted root fixture: %v", err)
	}
	tr, err := LoadTrustedRoot(data)
	if err != nil {
		t.Fatalf("failed to parse trusted root fixture: %v", err)
	}
	return tr
}
