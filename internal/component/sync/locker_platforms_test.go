package sync

import (
	"reflect"
	"testing"

	"github.com/locktivity/epack/internal/componenttypes"
)

func TestPlatformsToLock(t *testing.T) {
	existing := map[string]componenttypes.LockedPlatform{
		"darwin/arm64": {Digest: "sha256:old-darwin"},
		"linux/amd64":  {Digest: "sha256:old-linux"},
		"linux/arm64":  {Digest: "sha256:old-linux-arm"},
	}

	tests := []struct {
		name           string
		requested      []string
		versionChanged bool
		allPlatforms   bool
		want           []string
	}{
		{
			name:           "version changed relocks every existing platform",
			requested:      []string{"darwin/arm64"},
			versionChanged: true,
			want:           []string{"darwin/arm64", "linux/amd64", "linux/arm64"},
		},
		{
			name:      "version unchanged locks only the requested platforms",
			requested: []string{"darwin/arm64"},
			want:      []string{"darwin/arm64"},
		},
		{
			name:           "all platforms uses the detected set",
			requested:      []string{"darwin/arm64", "windows/amd64"},
			versionChanged: true,
			allPlatforms:   true,
			want:           []string{"darwin/arm64", "windows/amd64"},
		},
		{
			name:           "explicit platforms are kept alongside existing ones",
			requested:      []string{"windows/amd64", "linux/amd64"},
			versionChanged: true,
			want:           []string{"darwin/arm64", "linux/amd64", "linux/arm64", "windows/amd64"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := platformsToLock(tt.requested, existing, tt.versionChanged, tt.allPlatforms)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("platformsToLock() = %v, want %v", got, tt.want)
			}
		})
	}
}
