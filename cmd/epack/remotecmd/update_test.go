//go:build components

package remotecmd

import (
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/remote"
	"github.com/locktivity/epack/internal/remoteconfig"
)

func TestOutdatedAdapterErrorPointsAtTheUpdate(t *testing.T) {
	hidden := &remoteconfig.HiddenPathError{Path: ".locktivity/manifest.json"}

	text := outdatedAdapterError("locktivity", &PreparedRemote{Caps: &remote.Capabilities{Version: "v0.1.5"}}, hidden).Error()
	for _, want := range []string{
		"the configuration includes .locktivity/manifest.json",
		"the locktivity adapter v0.1.5 declared no folder for its own files",
		"Update yours with 'epack remote update locktivity'",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("message missing %q:\n%s", want, text)
		}
	}

	project := outdatedAdapterError("locktivity", &PreparedRemote{Caps: &remote.Capabilities{}, ProjectRoot: "/work/northwind"}, hidden).Error()
	if !strings.Contains(project, "This project pins its own locktivity adapter") || !strings.Contains(project, "from outside the project") {
		t.Errorf("a project-pinned adapter needs its own hint:\n%s", project)
	}
	if strings.Contains(project, "adapter  declared") {
		t.Errorf("an adapter without a version must not leave a gap:\n%s", project)
	}
}
