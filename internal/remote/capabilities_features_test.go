package remote_test

import (
	"encoding/json"
	"testing"

	"github.com/locktivity/epack/internal/remote"
)

func TestCapabilities_AuthBrowserAndConfigPullFeatures(t *testing.T) {
	var caps remote.Capabilities
	raw := `{"name":"locktivity","kind":"remote_adapter","deploy_protocol_version":1,"features":{"auth_login":true,"auth_browser":true,"whoami":true,"config_pull":true}}`
	if err := json.Unmarshal([]byte(raw), &caps); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !caps.SupportsAuthLogin() || !caps.SupportsAuthBrowser() || !caps.SupportsConfigPull() {
		t.Errorf("features not read: %+v", caps.Features)
	}

	var older remote.Capabilities
	if err := json.Unmarshal([]byte(`{"name":"old","kind":"remote_adapter","deploy_protocol_version":1,"features":{"auth_login":true,"auth_wait":true}}`), &older); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !older.SupportsAuthLogin() {
		t.Error("auth_login not read")
	}
	if older.SupportsAuthBrowser() || older.SupportsConfigPull() {
		t.Error("an adapter that does not declare the features must not get them")
	}
}
