package remote

import (
	"encoding/json"
	"testing"
)

func TestValidateFilesDir(t *testing.T) {
	for _, name := range []string{"", ".locktivity", ".acme-remote", ".a"} {
		if err := ValidateFilesDir(name); err != nil {
			t.Errorf("%q should be accepted: %v", name, err)
		}
	}
	for _, name := range []string{"locktivity", ".", "..", ".epack", ".git", ".a/b", ".a\\b", ". x", ".\x01"} {
		if err := ValidateFilesDir(name); err == nil {
			t.Errorf("%q should be refused", name)
		}
	}
}

func TestCapabilitiesReadTheAdapterVersionAndFolder(t *testing.T) {
	var caps Capabilities
	if err := json.Unmarshal([]byte(`{"name":"locktivity","kind":"remote_adapter","deploy_protocol_version":1,"version":"v0.1.6","files_dir":".locktivity"}`), &caps); err != nil {
		t.Fatal(err)
	}
	if caps.Version != "v0.1.6" || caps.FilesDir != ".locktivity" {
		t.Fatalf("caps = %+v", caps)
	}
}
