package roster

import (
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// endpointTenant has five devices, keyed so they sort in this order: a
// kiosk the device manager doesn't manage, a Mac with every reading
// passing, a Mac that last reported two days ago, past the one-day window, a
// phone, and a Windows laptop with most readings failing.
const endpointTenant = `{
  "version": 1,
  "vendor": "test",
  "providers": {"endpoint-posture": "test-mdm"},
  "endpoint": {
    "organization_id": "org-1",
    "scope": {"name": "managed_devices", "max_observation_age_seconds": 86400, "management": ["managed"]},
    "compliance_policy": {},
    "screen_lock_policy": {"max_idle_seconds": 600},
    "os_support": {"macos": "14", "windows": "10.0.19045"},
    "os_baseline": {"id": "os_minimums", "version": "2", "min_versions": {"macos": "15.1"}},
    "not_applicable": {"firewall": ["ios"]},
    "devices": {
      "kiosk": {"os": "windows", "os_version": "10.0.19045", "management": "agentless", "last_seen_seconds_ago": 60},
      "mac": {"hostname": "alice-mbp", "os": "darwin", "os_name": "macOS", "os_version": "15.1",
        "user": {"id": "u1", "login": "alice"}, "management": "agent", "mdm": "internal",
        "created_at": "2025-01-06T09:00:00Z", "last_seen_seconds_ago": 300, "agentVersion": "2.1.0",
        "volumes": {"Macintosh HD": "on"}, "screen_lock": {"enabled": true, "idle_seconds": 300},
        "compliance": "compliant",
        "modules": {"XProtect": {"enabled": true, "current": true}, "alf": {"enabled": true},
          "Falcon": {"enabled": true, "reporting": true}},
        "local_accounts": {"501": {"username": "alice", "groups": ["admin"]}, "502": {"username": "guest", "groups": ["staff"]}},
        "findings": {"f1": {"type": "firewall_off", "status": "fixed", "first_seen_at": "2026-09-14T09:00:00Z",
          "last_seen_at": "2026-09-20T11:45:00Z", "resolved_at": "2026-09-20T12:00:00Z", "reason_code": "FIREWALL_DISABLED"}}},
      "old": {"os": "darwin", "os_version": "13.6", "management": "agent", "mdm": "internal",
        "last_seen_seconds_ago": 172800, "volumes": {"Macintosh HD": "on"}},
      "phone": {"os": "ios", "os_version": "18.1", "management": "agent", "mdm": "internal",
        "last_seen_seconds_ago": 3600, "screen_lock": {"enabled": true, "idle_seconds": 30}, "compliance": "compliant"},
      "win": {"os": "windows", "os_version": "10.0.19045", "management": "agent", "mdm": "none",
        "last_seen_seconds_ago": 3600, "volumes": {"C:": "on", "D:": "off"},
        "screen_lock": {"enabled": true, "idle_seconds": 900}, "compliance": "noncompliant",
        "modules": {"Defender": {"enabled": true, "current": false}, "Windows Firewall": {"enabled": false}},
        "local_accounts": {"S-500": {"username": "Administrator", "groups": ["Administrators"]}}}
    }
  },
  "terms": {
    "endpoint_os": {"darwin": "macos", "windows": "windows", "ios": "ios"},
    "endpoint_management": {"agent": "managed", "agentless": "unmanaged"},
    "endpoint_mdm": {"internal": "enrolled", "none": "not_enrolled"},
    "endpoint_encryption": {"on": "encrypted", "off": "not_encrypted", "unknown": "unknown"},
    "endpoint_verdicts": {"compliant": "pass", "noncompliant": "fail"},
    "endpoint_modules": {"XProtect": "antimalware", "Defender": "antimalware", "alf": "firewall",
      "Windows Firewall": "firewall", "Falcon": "edr", "Device Control": "device_control", "Web Filter": "other"},
    "endpoint_local_groups": {"admin": "admin", "staff": "none", "Administrators": "admin"},
    "endpoint_finding_types": {"firewall_off": "firewall"},
    "endpoint_finding_statuses": {"fixed": "resolved", "active": "open"}
  }
}`

// Indexes of endpointTenant's devices, in roster order.
const (
	kioskDevice = iota
	macDevice
	oldDevice
	phoneDevice
	winDevice
)

func endpointRoster(t *testing.T) *Roster {
	t.Helper()
	r, err := Parse([]byte(endpointTenant))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// endpointValues validates r and derives its endpoint-posture values.
func endpointValues(t *testing.T, r *Roster) map[string]any {
	t.Helper()
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	values, err := Derive(r)
	if err != nil {
		t.Fatal(err)
	}
	return values[EndpointPosture]
}

func controlState(v map[string]any, device int, control string) string {
	state, _ := v["/devices/"+strconv.Itoa(device)+"/controls/"+control+"/state"].(string)
	return state
}

// controlsOf gives the state of each control a device's values hold.
func controlsOf(v map[string]any, device int) map[string]string {
	out := map[string]string{}
	prefix := "/devices/" + strconv.Itoa(device) + "/controls/"
	for pointer, value := range v {
		if rest, ok := strings.CutPrefix(pointer, prefix); ok {
			control, _, _ := strings.Cut(rest, "/")
			out[control], _ = value.(string)
		}
	}
	return out
}

// coverageOf gives metric_coverage's counts, by metric path and count.
func coverageOf(v map[string]any) map[string]map[string]int {
	out := map[string]map[string]int{}
	for pointer, value := range v {
		rest, ok := strings.CutPrefix(pointer, "/metric_coverage/")
		if !ok {
			continue
		}
		path, field, _ := strings.Cut(rest, "/")
		if out[path] == nil {
			out[path] = map[string]int{}
		}
		out[path][field], _ = value.(int)
	}
	return out
}

func wantValues(t *testing.T, v map[string]any, want map[string]any) {
	t.Helper()
	for _, pointer := range slices.Sorted(maps.Keys(want)) {
		got, ok := v[pointer]
		if !ok || !sameValue(got, want[pointer]) {
			t.Errorf("%s = %v (set %t), want %v", pointer, got, ok, want[pointer])
		}
	}
}

func wantUnset(t *testing.T, v map[string]any, pointers ...string) {
	t.Helper()
	for _, p := range pointers {
		if got, ok := v[p]; ok {
			t.Errorf("%s = %v, want it unset", p, got)
		}
	}
}

// availability gives the reason availability lists for each path.
func availability(v map[string]any) map[string]string {
	out := map[string]string{}
	for i := 0; ; i++ {
		at := "/availability/" + strconv.Itoa(i)
		path, ok := v[at+"/path"].(string)
		if !ok {
			return out
		}
		out[path], _ = v[at+"/reason"].(string)
	}
}

func TestEndpointScopeCountsDevicesThatReportedInTheWindow(t *testing.T) {
	v := endpointValues(t, endpointRoster(t))
	wantValues(t, v, map[string]any{
		"/provider":                          "test-mdm",
		"/organization_id":                   "org-1",
		"/scope/discovery_complete":          true,
		"/scope/description":                 "managed_devices",
		"/scope/max_observation_age_seconds": 86400,
		"/scope/observed_device_count":       4,
		"/fleet/devices_present":             true,
		"/fleet/device_count":                3,
		"/fleet/managed_device_count":        3,
		"/fleet/mdm_enrolled_device_count":   2,
		"/fleet/mdm_enrolled_pct":            66,
		"/fleet/devices_by_os":               map[string]int{"ios": 1, "macos": 1, "windows": 1},
		"/devices/0/device_id":               "kiosk",
		"/devices/0/in_scope":                false,
		"/devices/0/management_state":        "unmanaged",
		"/devices/1/in_scope":                true,
		"/devices/2/device_id":               "old",
		"/devices/2/in_scope":                false,
		"/devices/3/in_scope":                true,
		"/devices/4/in_scope":                true,
	})
	if got := availability(v); len(got) != 0 {
		t.Errorf("availability = %v, want none", got)
	}
}

func TestEndpointScopeWithNoManagementFilterCountsEveryState(t *testing.T) {
	r := endpointRoster(t)
	r.Endpoint.Scope.Management = nil
	wantValues(t, endpointValues(t, r), map[string]any{
		"/fleet/device_count":         4,
		"/fleet/managed_device_count": 3,
		"/devices/0/in_scope":         true,
	})
}

func TestEndpointDeviceFactsCarryOver(t *testing.T) {
	v := endpointValues(t, endpointRoster(t))
	wantValues(t, v, map[string]any{
		"/devices/1/device_id":                                                "mac",
		"/devices/1/hostname":                                                 "alice-mbp",
		"/devices/1/os_family":                                                "macos",
		"/devices/1/os_name":                                                  "macOS",
		"/devices/1/os_version":                                               "15.1",
		"/devices/1/assigned_user/user_id":                                    "u1",
		"/devices/1/assigned_user/login":                                      "alice",
		"/devices/1/management_state":                                         "managed",
		"/devices/1/created_at":                                               "2025-01-06T09:00:00Z",
		"/devices/1/findings/0/finding_id":                                    "f1",
		"/devices/1/findings/0/control":                                       "firewall",
		"/devices/1/findings/0/status":                                        "resolved",
		"/devices/1/findings/0/resolved_at":                                   "2026-09-20T12:00:00Z",
		"/devices/1/findings/0/reason_code":                                   "FIREWALL_DISABLED",
		"/devices/1/controls/disk_encryption/state":                           ReadingPass,
		"/metric_coverage/hardening.disk_encryption_pct/passing_device_count": 1,
	})
	wantUnset(t, v, "/devices/3/hostname", "/devices/3/assigned_user/user_id", "/devices/1/last_seen_at",
		"/devices/1/controls", "/devices/1/controls/disk_encryption/observed_at", "/metric_coverage")
}

func TestEndpointLocalAdminsAreInAnAdminGroup(t *testing.T) {
	v := endpointValues(t, endpointRoster(t))
	wantValues(t, v, map[string]any{
		"/devices/1/local_admin_accounts/0/account_id": "501",
		"/devices/1/local_admin_accounts/0/username":   "alice",
		"/devices/4/local_admin_accounts/0/account_id": "S-500",
	})
	wantUnset(t, v, "/devices/1/local_admin_accounts/1/account_id")
}

func TestEndpointDiskEncryptionNeedsEveryVolume(t *testing.T) {
	cases := []struct {
		name    string
		volumes map[string]string
		want    string
	}{
		{"no volumes", nil, ReadingUnknown},
		{"one encrypted", map[string]string{"C:": "on"}, ReadingPass},
		{"one of two", map[string]string{"C:": "on", "D:": "off"}, ReadingFail},
		{"one unknown", map[string]string{"C:": "on", "D:": "unknown"}, ReadingUnknown},
		{"one off and one unknown", map[string]string{"C:": "off", "D:": "unknown"}, ReadingFail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := endpointRoster(t)
			r.Endpoint.Devices[winDevice].Volumes = tc.volumes
			if got := controlState(endpointValues(t, r), winDevice, ControlDiskEncryption); got != tc.want {
				t.Errorf("disk_encryption = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestEndpointScreenLockMeetsPolicy(t *testing.T) {
	cases := []struct {
		name string
		lock *ScreenLock
		want string
	}{
		{"no reading", nil, ReadingUnknown},
		{"off", &ScreenLock{Enabled: false}, ReadingFail},
		{"no idle time", &ScreenLock{Enabled: true}, ReadingUnknown},
		{"at the limit", &ScreenLock{Enabled: true, IdleSeconds: endpointPtr(600)}, ReadingPass},
		{"past the limit", &ScreenLock{Enabled: true, IdleSeconds: endpointPtr(601)}, ReadingFail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := endpointRoster(t)
			r.Endpoint.Devices[winDevice].ScreenLock = tc.lock
			if got := controlState(endpointValues(t, r), winDevice, ControlScreenLock); got != tc.want {
				t.Errorf("screen_lock = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestEndpointFirewallIsAnEnabledFirewallModule(t *testing.T) {
	v := endpointValues(t, endpointRoster(t))
	for device, want := range map[int]string{macDevice: ReadingPass, winDevice: ReadingFail, phoneDevice: ReadingNotApplicable} {
		if got := controlState(v, device, ControlFirewall); got != want {
			t.Errorf("device %d firewall = %s, want %s", device, got, want)
		}
	}
	r := endpointRoster(t)
	r.Endpoint.Devices[winDevice].Modules[1].Enabled = nil
	if got := controlState(endpointValues(t, r), winDevice, ControlFirewall); got != ReadingUnknown {
		t.Errorf("firewall with no enabled reading = %s, want unknown", got)
	}
	r.Endpoint.Devices[winDevice].Modules[1].Installed = false
	if got := controlState(endpointValues(t, r), winDevice, ControlFirewall); got != ReadingFail {
		t.Errorf("firewall not installed = %s, want fail", got)
	}
}

func TestEndpointOSVersionsMeetSupportAndTheBaseline(t *testing.T) {
	cases := []struct {
		version             string
		supported, baseline string
	}{
		{"15.1", ReadingPass, ReadingPass},
		{"15.1.0", ReadingPass, ReadingPass},
		{"15", ReadingPass, ReadingFail},
		{"14", ReadingPass, ReadingFail},
		{"13.6.9", ReadingFail, ReadingFail},
		{"", ReadingUnknown, ReadingUnknown},
		{"Sequoia", ReadingUnknown, ReadingUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.version, func(t *testing.T) {
			r := endpointRoster(t)
			r.Endpoint.Devices[macDevice].OSVersion = tc.version
			v := endpointValues(t, r)
			if got := controlState(v, macDevice, ControlOSSupported); got != tc.supported {
				t.Errorf("os_supported = %s, want %s", got, tc.supported)
			}
			if got := controlState(v, macDevice, ControlOSBaseline); got != tc.baseline {
				t.Errorf("os_baseline = %s, want %s", got, tc.baseline)
			}
		})
	}
	v := endpointValues(t, endpointRoster(t))
	if got := controlState(v, phoneDevice, ControlOSSupported); got != ReadingUnknown {
		t.Errorf("a family os_support leaves out = %s, want unknown", got)
	}
	if got := controlState(v, winDevice, ControlOSBaseline); got != ReadingNotApplicable {
		t.Errorf("a family the baseline leaves out = %s, want not_applicable", got)
	}
}

func TestEndpointPatchingCountsUnsupportedOSAndNamesTheBaseline(t *testing.T) {
	r := endpointRoster(t)
	r.Endpoint.Devices[winDevice].OSVersion = "10.0.17763"
	wantValues(t, endpointValues(t, r), map[string]any{
		"/patching/os_supported_pct":          50,
		"/patching/unsupported_os_count":      1,
		"/patching/os_baseline_compliant_pct": 100,
		"/patching/baseline_id":               "os_minimums",
		"/patching/baseline_version":          "2",
	})
}

func TestEndpointComplianceIsTheVerdictOfThePolicyOrBaseline(t *testing.T) {
	v := endpointValues(t, endpointRoster(t))
	wantValues(t, v, map[string]any{
		"/compliance/compliant_pct": 66,
		"/compliance/basis":         "provider_reported",
	})
	wantUnset(t, v, "/compliance/baseline_id", "/compliance/baseline_version")
	if got := controlState(v, macDevice, ControlCompliance); got != ReadingPass {
		t.Errorf("mac compliance = %s, want pass", got)
	}

	r := endpointRoster(t)
	r.Endpoint.CompliancePolicy = &CompliancePolicy{BaselineID: "cis_level_1", BaselineVersion: "1.2.0"}
	r.Endpoint.Devices[winDevice].Compliance = ""
	v = endpointValues(t, r)
	wantValues(t, v, map[string]any{
		"/compliance/compliant_pct":    100,
		"/compliance/basis":            "baseline_evaluation",
		"/compliance/baseline_id":      "cis_level_1",
		"/compliance/baseline_version": "1.2.0",
	})
	if got := controlState(v, winDevice, ControlCompliance); got != ReadingUnknown {
		t.Errorf("compliance with no verdict = %s, want unknown", got)
	}
}

func TestEndpointProtectionNeedsTheModuleInstalledRunningAndCurrent(t *testing.T) {
	v := endpointValues(t, endpointRoster(t))
	for _, tc := range []struct {
		device  int
		control string
		want    string
	}{
		{macDevice, ControlAntimalwareInstalled, ReadingPass},
		{macDevice, ControlAntimalwareHealthy, ReadingPass},
		{macDevice, ControlEDRInstalled, ReadingPass},
		{macDevice, ControlEDRHealthy, ReadingPass},
		{winDevice, ControlAntimalwareInstalled, ReadingPass},
		{winDevice, ControlAntimalwareHealthy, ReadingFail},
		{winDevice, ControlEDRInstalled, ReadingUnknown},
		{winDevice, ControlEDRHealthy, ReadingUnknown},
	} {
		if got := controlState(v, tc.device, tc.control); got != tc.want {
			t.Errorf("device %d %s = %s, want %s", tc.device, tc.control, got, tc.want)
		}
	}
	wantValues(t, v, map[string]any{
		"/protection/antimalware_installed_pct":     100,
		"/protection/antimalware_healthy_pct":       50,
		"/protection/edr_installed_pct":             100,
		"/protection/edr_healthy_pct":               100,
		"/devices/1/protection_modules/0/kind":      ModuleEDR,
		"/devices/1/protection_modules/0/healthy":   true,
		"/devices/1/protection_modules/1/kind":      ModuleAntimalware,
		"/devices/1/protection_modules/2/kind":      ModuleFirewall,
		"/devices/4/protection_modules/0/kind":      ModuleAntimalware,
		"/devices/4/protection_modules/0/installed": true,
		"/devices/4/protection_modules/0/enabled":   true,
		"/devices/4/protection_modules/0/healthy":   false,
		"/devices/4/protection_modules/1/kind":      ModuleFirewall,
		"/devices/4/protection_modules/1/healthy":   false,
	})

	cases := []struct {
		name   string
		module DeviceModule
		want   string
	}{
		{"not installed", DeviceModule{Key: "Falcon", Installed: false}, ReadingFail},
		{"stopped", DeviceModule{Key: "Falcon", Installed: true, Enabled: endpointPtr(true), Running: endpointPtr(false), Reporting: endpointPtr(true)}, ReadingFail},
		{"not reporting", DeviceModule{Key: "Falcon", Installed: true, Enabled: endpointPtr(true), Reporting: endpointPtr(false)}, ReadingFail},
		{"reporting unknown", DeviceModule{Key: "Falcon", Installed: true, Enabled: endpointPtr(true)}, ReadingUnknown},
		{"running though not enabled", DeviceModule{Key: "Falcon", Installed: true, Enabled: endpointPtr(false), Running: endpointPtr(true), Reporting: endpointPtr(true)}, ReadingPass},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := endpointRoster(t)
			r.Endpoint.Devices[winDevice].Modules = append(r.Endpoint.Devices[winDevice].Modules, tc.module)
			v := endpointValues(t, r)
			if got := controlState(v, winDevice, ControlEDRHealthy); got != tc.want {
				t.Errorf("edr_healthy = %s, want %s", got, tc.want)
			}
			if got := controlState(v, winDevice, ControlEDRInstalled); got != map[bool]string{true: ReadingPass, false: ReadingFail}[tc.module.Installed] {
				t.Errorf("edr_installed = %s", got)
			}
		})
	}
}

func TestEndpointModulesOfNoKindAreLeftOut(t *testing.T) {
	r := endpointRoster(t)
	r.Endpoint.Devices[winDevice].Modules = append(r.Endpoint.Devices[winDevice].Modules,
		DeviceModule{Key: "Device Control", Installed: true, Enabled: endpointPtr(true)}, DeviceModule{Key: "Web Filter", Installed: true})
	v := endpointValues(t, r)
	wantValues(t, v, map[string]any{
		"/devices/4/protection_modules/1/kind":    ModuleFirewall,
		"/devices/4/protection_modules/2/kind":    ModuleDeviceControl,
		"/devices/4/protection_modules/2/healthy": true,
	})
	wantUnset(t, v, "/devices/4/protection_modules/3/kind")
}

func TestEndpointPercentagesCountReadingsThatPassedOrFailed(t *testing.T) {
	v := endpointValues(t, endpointRoster(t))
	wantValues(t, v, map[string]any{
		"/hardening/disk_encryption_pct":       50,
		"/hardening/screen_lock_compliant_pct": 66,
		"/hardening/firewall_enabled_pct":      50,
	})
	coverage := coverageOf(v)
	want := map[string]map[string]int{
		"hardening.disk_encryption_pct":      {"passing_device_count": 1, "failing_device_count": 1, "unknown_device_count": 1, "not_applicable_device_count": 0},
		"hardening.firewall_enabled_pct":     {"passing_device_count": 1, "failing_device_count": 1, "unknown_device_count": 0, "not_applicable_device_count": 1},
		"patching.os_baseline_compliant_pct": {"passing_device_count": 1, "failing_device_count": 0, "unknown_device_count": 0, "not_applicable_device_count": 2},
	}
	for path, counts := range want {
		if !maps.Equal(coverage[path], counts) {
			t.Errorf("metric_coverage[%s] = %v, want %v", path, coverage[path], counts)
		}
	}
	if len(coverage) != 10 {
		t.Errorf("metric_coverage has %d metrics, want 10: %v", len(coverage), slices.Sorted(maps.Keys(coverage)))
	}

	r := endpointRoster(t)
	r.Endpoint.Devices[macDevice].Volumes = nil
	r.Endpoint.Devices[winDevice].Volumes = map[string]string{"C:": "unknown"}
	if got, ok := endpointValues(t, r)["/hardening/disk_encryption_pct"]; !ok || got != nil {
		t.Errorf("disk_encryption_pct with no reading passed or failed = %v (set %t), want null", got, ok)
	}
}

func TestEndpointNotApplicableByFamily(t *testing.T) {
	r := endpointRoster(t)
	r.Endpoint.NotApplicable[ControlScreenLock] = []string{"windows"}
	v := endpointValues(t, r)
	if got := controlState(v, winDevice, ControlScreenLock); got != ReadingNotApplicable {
		t.Errorf("screen_lock on windows = %s, want not_applicable", got)
	}
	if got := v["/hardening/screen_lock_compliant_pct"]; got != 100 {
		t.Errorf("screen_lock_compliant_pct = %v, want 100", got)
	}
}

func TestEndpointStaleReadingCountsAsUnknown(t *testing.T) {
	r := endpointRoster(t)
	r.Endpoint.Devices[macDevice].ObservedSecondsAgo = map[string]int{ControlDiskEncryption: 90000}
	v := endpointValues(t, r)
	if got := controlState(v, macDevice, ControlDiskEncryption); got != ReadingPass {
		t.Errorf("the device's own reading = %s, want pass whatever its age", got)
	}
	if got := coverageOf(v)["hardening.disk_encryption_pct"]; got["passing_device_count"] != 0 || got["unknown_device_count"] != 2 {
		t.Errorf("disk encryption coverage = %v, want the stale pass counted unknown", got)
	}
	if got := v["/hardening/disk_encryption_pct"]; got != 0 {
		t.Errorf("disk_encryption_pct = %v, want 0", got)
	}

	r.Endpoint.Devices[winDevice].ObservedSecondsAgo = map[string]int{ControlDiskEncryption: 90000}
	v = endpointValues(t, r)
	if got := availability(v)["hardening.disk_encryption_pct"]; got != UnavailableStale {
		t.Errorf("availability of disk_encryption_pct = %q, want stale", got)
	}
	wantUnset(t, v, "/hardening/disk_encryption_pct")
	if got := coverageOf(v)["hardening.disk_encryption_pct"]; got != nil {
		t.Errorf("metric_coverage has a stale metric: %v", got)
	}
}

func TestEndpointAvailabilityGivesTheFirstReason(t *testing.T) {
	r := endpointRoster(t)
	r.Endpoint.Unsupported = []string{ReadingMDM, ControlScreenLock}
	r.Endpoint.NotRead = []string{ControlScreenLock, ControlFirewall, ControlEDRHealthy}
	r.Endpoint.PermissionDenied = []string{ControlFirewall, ControlCompliance}
	r.Endpoint.OSBaseline = nil
	v := endpointValues(t, r)
	want := map[string]string{
		"fleet.mdm_enrolled_device_count":     UnavailableUnsupported,
		"fleet.mdm_enrolled_pct":              UnavailableUnsupported,
		"hardening.screen_lock_compliant_pct": UnavailableUnsupported,
		"hardening.firewall_enabled_pct":      UnavailableNotRead,
		"protection.edr_healthy_pct":          UnavailableNotRead,
		"compliance.compliant_pct":            UnavailablePermissionDenied,
		"patching.os_baseline_compliant_pct":  UnavailableNotConfigured,
	}
	if got := availability(v); !maps.Equal(got, want) {
		t.Errorf("availability = %v, want %v", got, want)
	}
	wantUnset(t, v, "/fleet/mdm_enrolled_device_count", "/fleet/mdm_enrolled_pct", "/hardening/screen_lock_compliant_pct",
		"/hardening/firewall_enabled_pct", "/protection/edr_healthy_pct", "/compliance/compliant_pct", "/compliance/basis",
		"/patching/os_baseline_compliant_pct", "/patching/baseline_id")
	wantValues(t, v, map[string]any{
		"/fleet/devices_present":                    true,
		"/protection/edr_installed_pct":             100,
		"/devices/1/protection_modules/0/kind":      ModuleEDR,
		"/devices/1/protection_modules/0/installed": true,
		"/devices/1/protection_modules/1/kind":      ModuleAntimalware,
	})
	wantUnset(t, v, "/devices/1/protection_modules/0/healthy", "/devices/1/protection_modules/2/kind")
	controls := controlsOf(v, macDevice)
	for _, gone := range []string{ControlScreenLock, ControlFirewall, ControlEDRHealthy, ControlCompliance, ControlOSBaseline} {
		if _, ok := controls[gone]; ok {
			t.Errorf("the device's controls hold %s, which the collector can't have", gone)
		}
	}
	if len(controls) != 5 {
		t.Errorf("controls = %v, want the 5 readings the collector has", controls)
	}

	r = endpointRoster(t)
	r.Endpoint.CompliancePolicy, r.Endpoint.ScreenLockPolicy = nil, nil
	if got := availability(endpointValues(t, r)); got["compliance.compliant_pct"] != UnavailableNotConfigured || got["hardening.screen_lock_compliant_pct"] != UnavailableNotConfigured {
		t.Errorf("availability = %v, want compliance and screen lock not configured", got)
	}
}

func TestEndpointIncompleteDiscoveryLeavesOutTheFleet(t *testing.T) {
	r := endpointRoster(t)
	r.Endpoint.Unsupported = []string{ControlEDRInstalled}
	r.Endpoint.Devices = append(r.Endpoint.Devices, Device{Key: "zz-hidden", OS: "darwin", Management: "agent", LastSeenSecondsAgo: endpointPtr(10), Readable: false})
	v := endpointValues(t, r)
	wantValues(t, v, map[string]any{
		"/scope/discovery_complete":    false,
		"/scope/observed_device_count": 4,
		"/devices/4/device_id":         "win",
	})
	wantUnset(t, v, "/devices/5/device_id", "/compliance/basis", "/patching/baseline_id")
	for pointer := range v {
		for _, section := range []string{"/fleet/", "/compliance/", "/hardening/", "/patching/", "/protection/", "/metric_coverage/"} {
			if strings.HasPrefix(pointer, section) {
				t.Errorf("%s is set though discovery is incomplete", pointer)
			}
		}
	}
	got := availability(v)
	if len(got) != len(endpointMetrics) {
		t.Errorf("availability lists %d metrics, want all %d: %v", len(got), len(endpointMetrics), got)
	}
	if got["fleet.device_count"] != UnavailablePartial || got["protection.edr_installed_pct"] != UnavailableUnsupported {
		t.Errorf("availability = %v, want partial but for edr_installed, which is unsupported", got)
	}
	if controlState(v, winDevice, ControlDiskEncryption) != ReadingFail {
		t.Errorf("devices' controls are left out with the fleet")
	}
}

func TestEndpointWithNoDevicesCountsZero(t *testing.T) {
	r := endpointRoster(t)
	r.Endpoint.Devices = nil
	v := endpointValues(t, r)
	wantValues(t, v, map[string]any{
		"/scope/discovery_complete":      true,
		"/scope/observed_device_count":   0,
		"/fleet/devices_present":         false,
		"/fleet/device_count":            0,
		"/fleet/mdm_enrolled_pct":        nil,
		"/fleet/devices_by_os":           map[string]int{},
		"/hardening/disk_encryption_pct": nil,
		"/patching/unsupported_os_count": 0,
	})

	r.Endpoint = nil
	values, err := Derive(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := values[EndpointPosture]; ok {
		t.Error("a roster with no endpoint block gives endpoint-posture values")
	}
}

func TestEndpointParseRefusesUnmappedTermsAndUnknownNames(t *testing.T) {
	cases := map[string]struct{ from, to, want string }{
		"os":            {`"os": "ios"`, `"os": "watchos"`, `os "watchos" has no entry in terms.endpoint_os`},
		"management":    {`"management": "agentless"`, `"management": "byod"`, `management "byod" has no entry in terms.endpoint_management`},
		"mdm":           {`"mdm": "none"`, `"mdm": "jamf"`, `mdm "jamf" has no entry in terms.endpoint_mdm`},
		"volume":        {`"D:": "off"`, `"D:": "suspended"`, `volume D: state "suspended" has no entry in terms.endpoint_encryption`},
		"verdict":       {`"compliance": "noncompliant"`, `"compliance": "inGracePeriod"`, `compliance "inGracePeriod" has no entry in terms.endpoint_verdicts`},
		"module":        {`"Defender": {`, `"Sophos": {`, `module "Sophos" has no entry in terms.endpoint_modules`},
		"group":         {`"groups": ["Administrators"]`, `"groups": ["Power Users"]`, `group "Power Users" has no entry in terms.endpoint_local_groups`},
		"finding type":  {`"type": "firewall_off"`, `"type": "usb_storage"`, `type "usb_storage" has no entry in terms.endpoint_finding_types`},
		"finding state": {`"status": "fixed"`, `"status": "muted"`, `status "muted" has no entry in terms.endpoint_finding_statuses`},
		"term value":    {`"darwin": "macos"`, `"darwin": "mac"`, `terms.endpoint_os maps "darwin" to "mac"`},
		"reading":       {`"not_applicable": {"firewall"`, `"not_applicable": {"host_firewall"`, `not_applicable names "host_firewall"`},
		"family":        {`"firewall": ["ios"]`, `"firewall": ["watchos"]`, `not_applicable.firewall names "watchos"`},
		"scope state":   {`"management": ["managed"]`, `"management": ["agent"]`, `scope.management names "agent"`},
		"scope name":    {`"name": "managed_devices"`, `"name": "Managed devices"`, `scope.name "Managed devices"`},
		"window":        {`"max_observation_age_seconds": 86400`, `"max_observation_age_seconds": 0`, `max_observation_age_seconds is 0`},
		"version":       {`"macos": "15.1"`, `"macos": "Sequoia"`, `os_baseline.min_versions.macos "Sequoia" is no version`},
		"timestamp":     {`"created_at": "2025-01-06T09:00:00Z"`, `"created_at": "January 6"`, `created_at "January 6" is not an RFC 3339 time`},
		"two modules":   {`"alf": {"enabled": true}`, `"alf": {"enabled": true}, "Windows Firewall": {}`, `are both firewall`},
		"observed":      {`"last_seen_seconds_ago": 300,`, `"last_seen_seconds_ago": 300, "observed_seconds_ago": {"mdm": 400},`, `observed_seconds_ago names "mdm"`},
		"too new":       {`"last_seen_seconds_ago": 300,`, `"last_seen_seconds_ago": 300, "observed_seconds_ago": {"firewall": 10},`, `observed_seconds_ago.firewall is newer`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			changed := strings.Replace(endpointTenant, tc.from, tc.to, 1)
			if changed == endpointTenant {
				t.Fatalf("%q is not in the roster", tc.from)
			}
			_, err := Parse([]byte(changed))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Parse() error = %v, want one containing %q", err, tc.want)
			}
		})
	}
	r := endpointRoster(t)
	r.Endpoint.NotRead = []string{"screen_locks"}
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), `not_read names "screen_locks"`) {
		t.Errorf("Validate() error = %v, want one naming screen_locks", err)
	}
}

func TestEndpointExtrasStayAndClonesAreIndependent(t *testing.T) {
	r := endpointRoster(t)
	var agent string
	if ok, err := r.Endpoint.Devices[macDevice].Extra.Get("agentVersion", &agent); !ok || err != nil || agent != "2.1.0" {
		t.Fatalf("agentVersion = %q, %t, %v", agent, ok, err)
	}
	c := r.Clone()
	c.Endpoint.Devices[winDevice].Volumes["D:"] = "on"
	*c.Endpoint.Devices[winDevice].Modules[0].Current = true
	c.Endpoint.NotApplicable[ControlFirewall][0] = "android"
	c.Endpoint.Scope.Name = "other"
	if r.Endpoint.Devices[winDevice].Volumes["D:"] != "off" || *r.Endpoint.Devices[winDevice].Modules[0].Current ||
		r.Endpoint.NotApplicable[ControlFirewall][0] != "ios" || r.Endpoint.Scope.Name != "managed_devices" {
		t.Error("changing a clone changed the roster")
	}
}
