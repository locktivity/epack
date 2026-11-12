package roster

import (
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/locktivity/epack/componentsdk"
)

// Normalized endpoint terms.
const (
	ManagementManaged   = "managed"
	ManagementUnmanaged = "unmanaged"
	ManagementRetired   = "retired"
	ManagementUnknown   = "unknown"

	MDMEnrolled    = "enrolled"
	MDMNotEnrolled = "not_enrolled"
	MDMUnknown     = "unknown"

	VolumeEncrypted    = "encrypted"
	VolumeNotEncrypted = "not_encrypted"
	VolumeUnknown      = "unknown"

	ReadingPass          = "pass"
	ReadingFail          = "fail"
	ReadingUnknown       = "unknown"
	ReadingNotApplicable = "not_applicable"

	ModuleAntimalware   = "antimalware"
	ModuleEDR           = "edr"
	ModuleFirewall      = "firewall"
	ModuleDeviceControl = "device_control"
	// ModuleOther is a vendor module that is none of the others, such as a
	// web content filter. Derive leaves it out.
	ModuleOther = "other"

	DeviceFindingOpen     = "open"
	DeviceFindingResolved = "resolved"
	DeviceFindingUnknown  = "unknown"
)

// The controls a device is read for, by their normalized keys, and the MDM
// enrollment reading, which has no control. Together they are the readings
// an endpoint block's unsupported, not_read and permission_denied name.
const (
	ControlDiskEncryption       = "disk_encryption"
	ControlScreenLock           = "screen_lock"
	ControlFirewall             = "firewall"
	ControlOSSupported          = "os_supported"
	ControlOSBaseline           = "os_baseline"
	ControlCompliance           = "compliance"
	ControlAntimalwareInstalled = "antimalware_installed"
	ControlAntimalwareHealthy   = "antimalware_healthy"
	ControlEDRInstalled         = "edr_installed"
	ControlEDRHealthy           = "edr_healthy"
	ReadingMDM                  = "mdm"
)

// Why a metric has no reading, as the availability list says.
const (
	UnavailableUnsupported      = "unsupported"
	UnavailableNotRead          = "not_read"
	UnavailablePermissionDenied = "permission_denied"
	UnavailableNotConfigured    = "not_configured"
	UnavailableStale            = "stale"
	UnavailablePartial          = "partial"
)

var (
	endpointControls = []string{
		ControlDiskEncryption, ControlScreenLock, ControlFirewall, ControlOSSupported, ControlOSBaseline, ControlCompliance,
		ControlAntimalwareInstalled, ControlAntimalwareHealthy, ControlEDRInstalled, ControlEDRHealthy,
	}
	endpointReadings   = append(slices.Clone(endpointControls), ReadingMDM)
	endpointOSFamilies = []string{"windows", "macos", "linux", "ios", "ipados", "android", "chromeos", "other", "unknown"}
	endpointScopeName  = regexp.MustCompile(`^[a-z0-9_]+$`)

	// endpointMetrics are the schema's metrics in its order, each with the
	// reading it needs, or none for a fleet total.
	endpointMetrics = []struct{ path, reading string }{
		{"fleet.devices_present", ""},
		{"fleet.device_count", ""},
		{"fleet.managed_device_count", ""},
		{"fleet.mdm_enrolled_device_count", ReadingMDM},
		{"fleet.mdm_enrolled_pct", ReadingMDM},
		{"fleet.devices_by_os", ""},
		{"compliance.compliant_pct", ControlCompliance},
		{"hardening.disk_encryption_pct", ControlDiskEncryption},
		{"hardening.screen_lock_compliant_pct", ControlScreenLock},
		{"hardening.firewall_enabled_pct", ControlFirewall},
		{"patching.os_supported_pct", ControlOSSupported},
		{"patching.os_baseline_compliant_pct", ControlOSBaseline},
		{"patching.unsupported_os_count", ControlOSSupported},
		{"protection.antimalware_installed_pct", ControlAntimalwareInstalled},
		{"protection.antimalware_healthy_pct", ControlAntimalwareHealthy},
		{"protection.edr_installed_pct", ControlEDRInstalled},
		{"protection.edr_healthy_pct", ControlEDRHealthy},
	}

	// moduleReadings gives, for each module kind, the readings its installed
	// and healthy facts feed.
	moduleReadings = map[string][2]string{
		ModuleAntimalware: {ControlAntimalwareInstalled, ControlAntimalwareHealthy},
		ModuleEDR:         {ControlEDRInstalled, ControlEDRHealthy},
		ModuleFirewall:    {ControlFirewall, ControlFirewall},
	}
)

// Endpoint is the devices a device manager holds, the tenant's settings that
// judge them, and the readings the collector can't have.
//
// The roster's endpoint block:
//
//	"endpoint": {
//	  "organization_id": "...",
//	  "scope": {"name": "managed_devices", "max_observation_age_seconds": 2592000,
//	    "management": ["managed"]},
//	  "compliance_policy": {"baseline_id": "...", "baseline_version": "..."},
//	  "screen_lock_policy": {"max_idle_seconds": 900},
//	  "os_support": {"<os family>": "13"},
//	  "os_baseline": {"id": "...", "version": "...", "min_versions": {"<os family>": "15.1"}},
//	  "not_applicable": {"<control>": ["<os family>", ...]},
//	  "unsupported": ["<reading>", ...], "not_read": [...], "permission_denied": [...],
//	  "devices": {"<device id>": {"hostname": "...", "os": "...", "os_name": "...",
//	    "os_version": "15.1.1", "user": {"id": "...", "login": "..."},
//	    "management": "...", "mdm": "...", "created_at": "2025-01-06T09:00:00Z",
//	    "last_seen_seconds_ago": 3600, "observed_seconds_ago": {"<control>": 86400},
//	    "readable": true, "volumes": {"<volume>": "..."},
//	    "screen_lock": {"enabled": true, "idle_seconds": 300}, "compliance": "...",
//	    "modules": {"<module>": {"installed": true, "enabled": true, "running": true,
//	      "current": true, "reporting": true}},
//	    "local_accounts": {"<account id>": {"username": "...", "groups": [...]}},
//	    "findings": {"<finding id>": {"type": "...", "status": "...",
//	      "first_seen_at": "...", "last_seen_at": "...", "resolved_at": "...",
//	      "reason_code": "..."}}}}
//	}
//
// os, management, mdm, the volumes' states, compliance, the modules' names,
// the local accounts' groups, and the findings' types and statuses are
// vendor terms, which terms.endpoint_os, endpoint_management, endpoint_mdm,
// endpoint_encryption, endpoint_verdicts, endpoint_modules,
// endpoint_local_groups, endpoint_finding_types and endpoint_finding_statuses
// map. A reading is a control's key, such as disk_encryption, or mdm. A
// version is numbers separated by dots, such as 10.0.22631.
//
// scope is the collector's: the name it gives its scope, the window a device
// must have reported in to count, and the management states it counts, every
// state when management is left out. not_read lists the readings the vendor
// has and the collector does not read. Everything else is the tenant's or the
// vendor's. A tenant with no compliance_policy, screen_lock_policy or
// os_baseline has not configured that reading. os_support gives, by OS
// family, the lowest version that gets security updates on the day of the
// run. unsupported lists the readings the vendor never reports, and
// permission_denied those the collector's credential may not read.
//
// A device's facts are those the vendor reports. A device with no os is of
// the unknown family, and one with no management is in the unknown state. A
// device with no last_seen_seconds_ago has never reported. Each reading is as
// old as the device's last report unless observed_seconds_ago says it is
// older. A device with readable false is one the vendor lists and won't give
// the collector the details of. A module the vendor lists is installed unless
// installed is false, and running when it is enabled unless running says
// otherwise. A fact a device leaves out is one the vendor doesn't report for
// it. Finding times are when the vendor recorded them.
type Endpoint struct {
	OrganizationID   string
	Scope            EndpointScope
	CompliancePolicy *CompliancePolicy
	ScreenLockPolicy *ScreenLockPolicy
	// OSSupport gives, by OS family, the lowest OS version that still gets
	// security updates.
	OSSupport  map[string]string
	OSBaseline *OSBaseline
	// NotApplicable lists, by control, the OS families it doesn't apply to.
	NotApplicable    map[string][]string
	Unsupported      []string
	NotRead          []string
	PermissionDenied []string
	Devices          []Device
	Extra            Extra
}

// EndpointScope is the collector's scope: its name, how recently a device
// must have reported to count, and the normalized management states it
// counts, every state when Management is empty.
type EndpointScope struct {
	Name                     string   `json:"name"`
	MaxObservationAgeSeconds int      `json:"max_observation_age_seconds"`
	Management               []string `json:"management"`
}

// CompliancePolicy is how a tenant judges its devices compliant: by the
// device manager's own policy, or by the baseline it names.
type CompliancePolicy struct {
	BaselineID      string `json:"baseline_id"`
	BaselineVersion string `json:"baseline_version"`
}

// ScreenLockPolicy is the longest a device may sit idle before its screen
// locks.
type ScreenLockPolicy struct {
	MaxIdleSeconds int `json:"max_idle_seconds"`
}

// OSBaseline is a named baseline of OS versions: the lowest version each OS
// family it covers must run.
type OSBaseline struct {
	ID          string            `json:"id"`
	Version     string            `json:"version"`
	MinVersions map[string]string `json:"min_versions"`
}

// Device is a device the device manager lists, keyed by the vendor's device
// ID.
type Device struct {
	Key        string
	Hostname   string
	OS         string
	OSName     string
	OSVersion  string
	User       *DeviceUser
	Management string
	MDM        string
	CreatedAt  string
	// LastSeenSecondsAgo is the age of the device's last report, or nil
	// when it has never reported.
	LastSeenSecondsAgo *int
	// ObservedSecondsAgo gives, by control, the age of a reading older than
	// the device's last report.
	ObservedSecondsAgo map[string]int
	Readable           bool
	// Volumes gives each volume's encryption state.
	Volumes       map[string]string
	ScreenLock    *ScreenLock
	Compliance    string
	Modules       []DeviceModule
	LocalAccounts []DeviceAccount
	Findings      []DeviceFinding
	Extra         Extra
}

// DeviceUser is a device's primary user.
type DeviceUser struct {
	ID    string `json:"id"`
	Login string `json:"login"`
}

// ScreenLock is a device's screen lock setting. IdleSeconds is nil when the
// vendor doesn't report it.
type ScreenLock struct {
	Enabled     bool `json:"enabled"`
	IdleSeconds *int `json:"idle_seconds"`
}

// DeviceModule is a security module on a device. Each fact but Installed is
// nil when the vendor doesn't report it. Current is whether an antimalware
// module's signatures are up to date, and Reporting whether an EDR module
// reports to its console.
type DeviceModule struct {
	Key       string
	Installed bool
	Enabled   *bool
	Running   *bool
	Current   *bool
	Reporting *bool
	Extra     Extra
}

// DeviceAccount is a local account on a device, with the local groups it is
// in.
type DeviceAccount struct {
	Key      string
	Username string
	Groups   []string
	Extra    Extra
}

// DeviceFinding is a control issue the vendor recorded for a device.
type DeviceFinding struct {
	Key         string
	Type        string
	Status      string
	FirstSeenAt string
	LastSeenAt  string
	ResolvedAt  string
	ReasonCode  string
	Extra       Extra
}

// EndpointTerms maps the vendor terms a roster's endpoint block uses to
// normalized ones.
type EndpointTerms struct {
	EndpointOS              map[string]string `json:"endpoint_os"`
	EndpointManagement      map[string]string `json:"endpoint_management"`
	EndpointMDM             map[string]string `json:"endpoint_mdm"`
	EndpointEncryption      map[string]string `json:"endpoint_encryption"`
	EndpointVerdicts        map[string]string `json:"endpoint_verdicts"`
	EndpointModules         map[string]string `json:"endpoint_modules"`
	EndpointLocalGroups     map[string]string `json:"endpoint_local_groups"`
	EndpointFindingTypes    map[string]string `json:"endpoint_finding_types"`
	EndpointFindingStatuses map[string]string `json:"endpoint_finding_statuses"`
}

var endpointDomain = domain{
	key: "endpoint",
	parse: func(r *Roster, raw json.RawMessage) error {
		e, err := parseEndpoint(raw)
		if err != nil {
			return err
		}
		r.Endpoint = e
		return nil
	},
	validate: validateEndpoint,
	clone: func(c, r *Roster) {
		if r.Endpoint != nil {
			c.Endpoint = r.Endpoint.clone()
		}
	},
	derive: deriveEndpoint,
	notDerived: map[string]map[string]string{EndpointPosture: {
		"/devices/*/last_seen_at":                     "the time of the run less the device's last_seen_seconds_ago; Derive has no clock",
		"/devices/*/controls/*/observed_at":           "the time of the run less the reading's age; Derive has no clock",
		"/devices/*/protection_modules/*/observed_at": "the time of the run less the reading's age; Derive has no clock",
		"/availability/*/message":                     "free text the schema leaves to the collector",
	}},
}

func parseEndpoint(raw json.RawMessage) (*Endpoint, error) {
	var f struct {
		OrganizationID   string                     `json:"organization_id"`
		Scope            EndpointScope              `json:"scope"`
		CompliancePolicy *CompliancePolicy          `json:"compliance_policy"`
		ScreenLockPolicy *ScreenLockPolicy          `json:"screen_lock_policy"`
		OSSupport        map[string]string          `json:"os_support"`
		OSBaseline       *OSBaseline                `json:"os_baseline"`
		NotApplicable    map[string][]string        `json:"not_applicable"`
		Unsupported      []string                   `json:"unsupported"`
		NotRead          []string                   `json:"not_read"`
		PermissionDenied []string                   `json:"permission_denied"`
		Devices          map[string]json.RawMessage `json:"devices"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, err
	}
	e := &Endpoint{
		OrganizationID: f.OrganizationID, Scope: f.Scope, CompliancePolicy: f.CompliancePolicy, ScreenLockPolicy: f.ScreenLockPolicy,
		OSSupport: f.OSSupport, OSBaseline: f.OSBaseline, NotApplicable: f.NotApplicable,
		Unsupported: f.Unsupported, NotRead: f.NotRead, PermissionDenied: f.PermissionDenied,
	}
	var err error
	if e.Extra, err = extra(raw, "organization_id", "scope", "compliance_policy", "screen_lock_policy", "os_support", "os_baseline",
		"not_applicable", "unsupported", "not_read", "permission_denied", "devices"); err != nil {
		return nil, err
	}
	for _, key := range sortedKeys(f.Devices) {
		d, err := parseDevice(key, f.Devices[key])
		if err != nil {
			return nil, err
		}
		e.Devices = append(e.Devices, d)
	}
	return e, nil
}

func parseDevice(key string, raw json.RawMessage) (Device, error) {
	var d struct {
		Hostname           string                     `json:"hostname"`
		OS                 string                     `json:"os"`
		OSName             string                     `json:"os_name"`
		OSVersion          string                     `json:"os_version"`
		User               *DeviceUser                `json:"user"`
		Management         string                     `json:"management"`
		MDM                string                     `json:"mdm"`
		CreatedAt          string                     `json:"created_at"`
		LastSeenSecondsAgo *int                       `json:"last_seen_seconds_ago"`
		ObservedSecondsAgo map[string]int             `json:"observed_seconds_ago"`
		Readable           *bool                      `json:"readable"`
		Volumes            map[string]string          `json:"volumes"`
		ScreenLock         *ScreenLock                `json:"screen_lock"`
		Compliance         string                     `json:"compliance"`
		Modules            map[string]json.RawMessage `json:"modules"`
		LocalAccounts      map[string]json.RawMessage `json:"local_accounts"`
		Findings           map[string]json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return Device{}, fmt.Errorf("device %s: %w", key, err)
	}
	out := Device{
		Key: key, Hostname: d.Hostname, OS: d.OS, OSName: d.OSName, OSVersion: d.OSVersion, User: d.User,
		Management: d.Management, MDM: d.MDM, CreatedAt: d.CreatedAt, LastSeenSecondsAgo: d.LastSeenSecondsAgo,
		ObservedSecondsAgo: d.ObservedSecondsAgo, Readable: d.Readable == nil || *d.Readable, Volumes: d.Volumes,
		ScreenLock: d.ScreenLock, Compliance: d.Compliance,
	}
	var err error
	if out.Extra, err = extra(raw, "hostname", "os", "os_name", "os_version", "user", "management", "mdm", "created_at",
		"last_seen_seconds_ago", "observed_seconds_ago", "readable", "volumes", "screen_lock", "compliance", "modules",
		"local_accounts", "findings"); err != nil {
		return Device{}, fmt.Errorf("device %s: %w", key, err)
	}
	for _, mk := range sortedKeys(d.Modules) {
		var m struct {
			Installed *bool `json:"installed"`
			Enabled   *bool `json:"enabled"`
			Running   *bool `json:"running"`
			Current   *bool `json:"current"`
			Reporting *bool `json:"reporting"`
		}
		if err := json.Unmarshal(d.Modules[mk], &m); err != nil {
			return Device{}, fmt.Errorf("device %s module %s: %w", key, mk, err)
		}
		me, err := extra(d.Modules[mk], "installed", "enabled", "running", "current", "reporting")
		if err != nil {
			return Device{}, fmt.Errorf("device %s module %s: %w", key, mk, err)
		}
		out.Modules = append(out.Modules, DeviceModule{Key: mk, Installed: m.Installed == nil || *m.Installed, Enabled: m.Enabled,
			Running: m.Running, Current: m.Current, Reporting: m.Reporting, Extra: me})
	}
	for _, ak := range sortedKeys(d.LocalAccounts) {
		var a struct {
			Username string   `json:"username"`
			Groups   []string `json:"groups"`
		}
		if err := json.Unmarshal(d.LocalAccounts[ak], &a); err != nil {
			return Device{}, fmt.Errorf("device %s local account %s: %w", key, ak, err)
		}
		ae, err := extra(d.LocalAccounts[ak], "username", "groups")
		if err != nil {
			return Device{}, fmt.Errorf("device %s local account %s: %w", key, ak, err)
		}
		out.LocalAccounts = append(out.LocalAccounts, DeviceAccount{Key: ak, Username: a.Username, Groups: a.Groups, Extra: ae})
	}
	for _, fk := range sortedKeys(d.Findings) {
		var f struct {
			Type        string `json:"type"`
			Status      string `json:"status"`
			FirstSeenAt string `json:"first_seen_at"`
			LastSeenAt  string `json:"last_seen_at"`
			ResolvedAt  string `json:"resolved_at"`
			ReasonCode  string `json:"reason_code"`
		}
		if err := json.Unmarshal(d.Findings[fk], &f); err != nil {
			return Device{}, fmt.Errorf("device %s finding %s: %w", key, fk, err)
		}
		fe, err := extra(d.Findings[fk], "type", "status", "first_seen_at", "last_seen_at", "resolved_at", "reason_code")
		if err != nil {
			return Device{}, fmt.Errorf("device %s finding %s: %w", key, fk, err)
		}
		out.Findings = append(out.Findings, DeviceFinding{Key: fk, Type: f.Type, Status: f.Status, FirstSeenAt: f.FirstSeenAt,
			LastSeenAt: f.LastSeenAt, ResolvedAt: f.ResolvedAt, ReasonCode: f.ReasonCode, Extra: fe})
	}
	return out, nil
}

func validateEndpoint(r *Roster) error {
	t := r.Terms.EndpointTerms
	checks := map[string]struct {
		terms map[string]string
		allow []string
	}{
		"endpoint_os":               {t.EndpointOS, endpointOSFamilies},
		"endpoint_management":       {t.EndpointManagement, []string{ManagementManaged, ManagementUnmanaged, ManagementRetired, ManagementUnknown}},
		"endpoint_mdm":              {t.EndpointMDM, []string{MDMEnrolled, MDMNotEnrolled, MDMUnknown}},
		"endpoint_encryption":       {t.EndpointEncryption, []string{VolumeEncrypted, VolumeNotEncrypted, VolumeUnknown}},
		"endpoint_verdicts":         {t.EndpointVerdicts, []string{ReadingPass, ReadingFail, ReadingUnknown, ReadingNotApplicable}},
		"endpoint_modules":          {t.EndpointModules, []string{ModuleAntimalware, ModuleEDR, ModuleFirewall, ModuleDeviceControl, ModuleOther}},
		"endpoint_local_groups":     {t.EndpointLocalGroups, []string{RoleAdmin, RoleNone}},
		"endpoint_finding_types":    {t.EndpointFindingTypes, endpointControls},
		"endpoint_finding_statuses": {t.EndpointFindingStatuses, []string{DeviceFindingOpen, DeviceFindingResolved, DeviceFindingUnknown}},
	}
	for _, name := range sortedKeys(checks) {
		m := checks[name]
		for _, vendor := range sortedKeys(m.terms) {
			if !slices.Contains(m.allow, m.terms[vendor]) {
				return fmt.Errorf("terms.%s maps %q to %q, which is none of %v", name, vendor, m.terms[vendor], m.allow)
			}
		}
	}
	e := r.Endpoint
	if e == nil {
		return nil
	}
	if !endpointScopeName.MatchString(e.Scope.Name) {
		return fmt.Errorf("scope.name %q is not a name of lowercase letters, digits and underscores", e.Scope.Name)
	}
	if e.Scope.MaxObservationAgeSeconds < 1 {
		return fmt.Errorf("scope.max_observation_age_seconds is %d; it is at least 1", e.Scope.MaxObservationAgeSeconds)
	}
	if err := endpointAllowed("scope.management", checks["endpoint_management"].allow, e.Scope.Management...); err != nil {
		return err
	}
	for name, readings := range map[string][]string{"unsupported": e.Unsupported, "not_read": e.NotRead, "permission_denied": e.PermissionDenied} {
		if err := endpointAllowed(name, endpointReadings, readings...); err != nil {
			return err
		}
	}
	for _, control := range sortedKeys(e.NotApplicable) {
		if err := endpointAllowed("not_applicable", endpointControls, control); err != nil {
			return err
		}
		if err := endpointAllowed("not_applicable."+control, endpointOSFamilies, e.NotApplicable[control]...); err != nil {
			return err
		}
	}
	if err := endpointVersions("os_support", e.OSSupport); err != nil {
		return err
	}
	if b := e.OSBaseline; b != nil {
		if b.ID == "" {
			return fmt.Errorf("os_baseline has no id")
		}
		if err := endpointVersions("os_baseline.min_versions", b.MinVersions); err != nil {
			return err
		}
	}
	if p := e.ScreenLockPolicy; p != nil && p.MaxIdleSeconds < 1 {
		return fmt.Errorf("screen_lock_policy.max_idle_seconds is %d; it is at least 1", p.MaxIdleSeconds)
	}
	for _, d := range e.Devices {
		if err := r.validateDevice(d); err != nil {
			return fmt.Errorf("device %s: %w", d.Key, err)
		}
	}
	return nil
}

func (r *Roster) validateDevice(d Device) error {
	t := r.Terms.EndpointTerms
	for _, term := range []struct {
		terms               map[string]string
		block, what, vendor string
	}{
		{t.EndpointOS, "endpoint_os", "os", d.OS},
		{t.EndpointManagement, "endpoint_management", "management", d.Management},
		{t.EndpointMDM, "endpoint_mdm", "mdm", d.MDM},
		{t.EndpointVerdicts, "endpoint_verdicts", "compliance", d.Compliance},
	} {
		if term.vendor == "" {
			continue
		}
		if err := mapped(term.terms, term.block, term.what, term.vendor); err != nil {
			return err
		}
	}
	for _, volume := range sortedKeys(d.Volumes) {
		if err := mapped(t.EndpointEncryption, "endpoint_encryption", "volume "+volume+" state", d.Volumes[volume]); err != nil {
			return err
		}
	}
	if d.User != nil && d.User.ID == "" {
		return fmt.Errorf("user has no id")
	}
	if d.LastSeenSecondsAgo != nil && *d.LastSeenSecondsAgo < 0 {
		return fmt.Errorf("last seen %d seconds from now", *d.LastSeenSecondsAgo)
	}
	for _, control := range sortedKeys(d.ObservedSecondsAgo) {
		if err := endpointAllowed("observed_seconds_ago", endpointControls, control); err != nil {
			return err
		}
		if d.LastSeenSecondsAgo == nil {
			return fmt.Errorf("observed_seconds_ago.%s is set, and the device has never reported", control)
		}
		if d.ObservedSecondsAgo[control] < *d.LastSeenSecondsAgo {
			return fmt.Errorf("observed_seconds_ago.%s is newer than the device's last report", control)
		}
	}
	if d.ScreenLock != nil && d.ScreenLock.IdleSeconds != nil && *d.ScreenLock.IdleSeconds < 0 {
		return fmt.Errorf("screen_lock.idle_seconds is %d", *d.ScreenLock.IdleSeconds)
	}
	kinds := map[string]string{}
	for _, m := range d.Modules {
		if err := mapped(t.EndpointModules, "endpoint_modules", "module", m.Key); err != nil {
			return err
		}
		kind := t.EndpointModules[m.Key]
		if prev, ok := kinds[kind]; ok && kind != ModuleOther {
			return fmt.Errorf("modules %s and %s are both %s; a device has one module of each kind", prev, m.Key, kind)
		}
		kinds[kind] = m.Key
	}
	for _, a := range d.LocalAccounts {
		if err := mapped(t.EndpointLocalGroups, "endpoint_local_groups", "local account "+a.Key+" group", a.Groups...); err != nil {
			return err
		}
	}
	timestamps := []struct{ what, at string }{{"created_at", d.CreatedAt}}
	for _, f := range d.Findings {
		if err := mapped(t.EndpointFindingTypes, "endpoint_finding_types", "finding "+f.Key+" type", f.Type); err != nil {
			return err
		}
		if err := mapped(t.EndpointFindingStatuses, "endpoint_finding_statuses", "finding "+f.Key+" status", f.Status); err != nil {
			return err
		}
		timestamps = append(timestamps, []struct{ what, at string }{
			{"finding " + f.Key + " first_seen_at", f.FirstSeenAt}, {"finding " + f.Key + " last_seen_at", f.LastSeenAt},
			{"finding " + f.Key + " resolved_at", f.ResolvedAt},
		}...)
	}
	for _, ts := range timestamps {
		if ts.at == "" {
			continue
		}
		if _, err := time.Parse(time.RFC3339, ts.at); err != nil {
			return fmt.Errorf("%s %q is not an RFC 3339 time", ts.what, ts.at)
		}
	}
	return nil
}

// endpointAllowed checks that each of names is one of allow.
func endpointAllowed(what string, allow []string, names ...string) error {
	for _, n := range names {
		if !slices.Contains(allow, n) {
			return fmt.Errorf("%s names %q, which is none of %v", what, n, allow)
		}
	}
	return nil
}

func endpointVersions(what string, byFamily map[string]string) error {
	for _, family := range sortedKeys(byFamily) {
		if err := endpointAllowed(what, endpointOSFamilies, family); err != nil {
			return err
		}
		if _, ok := parseOSVersion(byFamily[family]); !ok {
			return fmt.Errorf("%s.%s %q is no version", what, family, byFamily[family])
		}
	}
	return nil
}

func (e *Endpoint) clone() *Endpoint {
	c := *e
	c.Scope.Management = slices.Clone(e.Scope.Management)
	c.CompliancePolicy, c.ScreenLockPolicy = endpointCopy(e.CompliancePolicy), endpointCopy(e.ScreenLockPolicy)
	c.OSSupport = maps.Clone(e.OSSupport)
	if e.OSBaseline != nil {
		b := *e.OSBaseline
		b.MinVersions = maps.Clone(b.MinVersions)
		c.OSBaseline = &b
	}
	c.NotApplicable = map[string][]string{}
	for k, v := range e.NotApplicable {
		c.NotApplicable[k] = slices.Clone(v)
	}
	c.Unsupported, c.NotRead, c.PermissionDenied = slices.Clone(e.Unsupported), slices.Clone(e.NotRead), slices.Clone(e.PermissionDenied)
	c.Devices = slices.Clone(e.Devices)
	for i := range c.Devices {
		d := &c.Devices[i]
		d.User, d.LastSeenSecondsAgo = endpointCopy(d.User), endpointCopy(d.LastSeenSecondsAgo)
		d.ObservedSecondsAgo, d.Volumes = maps.Clone(d.ObservedSecondsAgo), maps.Clone(d.Volumes)
		if d.ScreenLock != nil {
			s := *d.ScreenLock
			s.IdleSeconds = endpointCopy(s.IdleSeconds)
			d.ScreenLock = &s
		}
		d.Modules = slices.Clone(d.Modules)
		for j := range d.Modules {
			m := &d.Modules[j]
			m.Enabled, m.Running, m.Current, m.Reporting = endpointCopy(m.Enabled), endpointCopy(m.Running), endpointCopy(m.Current), endpointCopy(m.Reporting)
		}
		d.LocalAccounts = slices.Clone(d.LocalAccounts)
		for j := range d.LocalAccounts {
			d.LocalAccounts[j].Groups = slices.Clone(d.LocalAccounts[j].Groups)
		}
		d.Findings = slices.Clone(d.Findings)
	}
	return &c
}

func endpointCopy[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// deriveEndpoint gives endpoint-posture's values. A device counts toward
// the fleet, and is in scope, when the collector could read it, it reported
// within the scope's window, and its management state is one the scope
// counts. A device the collector couldn't read is left out of the devices
// list and makes discovery incomplete. A metric has no value when a reading
// it needs is unavailable, when discovery is incomplete, or when no device in
// scope has a reading of it that passed or failed within the window and some
// have older ones, and availability gives the first of those reasons. A
// percentage is of the devices in scope whose reading passed, out of those
// whose reading passed or failed, where a reading older than the window
// counts as unknown.
func deriveEndpoint(r *Roster, out Values) error {
	e := r.Endpoint
	if e == nil {
		return nil
	}
	v := out[EndpointPosture]
	if v == nil {
		v = map[string]any{}
		out[EndpointPosture] = v
	}
	window := e.Scope.MaxObservationAgeSeconds
	complete := !slices.ContainsFunc(e.Devices, func(d Device) bool { return !d.Readable })
	if e.OrganizationID != "" {
		v["/organization_id"] = e.OrganizationID
	}
	v["/scope/discovery_complete"] = complete
	v["/scope/description"] = e.Scope.Name
	v["/scope/max_observation_age_seconds"] = window

	var inScope []Device
	observed, n := 0, 0
	for _, d := range e.Devices {
		if !d.Readable {
			continue
		}
		fresh := d.reportedWithin(window)
		if fresh {
			observed++
		}
		in := fresh && (len(e.Scope.Management) == 0 || slices.Contains(e.Scope.Management, r.deviceManagement(d)))
		if in {
			inScope = append(inScope, d)
		}
		e.deriveDevice(r, d, in, "/devices/"+strconv.Itoa(n), v)
		n++
	}
	v["/scope/observed_device_count"] = observed

	byOS := map[string]int{}
	for _, d := range inScope {
		byOS[r.osFamily(d)]++
	}
	values := map[string]any{
		"fleet.devices_present":           len(inScope) > 0,
		"fleet.device_count":              len(inScope),
		"fleet.managed_device_count":      count(inScope, func(d Device) bool { return r.deviceManagement(d) == ManagementManaged }),
		"fleet.mdm_enrolled_device_count": count(inScope, func(d Device) bool { return r.Terms.EndpointMDM[d.MDM] == MDMEnrolled }),
		"fleet.devices_by_os":             byOS,
	}
	tallies := map[string]readingTally{}
	for _, control := range endpointControls {
		if e.unavailable(control) != "" {
			continue
		}
		tally := e.tally(r, inScope, control, window)
		tallies[control] = tally
		values[endpointMetricFor(control)] = tally.percent()
	}
	values["patching.unsupported_os_count"] = tallies[ControlOSSupported].fail

	given := map[string]bool{}
	gaps := 0
	for _, m := range endpointMetrics {
		reason := e.unavailable(m.reading)
		if reason == "" && !complete {
			reason = UnavailablePartial
		}
		if t, ok := tallies[m.reading]; ok && reason == "" && t.pass+t.fail == 0 && t.stale > 0 {
			reason = UnavailableStale
		}
		if reason != "" {
			at := "/availability/" + strconv.Itoa(gaps)
			v[at+"/path"], v[at+"/reason"] = m.path, reason
			gaps++
			continue
		}
		given[m.path] = true
		if value, ok := values[m.path]; ok {
			v["/"+strings.Replace(m.path, ".", "/", 1)] = value
		}
		if t, ok := tallies[m.reading]; ok && m.path == endpointMetricFor(m.reading) {
			for field, n := range t.coverage() {
				v["/metric_coverage/"+m.path+"/"+field] = n
			}
		}
	}
	if p := e.CompliancePolicy; given["compliance.compliant_pct"] {
		v["/compliance/basis"] = "provider_reported"
		if p.BaselineID != "" {
			v["/compliance/basis"] = "baseline_evaluation"
			v["/compliance/baseline_id"] = p.BaselineID
		}
		if p.BaselineVersion != "" {
			v["/compliance/baseline_version"] = p.BaselineVersion
		}
	}
	if b := e.OSBaseline; given["patching.os_baseline_compliant_pct"] {
		v["/patching/baseline_id"] = b.ID
		if b.Version != "" {
			v["/patching/baseline_version"] = b.Version
		}
	}
	return nil
}

// endpointMetricFor is the percentage a control's readings give.
func endpointMetricFor(control string) string {
	for _, m := range endpointMetrics {
		if m.reading == control && strings.HasSuffix(m.path, "_pct") {
			return m.path
		}
	}
	return ""
}

// deriveDevice gives a device's entry in the devices list, at at. Its
// controls give the state of each reading the collector can have, as the
// device reports it whatever its age.
func (e *Endpoint) deriveDevice(r *Roster, d Device, in bool, at string, v map[string]any) {
	v[at+"/device_id"] = d.Key
	v[at+"/os_family"] = r.osFamily(d)
	v[at+"/management_state"] = r.deviceManagement(d)
	v[at+"/in_scope"] = in
	for field, value := range map[string]string{"hostname": d.Hostname, "os_name": d.OSName, "os_version": d.OSVersion, "created_at": d.CreatedAt} {
		if value != "" {
			v[at+"/"+field] = value
		}
	}
	if d.User != nil {
		v[at+"/assigned_user/user_id"] = d.User.ID
		if d.User.Login != "" {
			v[at+"/assigned_user/login"] = d.User.Login
		}
	}
	for _, control := range endpointControls {
		if e.unavailable(control) == "" {
			v[at+"/controls/"+control+"/state"] = e.state(r, d, control)
		}
	}

	admins := 0
	for _, a := range d.LocalAccounts {
		if !slices.ContainsFunc(a.Groups, func(g string) bool { return r.Terms.EndpointLocalGroups[g] == RoleAdmin }) {
			continue
		}
		la := at + "/local_admin_accounts/" + strconv.Itoa(admins)
		v[la+"/account_id"] = a.Key
		if a.Username != "" {
			v[la+"/username"] = a.Username
		}
		admins++
	}

	for i, f := range d.Findings {
		fa := at + "/findings/" + strconv.Itoa(i)
		v[fa+"/finding_id"] = f.Key
		v[fa+"/control"] = r.Terms.EndpointFindingTypes[f.Type]
		v[fa+"/status"] = r.Terms.EndpointFindingStatuses[f.Status]
		for field, value := range map[string]string{"first_seen_at": f.FirstSeenAt, "last_seen_at": f.LastSeenAt, "resolved_at": f.ResolvedAt, "reason_code": f.ReasonCode} {
			if value != "" {
				v[fa+"/"+field] = value
			}
		}
	}

	listed := 0
	for _, m := range d.Modules {
		kind := r.Terms.EndpointModules[m.Key]
		if kind == ModuleOther {
			continue
		}
		readings, fed := moduleReadings[kind]
		installedRead := !fed || e.unavailable(readings[0]) == ""
		healthyRead := !fed || e.unavailable(readings[1]) == ""
		if !installedRead && !healthyRead {
			continue
		}
		ma := at + "/protection_modules/" + strconv.Itoa(listed)
		listed++
		v[ma+"/kind"] = kind
		if installedRead {
			v[ma+"/installed"] = m.Installed
			if m.Enabled != nil {
				v[ma+"/enabled"] = *m.Enabled
			}
		}
		if h := m.healthy(kind); healthyRead && h != nil {
			v[ma+"/healthy"] = *h
		}
	}
}

// unavailable gives the reason the collector can't have a reading, or ""
// when it can.
func (e *Endpoint) unavailable(reading string) string {
	switch {
	case reading == "":
		return ""
	case slices.Contains(e.Unsupported, reading):
		return UnavailableUnsupported
	case slices.Contains(e.NotRead, reading):
		return UnavailableNotRead
	case slices.Contains(e.PermissionDenied, reading):
		return UnavailablePermissionDenied
	case reading == ControlCompliance && e.CompliancePolicy == nil,
		reading == ControlScreenLock && e.ScreenLockPolicy == nil,
		reading == ControlOSBaseline && e.OSBaseline == nil:
		return UnavailableNotConfigured
	}
	return ""
}

// state is a device's reading of a control: pass, fail, unknown when the
// vendor reports nothing that settles it, or not applicable.
//
// Disk encryption passes when every volume is encrypted. A screen lock meets
// policy when it is on and locks within the policy's idle time. The host
// firewall is on when a firewall module is installed and enabled. An OS is
// supported, or meets the baseline, when its version is at least the one
// os_support or the baseline gives its family; a family os_support leaves out
// is unknown and one the baseline leaves out is not applicable. Compliance is
// the vendor's verdict. Antimalware and EDR are installed when a module of
// that kind is, and healthy when it is installed and running and, for
// antimalware, its signatures are current or, for EDR, it is reporting.
func (e *Endpoint) state(r *Roster, d Device, control string) string {
	family := r.osFamily(d)
	if slices.Contains(e.NotApplicable[control], family) {
		return ReadingNotApplicable
	}
	switch control {
	case ControlDiskEncryption:
		if len(d.Volumes) == 0 {
			return ReadingUnknown
		}
		states := slices.Collect(maps.Values(d.Volumes))
		switch {
		case slices.ContainsFunc(states, func(s string) bool { return r.Terms.EndpointEncryption[s] == VolumeNotEncrypted }):
			return ReadingFail
		case slices.ContainsFunc(states, func(s string) bool { return r.Terms.EndpointEncryption[s] != VolumeEncrypted }):
			return ReadingUnknown
		}
		return ReadingPass
	case ControlScreenLock:
		s := d.ScreenLock
		switch {
		case s == nil:
			return ReadingUnknown
		case !s.Enabled:
			return ReadingFail
		case s.IdleSeconds == nil:
			return ReadingUnknown
		}
		return endpointVerdict(endpointPtr(*s.IdleSeconds <= e.ScreenLockPolicy.MaxIdleSeconds))
	case ControlFirewall:
		m, ok := r.deviceModule(d, ModuleFirewall)
		if !ok {
			return ReadingUnknown
		}
		return endpointVerdict(endpointAll(&m.Installed, m.Enabled))
	case ControlOSSupported:
		lowest, ok := e.OSSupport[family]
		if !ok {
			return ReadingUnknown
		}
		return endpointVersionVerdict(d.OSVersion, lowest)
	case ControlOSBaseline:
		lowest, ok := e.OSBaseline.MinVersions[family]
		if !ok {
			return ReadingNotApplicable
		}
		return endpointVersionVerdict(d.OSVersion, lowest)
	case ControlCompliance:
		if d.Compliance == "" {
			return ReadingUnknown
		}
		return r.Terms.EndpointVerdicts[d.Compliance]
	}
	kind, healthy := ModuleAntimalware, false
	switch control {
	case ControlAntimalwareHealthy:
		healthy = true
	case ControlEDRInstalled:
		kind = ModuleEDR
	case ControlEDRHealthy:
		kind, healthy = ModuleEDR, true
	}
	m, ok := r.deviceModule(d, kind)
	switch {
	case !ok:
		return ReadingUnknown
	case healthy:
		return endpointVerdict(m.healthy(kind))
	}
	return endpointVerdict(&m.Installed)
}

// healthy reports whether a module is running and working normally:
// installed and running and, for antimalware, current or, for EDR,
// reporting. It is nil when the facts the vendor reports don't settle it.
func (m DeviceModule) healthy(kind string) *bool {
	running := m.Running
	if running == nil {
		running = m.Enabled
	}
	facts := []*bool{&m.Installed, running}
	switch kind {
	case ModuleAntimalware:
		facts = append(facts, m.Current)
	case ModuleEDR:
		facts = append(facts, m.Reporting)
	}
	return endpointAll(facts...)
}

// endpointAll is false when any fact is false, true when every fact is true, and
// nil otherwise.
func endpointAll(facts ...*bool) *bool {
	unknown := false
	for _, f := range facts {
		if f == nil {
			unknown = true
		} else if !*f {
			return endpointPtr(false)
		}
	}
	if unknown {
		return nil
	}
	return endpointPtr(true)
}

func endpointVerdict(b *bool) string {
	switch {
	case b == nil:
		return ReadingUnknown
	case *b:
		return ReadingPass
	}
	return ReadingFail
}

func endpointVersionVerdict(version, lowest string) string {
	got, ok := parseOSVersion(version)
	if !ok {
		return ReadingUnknown
	}
	want, _ := parseOSVersion(lowest)
	return endpointVerdict(endpointPtr(slices.Compare(paddedVersion(got, len(want)), paddedVersion(want, len(got))) >= 0))
}

// parseOSVersion reads a version of numbers separated by dots.
func parseOSVersion(s string) ([]int, bool) {
	if s == "" {
		return nil, false
	}
	var out []int
	for _, part := range strings.Split(s, ".") {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

// paddedVersion adds zeros to a version up to n numbers, so 15 compares as 15.0.0
// with 15.0.0.
func paddedVersion(version []int, n int) []int {
	out := slices.Clone(version)
	for len(out) < n {
		out = append(out, 0)
	}
	return out
}

func endpointPtr[T any](v T) *T { return &v }

func (r *Roster) deviceModule(d Device, kind string) (DeviceModule, bool) {
	i := slices.IndexFunc(d.Modules, func(m DeviceModule) bool { return r.Terms.EndpointModules[m.Key] == kind })
	if i < 0 {
		return DeviceModule{}, false
	}
	return d.Modules[i], true
}

func (r *Roster) osFamily(d Device) string {
	if d.OS == "" {
		return "unknown"
	}
	return r.Terms.EndpointOS[d.OS]
}

func (r *Roster) deviceManagement(d Device) string {
	if d.Management == "" {
		return ManagementUnknown
	}
	return r.Terms.EndpointManagement[d.Management]
}

// reportedWithin reports whether the device reported within window seconds
// of the run.
func (d Device) reportedWithin(window int) bool {
	return d.LastSeenSecondsAgo != nil && *d.LastSeenSecondsAgo <= window
}

// readWithin reports whether the device's reading of control was taken
// within window seconds of the run.
func (d Device) readWithin(control string, window int) bool {
	if age, ok := d.ObservedSecondsAgo[control]; ok {
		return age <= window
	}
	return d.reportedWithin(window)
}

// readingTally counts devices by the outcome of their reading of a control.
// A reading older than the window is unknown, and stale counts those.
type readingTally struct {
	pass, fail, unknown, notApplicable, stale int
}

func (e *Endpoint) tally(r *Roster, devices []Device, control string, window int) readingTally {
	var t readingTally
	for _, d := range devices {
		s := e.state(r, d, control)
		if (s == ReadingPass || s == ReadingFail) && !d.readWithin(control, window) {
			s = ReadingUnknown
			t.stale++
		}
		switch s {
		case ReadingPass:
			t.pass++
		case ReadingFail:
			t.fail++
		case ReadingNotApplicable:
			t.notApplicable++
		default:
			t.unknown++
		}
	}
	return t
}

// percent is the share of devices whose reading passed out of those whose
// reading passed or failed, rounded down as every endpoint-posture
// percentage is, or nil when none did either.
func (t readingTally) percent() any {
	if p := componentsdk.Percent(t.pass, t.pass+t.fail, componentsdk.RoundDown); p != nil {
		return *p
	}
	return nil
}

func (t readingTally) coverage() map[string]int {
	return map[string]int{
		"passing_device_count":        t.pass,
		"failing_device_count":        t.fail,
		"unknown_device_count":        t.unknown,
		"not_applicable_device_count": t.notApplicable,
	}
}
