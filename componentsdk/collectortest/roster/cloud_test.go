package roster

import (
	"strings"
	"testing"
)

// cloudResources adds to awsOrg's prod account storage, databases, audit
// logs and regions that cover each judgment, and backups to one dev
// storage resource.
func cloudResources(t *testing.T) *Roster {
	t.Helper()
	r := parseAWSOrg(t)
	days := func(n int) *int { return &n }
	r.Storage = []Storage{
		{Key: "open", CloudAccount: "prod", KeySource: "sse", NetworkAccess: "Enabled"},
		{Key: "listed_any", CloudAccount: "prod", KeySource: "sse", NetworkAccess: "Limited", AllowedSources: []string{"0.0.0.0/0"}},
		{Key: "listed", CloudAccount: "prod", KeySource: "kms", NetworkAccess: "Limited", AllowedSources: []string{"10.0.0.0/8"}, BackupRetentionDays: days(30)},
		{Key: "private", CloudAccount: "prod", KeySource: "plain", NetworkAccess: "Disabled"},
		{Key: "scratch", CloudAccount: "dev", KeySource: "sse", NetworkAccess: "Disabled"},
	}
	r.Cloud.Databases = []Database{
		{Key: "multi", CloudAccount: "prod", KeySource: "kms", NetworkAccess: "Disabled", Zones: 3, BackupRetentionDays: days(7)},
		{Key: "public", CloudAccount: "prod", KeySource: "plain", NetworkAccess: "Enabled", Zones: 1},
		{Key: "listed", CloudAccount: "prod", KeySource: "sse", NetworkAccess: "Limited", AllowedSources: []string{"10.0.0.0/8"}, Zones: 1, BackupRetentionDays: days(35)},
	}
	prod := &r.Cloud.Accounts[2]
	if prod.Key != "prod" {
		t.Fatalf("account 2 is %s", prod.Key)
	}
	prod.Regions = []string{"us-east-1", "eu-west-1"}
	prod.AuditLogs = []AuditLog{{Key: "east", Enabled: true, Regions: []string{"us-east-1"}}, {Key: "west", Enabled: true, Regions: []string{"eu-west-1"}}}
	prod.ThreatDetection = []string{"us-east-1"}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	return r
}

// The collection covers every account in the cloud block, and collects
// those the collector can read.
func TestCloudCoverageOfAccounts(t *testing.T) {
	r := parseAWSOrg(t)
	checkPointers(t, deriveSchema(t, r, CloudPosture), map[string]any{
		"/accounts_expected":         3,
		"/all_accounts_collected":    false,
		"/accounts/0/account_id":     "222",
		"/accounts/1/account_id":     "111",
		"/accounts/1/iam/user_count": 2,
	})
	r.Cloud.Accounts[0].CollectorAccess = true
	v := deriveSchema(t, r, CloudPosture)
	checkPointers(t, v, map[string]any{"/all_accounts_collected": true, "/accounts/0/account_id": "333"})
	checkPointers(t, deriveSchema(t, r, AccessPosture), map[string]any{"/root/root_account_count": 3, "/scopes/0/id": "333"})
}

// Storage and databases refuse the internet when public network access is
// off, or only listed networks may connect and none holds every address.
func TestCloudStorageAndDatabases(t *testing.T) {
	checkPointers(t, deriveSchema(t, cloudResources(t), CloudPosture), map[string]any{
		"/accounts/1/storage/storage_resource_count":                    4,
		"/accounts/1/storage/encrypted_storage_resource_count":          3,
		"/accounts/1/storage/network_restricted_storage_resource_count": 2,
		"/accounts/1/storage/network_restricted_pct":                    50,
		"/accounts/0/storage/network_restricted_storage_resource_count": 1,
		"/accounts/1/database/database_count":                           3,
		"/accounts/1/database/encrypted_database_count":                 2,
		"/accounts/1/database/public_access_blocked_database_count":     2,
		"/accounts/1/database/multi_az_database_count":                  1,
		"/accounts/1/database/multi_az_pct":                             33,
		"/accounts/0/database/database_count":                           0,
		"/accounts/0/database/databases_present":                        false,
		"/accounts/0/database/encryption_pct":                           nil,
	})
}

// Backup retention is the shortest across databases and storage with
// backups, and null when none has them.
func TestCloudBackupRetention(t *testing.T) {
	checkPointers(t, deriveSchema(t, cloudResources(t), CloudPosture), map[string]any{
		"/accounts/1/backup/retention_days_min": 7,
		"/accounts/0/backup/retention_days_min": nil,
	})
}

// The audit log covers every region when the enabled logs between them do,
// a disabled log covers none, and the deprecated names hold the same
// values. Threat detection must be on in every region the account uses.
func TestCloudLoggingAndThreatDetection(t *testing.T) {
	r := cloudResources(t)
	checkPointers(t, deriveSchema(t, r, CloudPosture), map[string]any{
		"/accounts/1/logging/audit_log_enabled":      true,
		"/accounts/1/logging/audit_log_all_regions":  true,
		"/accounts/1/logging/cloudtrail_enabled":     true,
		"/accounts/1/logging/cloudtrail_multiregion": true,
		"/accounts/1/threat_detection/enabled":       false,
		"/accounts/0/logging/audit_log_enabled":      false,
		"/accounts/0/logging/audit_log_all_regions":  false,
		"/accounts/0/threat_detection/enabled":       false,
	})
	prod := &r.Cloud.Accounts[2]
	prod.AuditLogs[1].Enabled = false
	prod.ThreatDetection = []string{"*"}
	checkPointers(t, deriveSchema(t, r, CloudPosture), map[string]any{
		"/accounts/1/logging/audit_log_enabled":      true,
		"/accounts/1/logging/audit_log_all_regions":  false,
		"/accounts/1/logging/cloudtrail_multiregion": false,
		"/accounts/1/threat_detection/enabled":       true,
	})
}

// The iam block gives the account's access-posture values as its
// descriptions say. A root account is protected from password-only use by
// MFA, or by having no password and no active credential. Users with access
// keys are the owners of active credentials, and an owner is rotated in
// time when none of its credentials is overdue. SAML providers a workforce
// sign-in service made don't count.
func TestCloudIAM(t *testing.T) {
	r := parseAWSOrg(t)
	v := deriveSchema(t, r, CloudPosture)
	checkPointers(t, v, map[string]any{
		"/accounts/1/iam/user_count":                        2,
		"/accounts/1/iam/mfa_coverage_pct":                  50,
		"/accounts/1/iam/root_mfa_enabled":                  true,
		"/accounts/1/iam/root_access_protected":             true,
		"/accounts/1/iam/access_key_user_count":             3,
		"/accounts/1/iam/access_key_rotation_compliant_pct": 33,
		"/accounts/1/iam/saml_provider_count":               0,
		"/accounts/0/iam/user_count":                        0,
		"/accounts/0/iam/mfa_coverage_pct":                  nil,
		"/accounts/0/iam/root_mfa_enabled":                  false,
		"/accounts/0/iam/root_access_protected":             false,
		"/accounts/0/iam/access_key_user_count":             1,
		"/accounts/0/iam/saml_provider_count":               1,
	})
	checkUnset(t, v, "/accounts/0/iam/access_key_rotation_compliant_pct")

	for i := range r.Accounts {
		switch r.Accounts[i].Key {
		case "dev_root":
			r.Accounts[i].Logins = nil
		case "prod_root":
			r.Accounts[i].Kind = "member"
		}
	}
	v = deriveSchema(t, r, CloudPosture)
	checkPointers(t, v, map[string]any{
		"/accounts/0/iam/root_access_protected": true,
		"/accounts/1/iam/root_mfa_enabled":      nil,
		"/accounts/1/iam/root_access_protected": nil,
	})
}

// The deprecated vuln_scanning block reads the scanning block's scope with
// the account's ID: enabled when a scanner is enabled there, and unpatched
// resources are scanned ones with an open finding. Without a scanning
// block, it is left out.
func TestCloudVulnScanningReadsTheScanningBlock(t *testing.T) {
	r := parseAWSOrg(t)
	checkUnset(t, deriveSchema(t, r, CloudPosture), "/accounts/0/vuln_scanning/enabled", "/accounts/1/vuln_scanning/unpatched_pct")

	r.Terms.ScanningTerms = ScanningTerms{
		VulnScanners:      map[string]ScannerTerms{"Inspector": {Name: "inspector", Categories: map[string]string{"EC2": VulnHosts}}},
		VulnScopeKinds:    map[string]string{"ACCOUNT": VulnAccount},
		VulnScannerStates: map[string]string{"ENABLED": VulnOn},
		VulnScanStatuses:  map[string]string{"ACTIVE": VulnScanned, "INACTIVE": VulnNotScanned},
		VulnSeverities:    map[string]string{"HIGH": VulnHigh},
		VulnFindingStates: map[string]string{"ACTIVE": VulnOpen, "CLOSED": VulnClosed},
	}
	open := 3
	r.Scanning = &Scanning{Scopes: []ScanScope{{
		ID: "111", Kind: "ACCOUNT",
		Switches: []ScannerSwitch{{Scanner: "Inspector", States: map[string]string{"EC2": "ENABLED"}}},
		Resources: []ScanResource{
			{Key: "i-1", Type: "EC2", Scans: map[string]string{"Inspector": "ACTIVE"},
				Findings: []VulnFinding{{Key: "f", Scanner: "Inspector", Severity: "HIGH", State: "ACTIVE", OpenDays: &open}}},
			{Key: "i-2", Type: "EC2", Scans: map[string]string{"Inspector": "ACTIVE"},
				Findings: []VulnFinding{{Key: "g", Scanner: "Inspector", Severity: "HIGH", State: "CLOSED", OpenDays: &open}}},
			{Key: "i-3", Type: "EC2", Scans: map[string]string{"Inspector": "INACTIVE"},
				Findings: []VulnFinding{{Key: "h", Scanner: "Inspector", Severity: "HIGH", State: "ACTIVE", OpenDays: &open}}},
		},
	}}}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	checkPointers(t, deriveSchema(t, r, CloudPosture), map[string]any{
		"/accounts/1/vuln_scanning/enabled":       true,
		"/accounts/1/vuln_scanning/unpatched_pct": 50,
		"/accounts/0/vuln_scanning/enabled":       false,
		"/accounts/0/vuln_scanning/unpatched_pct": nil,
	})
}

// The workforce sign-in service is in use when an account trusts a
// provider it made, its users are the directory's people, and its MFA
// source is its identity source.
func TestCloudWorkforceSignIn(t *testing.T) {
	r := parseAWSOrg(t)
	checkUnset(t, deriveSchema(t, r, CloudPosture), "/workforce_sign_in/in_use")
	r.Cloud.Workforce = &WorkforceSignIn{IdentitySource: "External"}
	checkPointers(t, deriveSchema(t, r, CloudPosture), map[string]any{
		"/workforce_sign_in/in_use":     true,
		"/workforce_sign_in/user_count": 3,
		"/workforce_sign_in/mfa_source": SourceExternalIdP,
	})
	for i := range r.Cloud.Accounts {
		r.Cloud.Accounts[i].IdentityProviders = nil
	}
	checkPointers(t, deriveSchema(t, r, CloudPosture), map[string]any{"/workforce_sign_in/in_use": false})
}

func TestParseRefusesBadCloudFacts(t *testing.T) {
	cases := map[string]struct{ from, to, want string }{
		"network":  {`"cloud": {`, `"storage": {"bucket": {"cloud_account": "prod", "key_source": "sse", "network_access": "Private"}}, "cloud": {`, `network_access "Private" has no entry in terms.cloud_network_access`},
		"missing":  {`"cloud": {`, `"storage": {"bucket": {"cloud_account": "prod", "key_source": "sse"}}, "cloud": {`, `storage bucket has no network_access`},
		"database": {`"credentials": {`, `"databases": {"db": {"cloud_account": "nowhere", "key_source": "sse", "network_access": "Disabled"}}, "credentials": {`, `database db cloud account nowhere is not in the roster`},
		"zones":    {`"credentials": {`, `"databases": {"db": {"cloud_account": "prod", "key_source": "sse", "network_access": "Disabled", "zones": 0}}, "credentials": {`, `database db runs in 0 zones`},
		"source":   {`"system_type": "cloud",`, `"system_type": "cloud", "workforce_sign_in": {"identity_source": "AD"},`, `identity_source "AD" has no entry in terms.workforce_identity_sources`},
		"system":   {`"system_type": "cloud"`, `"system_type": "mainframe"`, `system_type "mainframe" is none of`},
		"id":       {`"id": "333", `, ``, `account audit has no id`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			changed := strings.Replace(awsOrg, tc.from, tc.to, 1)
			if changed == awsOrg {
				t.Fatalf("%q is not in the roster", tc.from)
			}
			if _, err := Parse([]byte(changed)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Parse() error = %v, want one containing %q", err, tc.want)
			}
		})
	}
}
