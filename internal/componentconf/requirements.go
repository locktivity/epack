//go:build conformance

package componentconf

import "github.com/locktivity/epack/internal/componenttypes"

// Requirements is the registry of all conformance requirements.
// IDs match those in docs/component-rules.md.
var Requirements = []Requirement{
	// Common requirements (all component types)
	{ID: "C-001", Level: LevelMust, Description: "Binary name follows pattern epack-{type}-{name}", Types: []componenttypes.ComponentKind{componenttypes.KindCollector, componenttypes.KindTool, componenttypes.KindRemote, componenttypes.KindUtility}},
	{ID: "C-002", Level: LevelMust, Description: "Name segment matches ^[a-z0-9][a-z0-9._-]{0,63}$", Types: []componenttypes.ComponentKind{componenttypes.KindCollector, componenttypes.KindTool, componenttypes.KindRemote, componenttypes.KindUtility}},
	{ID: "C-003", Level: LevelMust, Description: "Name contains no path separators or traversal sequences", Types: []componenttypes.ComponentKind{componenttypes.KindCollector, componenttypes.KindTool, componenttypes.KindRemote, componenttypes.KindUtility}},
	{ID: "C-010", Level: LevelMust, Description: "Component accepts protocol variables via environment", Types: []componenttypes.ComponentKind{componenttypes.KindCollector, componenttypes.KindTool, componenttypes.KindRemote}},
	{ID: "C-013", Level: LevelShould, Description: "Component honors NO_COLOR for terminal output", Types: []componenttypes.ComponentKind{componenttypes.KindCollector, componenttypes.KindTool, componenttypes.KindRemote, componenttypes.KindUtility}},
	{ID: "C-020", Level: LevelMust, Description: "Exit code 0 indicates success", Types: []componenttypes.ComponentKind{componenttypes.KindCollector, componenttypes.KindTool, componenttypes.KindRemote, componenttypes.KindUtility}},
	{ID: "C-021", Level: LevelMust, Description: "Exit code 1 indicates general error", Types: []componenttypes.ComponentKind{componenttypes.KindCollector, componenttypes.KindTool, componenttypes.KindRemote, componenttypes.KindUtility}},
	{ID: "C-022", Level: LevelShould, Description: "Exit codes 2-9 used for component-specific errors", Types: []componenttypes.ComponentKind{componenttypes.KindCollector, componenttypes.KindTool, componenttypes.KindRemote, componenttypes.KindUtility}},
	{ID: "C-030", Level: LevelMust, Description: "Component does not write outside designated output area", Types: []componenttypes.ComponentKind{componenttypes.KindCollector, componenttypes.KindTool, componenttypes.KindRemote}},
	{ID: "C-031", Level: LevelMust, Description: "Component does not log credentials, tokens, or secrets", Types: []componenttypes.ComponentKind{componenttypes.KindCollector, componenttypes.KindTool, componenttypes.KindRemote}},
	{ID: "C-032", Level: LevelShould, Description: "Component redacts sensitive values from error messages", Types: []componenttypes.ComponentKind{componenttypes.KindCollector, componenttypes.KindTool, componenttypes.KindRemote}},
	{ID: "C-033", Level: LevelMust, Description: "Component validates all input before use", Types: []componenttypes.ComponentKind{componenttypes.KindCollector, componenttypes.KindTool, componenttypes.KindRemote}},

	// Collector requirements
	{ID: "COL-001", Level: LevelMust, Description: "Output valid JSON to stdout", Types: []componenttypes.ComponentKind{componenttypes.KindCollector}},
	{ID: "COL-002", Level: LevelShould, Description: "Output uses protocol envelope format with protocol_version and data fields", Types: []componenttypes.ComponentKind{componenttypes.KindCollector}},
	{ID: "COL-003", Level: LevelMay, Description: "Output plain JSON without envelope", Types: []componenttypes.ComponentKind{componenttypes.KindCollector}},
	{ID: "COL-005", Level: LevelMust, Description: "Output size does not exceed 64 MB", Types: []componenttypes.ComponentKind{componenttypes.KindCollector}},
	{ID: "COL-006", Level: LevelMust, Description: "JSON is UTF-8 encoded", Types: []componenttypes.ComponentKind{componenttypes.KindCollector}},
	{ID: "COL-010", Level: LevelMust, Description: "Read collector name from EPACK_COLLECTOR_NAME", Types: []componenttypes.ComponentKind{componenttypes.KindCollector}},
	{ID: "COL-011", Level: LevelMust, Description: "Read protocol version from EPACK_PROTOCOL_VERSION", Types: []componenttypes.ComponentKind{componenttypes.KindCollector}},
	{ID: "COL-012", Level: LevelShould, Description: "Read config file path from EPACK_COLLECTOR_CONFIG if present", Types: []componenttypes.ComponentKind{componenttypes.KindCollector}},
	{ID: "COL-020", Level: LevelMust, Description: "Parse config file as JSON when EPACK_COLLECTOR_CONFIG is set", Types: []componenttypes.ComponentKind{componenttypes.KindCollector}},
	{ID: "COL-021", Level: LevelMust, Description: "Not crash or hang when config file is missing", Types: []componenttypes.ComponentKind{componenttypes.KindCollector}},
	{ID: "COL-022", Level: LevelShould, Description: "Validate config schema and report clear errors", Types: []componenttypes.ComponentKind{componenttypes.KindCollector}},
	{ID: "COL-024", Level: LevelShould, Description: "Exit with config error (exit 2) if required configuration is missing", Types: []componenttypes.ComponentKind{componenttypes.KindCollector}},
	{ID: "COL-030", Level: LevelMust, Description: "Complete within timeout", Types: []componenttypes.ComponentKind{componenttypes.KindCollector}},
	{ID: "COL-031", Level: LevelMust, Description: "Handle SIGTERM gracefully", Types: []componenttypes.ComponentKind{componenttypes.KindCollector}},
	{ID: "COL-034", Level: LevelMust, Description: "Exit with code 0 only when collection succeeds", Types: []componenttypes.ComponentKind{componenttypes.KindCollector}},
	{ID: "COL-040", Level: LevelMust, Description: "Exit 0 on success", Types: []componenttypes.ComponentKind{componenttypes.KindCollector}},
	{ID: "COL-041", Level: LevelShould, Description: "Exit 1 on general error", Types: []componenttypes.ComponentKind{componenttypes.KindCollector}},
	{ID: "COL-042", Level: LevelShould, Description: "Exit 2 on configuration error", Types: []componenttypes.ComponentKind{componenttypes.KindCollector}},
	{ID: "COL-043", Level: LevelShould, Description: "Exit 3 on authentication error", Types: []componenttypes.ComponentKind{componenttypes.KindCollector}},
	{ID: "COL-044", Level: LevelShould, Description: "Exit 4 on network/API error", Types: []componenttypes.ComponentKind{componenttypes.KindCollector}},
	{ID: "COL-052", Level: LevelMust, Description: "Use HTTPS for external API calls", Types: []componenttypes.ComponentKind{componenttypes.KindCollector}},

	// Tool requirements
	{ID: "TOOL-001", Level: LevelMust, Description: "Implement --capabilities flag returning JSON metadata", Types: []componenttypes.ComponentKind{componenttypes.KindTool}},
	{ID: "TOOL-002", Level: LevelMust, Description: "Set EPACK_MODE=capabilities when invoked with --capabilities", Types: []componenttypes.ComponentKind{componenttypes.KindTool}},
	{ID: "TOOL-003", Level: LevelMust, Description: "Capabilities include name, version, protocol_version fields", Types: []componenttypes.ComponentKind{componenttypes.KindTool}},
	{ID: "TOOL-004", Level: LevelShould, Description: "Capabilities include description field", Types: []componenttypes.ComponentKind{componenttypes.KindTool}},
	{ID: "TOOL-005", Level: LevelMay, Description: "Capabilities include network, requires_tools, requires_outputs fields", Types: []componenttypes.ComponentKind{componenttypes.KindTool}},
	{ID: "TOOL-010", Level: LevelMust, Description: "Read run ID from EPACK_RUN_ID", Types: []componenttypes.ComponentKind{componenttypes.KindTool}},
	{ID: "TOOL-011", Level: LevelMust, Description: "Read run directory from EPACK_RUN_DIR", Types: []componenttypes.ComponentKind{componenttypes.KindTool}},
	{ID: "TOOL-012", Level: LevelMust, Description: "Read tool name from EPACK_TOOL_NAME", Types: []componenttypes.ComponentKind{componenttypes.KindTool}},
	{ID: "TOOL-013", Level: LevelMust, Description: "Read protocol version from EPACK_PROTOCOL_VERSION", Types: []componenttypes.ComponentKind{componenttypes.KindTool}},
	{ID: "TOOL-014", Level: LevelShould, Description: "Read pack path from EPACK_PACK_PATH when pack is provided", Types: []componenttypes.ComponentKind{componenttypes.KindTool}},
	{ID: "TOOL-015", Level: LevelShould, Description: "Read pack digest from EPACK_PACK_DIGEST when pack is provided", Types: []componenttypes.ComponentKind{componenttypes.KindTool}},
	{ID: "TOOL-020", Level: LevelMust, Description: "Write all outputs inside current working directory", Types: []componenttypes.ComponentKind{componenttypes.KindTool}},
	{ID: "TOOL-021", Level: LevelMust, Description: "Do not write outside the run directory", Types: []componenttypes.ComponentKind{componenttypes.KindTool}},
	{ID: "TOOL-022", Level: LevelMust, Description: "Do not use .. to traverse outside run directory", Types: []componenttypes.ComponentKind{componenttypes.KindTool}},
	{ID: "TOOL-023", Level: LevelMust, Description: "Do not create symlinks pointing outside run directory", Types: []componenttypes.ComponentKind{componenttypes.KindTool}},
	{ID: "TOOL-030", Level: LevelMust, Description: "Write result.json to run directory root", Types: []componenttypes.ComponentKind{componenttypes.KindTool}},
	{ID: "TOOL-031", Level: LevelMust, Description: "Include schema_version, tool.name, tool.version, run_id, status in result.json", Types: []componenttypes.ComponentKind{componenttypes.KindTool}},
	{ID: "TOOL-032", Level: LevelMust, Description: "Set status to success, failure, or partial", Types: []componenttypes.ComponentKind{componenttypes.KindTool}},
	{ID: "TOOL-033", Level: LevelShould, Description: "Include started_at, completed_at, duration_ms timestamps", Types: []componenttypes.ComponentKind{componenttypes.KindTool}},
	{ID: "TOOL-034", Level: LevelShould, Description: "Include outputs array listing produced files", Types: []componenttypes.ComponentKind{componenttypes.KindTool}},
	{ID: "TOOL-036", Level: LevelMust, Description: "Write result.json even on failure", Types: []componenttypes.ComponentKind{componenttypes.KindTool}},
	{ID: "TOOL-040", Level: LevelMust, Description: "Output paths in outputs array are relative to run directory", Types: []componenttypes.ComponentKind{componenttypes.KindTool}},
	{ID: "TOOL-041", Level: LevelMust, Description: "Output paths do not contain .. segments", Types: []componenttypes.ComponentKind{componenttypes.KindTool}},
	{ID: "TOOL-042", Level: LevelMust, Description: "Output paths are not absolute", Types: []componenttypes.ComponentKind{componenttypes.KindTool}},
	{ID: "TOOL-043", Level: LevelShould, Description: "Place output files in outputs/ subdirectory", Types: []componenttypes.ComponentKind{componenttypes.KindTool}},
	{ID: "TOOL-050", Level: LevelMust, Description: "Format timestamps as YYYY-MM-DDTHH:MM:SSZ", Types: []componenttypes.ComponentKind{componenttypes.KindTool}},
	{ID: "TOOL-051", Level: LevelMust, Description: "Do not include milliseconds or timezone offsets in timestamps", Types: []componenttypes.ComponentKind{componenttypes.KindTool}},
	{ID: "TOOL-052", Level: LevelMust, Description: "Run IDs sort chronologically when sorted lexicographically", Types: []componenttypes.ComponentKind{componenttypes.KindTool}},
	{ID: "TOOL-060", Level: LevelMust, Description: "Treat pack path as read-only", Types: []componenttypes.ComponentKind{componenttypes.KindTool}},
	{ID: "TOOL-061", Level: LevelMust, Description: "Do not modify the input pack", Types: []componenttypes.ComponentKind{componenttypes.KindTool}},
	{ID: "TOOL-070", Level: LevelShould, Description: "Support --json flag for machine-readable output", Types: []componenttypes.ComponentKind{componenttypes.KindTool}},
	{ID: "TOOL-071", Level: LevelShould, Description: "Support --quiet flag to suppress progress output", Types: []componenttypes.ComponentKind{componenttypes.KindTool}},

	// Remote adapter requirements
	{ID: "REM-001", Level: LevelMust, Description: "Implement --capabilities flag returning JSON metadata", Types: []componenttypes.ComponentKind{componenttypes.KindRemote}},
	{ID: "REM-002", Level: LevelMust, Description: "Capabilities include name, kind: remote_adapter, deploy_protocol_version", Types: []componenttypes.ComponentKind{componenttypes.KindRemote}},
	{ID: "REM-003", Level: LevelMust, Description: "Capabilities include features object", Types: []componenttypes.ComponentKind{componenttypes.KindRemote}},
	{ID: "REM-004", Level: LevelShould, Description: "Capabilities include auth and limits objects", Types: []componenttypes.ComponentKind{componenttypes.KindRemote}},
	{ID: "REM-010", Level: LevelMust, Description: "Accept JSON requests on stdin", Types: []componenttypes.ComponentKind{componenttypes.KindRemote}},
	{ID: "REM-011", Level: LevelMust, Description: "Write JSON responses to stdout", Types: []componenttypes.ComponentKind{componenttypes.KindRemote}},
	{ID: "REM-012", Level: LevelMay, Description: "Write human-readable logs to stderr", Types: []componenttypes.ComponentKind{componenttypes.KindRemote}},
	{ID: "REM-013", Level: LevelMust, Description: "Include type field in all responses", Types: []componenttypes.ComponentKind{componenttypes.KindRemote}},
	{ID: "REM-014", Level: LevelMust, Description: "Include ok boolean in all responses", Types: []componenttypes.ComponentKind{componenttypes.KindRemote}},
	{ID: "REM-015", Level: LevelMust, Description: "Echo request_id from request in response", Types: []componenttypes.ComponentKind{componenttypes.KindRemote}},
	{ID: "REM-020", Level: LevelMust, Description: "Support push.prepare if features.prepare_finalize is true", Types: []componenttypes.ComponentKind{componenttypes.KindRemote}},
	{ID: "REM-021", Level: LevelMust, Description: "Support push.finalize if features.prepare_finalize is true", Types: []componenttypes.ComponentKind{componenttypes.KindRemote}},
	{ID: "REM-022", Level: LevelShould, Description: "Support pull.prepare if features.pull is true", Types: []componenttypes.ComponentKind{componenttypes.KindRemote}},
	{ID: "REM-023", Level: LevelShould, Description: "Support pull.finalize if features.pull is true", Types: []componenttypes.ComponentKind{componenttypes.KindRemote}},
	{ID: "REM-030", Level: LevelMust, Description: "push.prepare accepts target, pack, release in request", Types: []componenttypes.ComponentKind{componenttypes.KindRemote}},
	{ID: "REM-031", Level: LevelMust, Description: "push.prepare returns upload object with method, url on success", Types: []componenttypes.ComponentKind{componenttypes.KindRemote}},
	{ID: "REM-034", Level: LevelMust, Description: "push.prepare returns finalize_token", Types: []componenttypes.ComponentKind{componenttypes.KindRemote}},
	{ID: "REM-040", Level: LevelMust, Description: "push.finalize accepts finalize_token from prepare response", Types: []componenttypes.ComponentKind{componenttypes.KindRemote}},
	{ID: "REM-041", Level: LevelMust, Description: "push.finalize returns release object with release_id, pack_digest on success", Types: []componenttypes.ComponentKind{componenttypes.KindRemote}},
	{ID: "REM-050", Level: LevelMust, Description: "pull.prepare accepts target and ref", Types: []componenttypes.ComponentKind{componenttypes.KindRemote}},
	{ID: "REM-051", Level: LevelMust, Description: "pull.prepare returns download.url on success", Types: []componenttypes.ComponentKind{componenttypes.KindRemote}},
	{ID: "REM-052", Level: LevelMust, Description: "pull.prepare returns pack.digest for integrity verification", Types: []componenttypes.ComponentKind{componenttypes.KindRemote}},
	{ID: "REM-054", Level: LevelMust, Description: "pull.prepare returns finalize_token", Types: []componenttypes.ComponentKind{componenttypes.KindRemote}},
	{ID: "REM-060", Level: LevelMust, Description: "pull.finalize accepts finalize_token and pack_digest", Types: []componenttypes.ComponentKind{componenttypes.KindRemote}},
	{ID: "REM-061", Level: LevelMust, Description: "pull.finalize returns confirmed: true on success", Types: []componenttypes.ComponentKind{componenttypes.KindRemote}},
	{ID: "REM-070", Level: LevelMust, Description: "Set ok: false for error responses", Types: []componenttypes.ComponentKind{componenttypes.KindRemote}},
	{ID: "REM-071", Level: LevelMust, Description: "Set type: error for error responses", Types: []componenttypes.ComponentKind{componenttypes.KindRemote}},
	{ID: "REM-072", Level: LevelMust, Description: "Include error.code with machine-readable error code", Types: []componenttypes.ComponentKind{componenttypes.KindRemote}},
	{ID: "REM-073", Level: LevelMust, Description: "Include error.message with human-readable description", Types: []componenttypes.ComponentKind{componenttypes.KindRemote}},
	{ID: "REM-074", Level: LevelShould, Description: "Include error.retryable boolean", Types: []componenttypes.ComponentKind{componenttypes.KindRemote}},
	{ID: "REM-080", Level: LevelMust, Description: "Handle authentication internally", Types: []componenttypes.ComponentKind{componenttypes.KindRemote}},
	{ID: "REM-082", Level: LevelMust, Description: "Accept identity token via identity field in requests", Types: []componenttypes.ComponentKind{componenttypes.KindRemote}},
	{ID: "REM-084", Level: LevelMust, Description: "Do not log or expose credentials", Types: []componenttypes.ComponentKind{componenttypes.KindRemote}},

	// Utility requirements
	{ID: "UTIL-001", Level: LevelMust, Description: "Implement --version flag returning version string", Types: []componenttypes.ComponentKind{componenttypes.KindUtility}},
	{ID: "UTIL-002", Level: LevelMust, Description: "Implement --capabilities flag returning JSON metadata", Types: []componenttypes.ComponentKind{componenttypes.KindUtility}},
	{ID: "UTIL-003", Level: LevelMust, Description: "Capabilities include name, kind: utility, version fields", Types: []componenttypes.ComponentKind{componenttypes.KindUtility}},
	{ID: "UTIL-004", Level: LevelShould, Description: "Capabilities include description field", Types: []componenttypes.ComponentKind{componenttypes.KindUtility}},
	{ID: "UTIL-010", Level: LevelShould, Description: "Implement --help flag with usage information", Types: []componenttypes.ComponentKind{componenttypes.KindUtility}},
	{ID: "UTIL-011", Level: LevelShould, Description: "Help output includes synopsis, description, and examples", Types: []componenttypes.ComponentKind{componenttypes.KindUtility}},
}

// RequirementsByType returns requirements applicable to a specific component type.
func RequirementsByType(t componenttypes.ComponentKind) []Requirement {
	var result []Requirement
	for _, r := range Requirements {
		for _, rt := range r.Types {
			if rt == t {
				result = append(result, r)
				break
			}
		}
	}
	return result
}

// RequirementByID returns a requirement by its ID.
func RequirementByID(id string) *Requirement {
	for i := range Requirements {
		if Requirements[i].ID == id {
			return &Requirements[i]
		}
	}
	return nil
}
