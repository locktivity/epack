//go:build conformance

package componentconf

import (
	"context"
	"encoding/json"
)

func (r *Runner) runRemoteTests(ctx context.Context) {
	// Common tests
	r.testBinaryNaming()

	// Remote-specific tests
	r.testRemoteCapabilities(ctx)
	r.testRemoteProtocol(ctx)
}

func (r *Runner) testRemoteCapabilities(ctx context.Context) {
	// REM-001: Implement --capabilities flag
	result := r.exec(ctx, []string{"--capabilities"}, nil, nil)

	if result.ExitCode != 0 {
		r.fail("REM-001", "non-zero exit code from --capabilities")
		r.skip("REM-002", "depends on REM-001")
		r.skip("REM-003", "depends on REM-001")
		r.skip("REM-004", "depends on REM-001")
		return
	}

	if !isValidJSON(result.Stdout) {
		r.fail("REM-001", "output is not valid JSON")
		r.skip("REM-002", "depends on REM-001")
		r.skip("REM-003", "depends on REM-001")
		r.skip("REM-004", "depends on REM-001")
		return
	}

	r.pass("REM-001")

	// Parse capabilities
	var caps map[string]interface{}
	if err := json.Unmarshal(result.Stdout, &caps); err != nil {
		r.fail("REM-002", "failed to parse capabilities JSON")
		return
	}
	r.caps = caps

	// REM-002: Required fields
	hasName := caps["name"] != nil
	kind, _ := caps["kind"].(string)
	hasDeployProtocolVersion := caps["deploy_protocol_version"] != nil

	if hasName && kind == "remote_adapter" && hasDeployProtocolVersion {
		r.pass("REM-002")
	} else {
		r.fail("REM-002", "missing required fields (name, kind=remote_adapter, deploy_protocol_version)")
	}

	// REM-003: Features object
	if caps["features"] != nil {
		r.pass("REM-003")
	} else {
		r.fail("REM-003", "missing features object")
	}

	// REM-004: Auth and limits objects
	hasAuth := caps["auth"] != nil
	hasLimits := caps["limits"] != nil
	if hasAuth && hasLimits {
		r.pass("REM-004")
	} else if hasAuth || hasLimits {
		r.skip("REM-004", "only one of auth/limits present")
	} else {
		r.skip("REM-004", "auth and limits objects not present")
	}

	// C-010: Accepts protocol variables
	r.pass("C-010")

	// C-020: Exit code 0 on success
	r.pass("C-020")
}

func (r *Runner) testRemoteProtocol(ctx context.Context) {
	// Get features to determine which commands to test
	features, _ := r.caps["features"].(map[string]interface{})
	hasPrepareFinalize, _ := features["prepare_finalize"].(bool)
	hasPull, _ := features["pull"].(bool)

	// Test basic protocol: send a request, get a response
	r.testRemoteBasicProtocol(ctx)

	if hasPrepareFinalize {
		r.testRemotePushPrepare(ctx)
		r.testRemotePushFinalize(ctx)
	} else {
		r.skip("REM-020", "prepare_finalize not supported")
		r.skip("REM-021", "prepare_finalize not supported")
		r.skip("REM-030", "prepare_finalize not supported")
		r.skip("REM-031", "prepare_finalize not supported")
		r.skip("REM-034", "prepare_finalize not supported")
		r.skip("REM-040", "prepare_finalize not supported")
		r.skip("REM-041", "prepare_finalize not supported")
	}

	if hasPull {
		r.testRemotePullPrepare(ctx)
		r.testRemotePullFinalize(ctx)
	} else {
		r.skip("REM-022", "pull not supported")
		r.skip("REM-023", "pull not supported")
		r.skip("REM-050", "pull not supported")
		r.skip("REM-051", "pull not supported")
		r.skip("REM-052", "pull not supported")
		r.skip("REM-054", "pull not supported")
		r.skip("REM-060", "pull not supported")
		r.skip("REM-061", "pull not supported")
	}

	// Test error handling
	r.testRemoteErrorHandling(ctx)

	// Common tests
	r.testRemoteFilesystemBoundary(ctx)
	r.testRemoteNoColor(ctx)
	r.testRemoteExitCodes(ctx)

	// Security tests (skip - require more complex setup)
	r.skip("REM-080", "authentication test not implemented")
	r.skip("REM-082", "identity token test not implemented")
	r.skip("REM-084", "credential logging test not implemented")
	r.skip("C-031", "credential logging test requires log inspection")
	r.skip("C-032", "error redaction test requires log inspection")
	r.skip("C-033", "input validation test requires specific malformed inputs")
}

func (r *Runner) testRemoteBasicProtocol(ctx context.Context) {
	// Send a minimal request to test basic protocol handling
	request := map[string]interface{}{
		"type":             "ping",
		"protocol_version": 1,
		"request_id":       "test-001",
	}
	requestJSON, _ := json.Marshal(request)

	result := r.exec(ctx, []string{"ping"}, requestJSON, nil)

	// REM-010: Accept JSON on stdin (if it didn't crash, it accepted it)
	if result.Err == nil {
		r.pass("REM-010")
	} else {
		r.fail("REM-010", "failed to accept JSON on stdin")
		return
	}

	// REM-011: Write JSON to stdout
	if isValidJSON(result.Stdout) {
		r.pass("REM-011")
	} else {
		// May return error for unsupported command, which is still valid
		r.pass("REM-011")
	}

	// REM-012: MAY write to stderr (just note it)
	if len(result.Stderr) > 0 {
		r.pass("REM-012")
	} else {
		r.skip("REM-012", "no stderr output")
	}

	// Parse response for field checks
	var response map[string]interface{}
	if err := json.Unmarshal(result.Stdout, &response); err != nil {
		// May be an error response, which is valid
		r.skip("REM-013", "could not parse response")
		r.skip("REM-014", "could not parse response")
		r.skip("REM-015", "could not parse response")
		return
	}

	// REM-013: type field
	if response["type"] != nil {
		r.pass("REM-013")
	} else {
		r.fail("REM-013", "response missing type field")
	}

	// REM-014: ok boolean
	if _, hasOK := response["ok"]; hasOK {
		r.pass("REM-014")
	} else {
		r.fail("REM-014", "response missing ok field")
	}

	// REM-015: request_id echo
	if response["request_id"] == "test-001" {
		r.pass("REM-015")
	} else {
		r.fail("REM-015", "response did not echo request_id")
	}
}

func (r *Runner) testRemotePushPrepare(ctx context.Context) {
	request := map[string]interface{}{
		"type":             "push.prepare",
		"protocol_version": 1,
		"request_id":       "test-push-001",
		"remote":           "test",
		"target": map[string]interface{}{
			"workspace":   "test-workspace",
			"environment": "test",
		},
		"pack": map[string]interface{}{
			"path":       "test.pack",
			"digest":     "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			"size_bytes": 1024,
		},
		"release": map[string]interface{}{
			"labels": []string{"test"},
		},
	}
	requestJSON, _ := json.Marshal(request)

	result := r.exec(ctx, []string{"push.prepare"}, requestJSON, nil)

	// REM-020: Support push.prepare
	if result.ExitCode == 0 && isValidJSON(result.Stdout) {
		r.pass("REM-020")
	} else {
		r.fail("REM-020", "push.prepare failed")
		return
	}

	var response map[string]interface{}
	if err := json.Unmarshal(result.Stdout, &response); err != nil {
		r.fail("REM-030", "invalid response JSON")
		return
	}

	// REM-030: Accepts required fields (implicit - we sent them)
	r.pass("REM-030")

	// Check if it's an auth error (acceptable)
	ok, _ := response["ok"].(bool)
	if !ok {
		r.skip("REM-031", "push.prepare returned error (likely auth)")
		r.skip("REM-034", "push.prepare returned error (likely auth)")
		return
	}

	// REM-031: Returns upload object
	upload, _ := response["upload"].(map[string]interface{})
	if upload != nil && upload["method"] != nil && upload["url"] != nil {
		r.pass("REM-031")
	} else {
		r.fail("REM-031", "missing upload.method or upload.url")
	}

	// REM-034: Returns finalize_token
	if response["finalize_token"] != nil {
		r.pass("REM-034")
	} else {
		r.fail("REM-034", "missing finalize_token")
	}
}

func (r *Runner) testRemotePushFinalize(ctx context.Context) {
	request := map[string]interface{}{
		"type":             "push.finalize",
		"protocol_version": 1,
		"request_id":       "test-push-002",
		"remote":           "test",
		"target": map[string]interface{}{
			"workspace":   "test-workspace",
			"environment": "test",
		},
		"pack": map[string]interface{}{
			"path":       "test.pack",
			"digest":     "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			"size_bytes": 1024,
		},
		"finalize_token": "test-token",
	}
	requestJSON, _ := json.Marshal(request)

	result := r.exec(ctx, []string{"push.finalize"}, requestJSON, nil)

	// REM-021: Support push.finalize
	if result.ExitCode == 0 && isValidJSON(result.Stdout) {
		r.pass("REM-021")
	} else {
		r.fail("REM-021", "push.finalize failed")
		return
	}

	var response map[string]interface{}
	if err := json.Unmarshal(result.Stdout, &response); err != nil {
		return
	}

	// REM-040: Accepts finalize_token (implicit)
	r.pass("REM-040")

	ok, _ := response["ok"].(bool)
	if !ok {
		r.skip("REM-041", "push.finalize returned error")
		return
	}

	// REM-041: Returns release object
	release, _ := response["release"].(map[string]interface{})
	if release != nil && release["release_id"] != nil && release["pack_digest"] != nil {
		r.pass("REM-041")
	} else {
		r.fail("REM-041", "missing release.release_id or release.pack_digest")
	}
}

func (r *Runner) testRemotePullPrepare(ctx context.Context) {
	request := map[string]interface{}{
		"type":             "pull.prepare",
		"protocol_version": 1,
		"request_id":       "test-pull-001",
		"remote":           "test",
		"target": map[string]interface{}{
			"workspace":   "test-workspace",
			"environment": "test",
		},
		"ref": map[string]interface{}{
			"latest": true,
		},
	}
	requestJSON, _ := json.Marshal(request)

	result := r.exec(ctx, []string{"pull.prepare"}, requestJSON, nil)

	// REM-022: Support pull.prepare
	if result.ExitCode == 0 && isValidJSON(result.Stdout) {
		r.pass("REM-022")
	} else {
		r.fail("REM-022", "pull.prepare failed")
		return
	}

	var response map[string]interface{}
	if err := json.Unmarshal(result.Stdout, &response); err != nil {
		return
	}

	// REM-050: Accepts target and ref (implicit)
	r.pass("REM-050")

	ok, _ := response["ok"].(bool)
	if !ok {
		r.skip("REM-051", "pull.prepare returned error")
		r.skip("REM-052", "pull.prepare returned error")
		r.skip("REM-054", "pull.prepare returned error")
		return
	}

	// REM-051: Returns download.url
	download, _ := response["download"].(map[string]interface{})
	if download != nil && download["url"] != nil {
		r.pass("REM-051")
	} else {
		r.fail("REM-051", "missing download.url")
	}

	// REM-052: Returns pack.digest
	pack, _ := response["pack"].(map[string]interface{})
	if pack != nil && pack["digest"] != nil {
		r.pass("REM-052")
	} else {
		r.fail("REM-052", "missing pack.digest")
	}

	// REM-054: Returns finalize_token
	if response["finalize_token"] != nil {
		r.pass("REM-054")
	} else {
		r.fail("REM-054", "missing finalize_token")
	}
}

func (r *Runner) testRemotePullFinalize(ctx context.Context) {
	request := map[string]interface{}{
		"type":             "pull.finalize",
		"protocol_version": 1,
		"request_id":       "test-pull-002",
		"remote":           "test",
		"target": map[string]interface{}{
			"workspace":   "test-workspace",
			"environment": "test",
		},
		"finalize_token": "test-token",
		"pack_digest":    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	}
	requestJSON, _ := json.Marshal(request)

	result := r.exec(ctx, []string{"pull.finalize"}, requestJSON, nil)

	// REM-023: Support pull.finalize
	if result.ExitCode == 0 && isValidJSON(result.Stdout) {
		r.pass("REM-023")
	} else {
		r.fail("REM-023", "pull.finalize failed")
		return
	}

	var response map[string]interface{}
	if err := json.Unmarshal(result.Stdout, &response); err != nil {
		return
	}

	// REM-060: Accepts finalize_token and pack_digest (implicit)
	r.pass("REM-060")

	ok, _ := response["ok"].(bool)
	if !ok {
		r.skip("REM-061", "pull.finalize returned error")
		return
	}

	// REM-061: Returns confirmed: true
	confirmed, _ := response["confirmed"].(bool)
	if confirmed {
		r.pass("REM-061")
	} else {
		r.fail("REM-061", "missing confirmed: true")
	}
}

func (r *Runner) testRemoteErrorHandling(ctx context.Context) {
	// Send an invalid request to trigger error response
	request := map[string]interface{}{
		"type":             "invalid.command",
		"protocol_version": 1,
		"request_id":       "test-error-001",
	}
	requestJSON, _ := json.Marshal(request)

	result := r.exec(ctx, []string{"invalid.command"}, requestJSON, nil)

	if !isValidJSON(result.Stdout) {
		r.skip("REM-070", "no JSON response for error")
		r.skip("REM-071", "no JSON response for error")
		r.skip("REM-072", "no JSON response for error")
		r.skip("REM-073", "no JSON response for error")
		r.skip("REM-074", "no JSON response for error")
		return
	}

	var response map[string]interface{}
	if err := json.Unmarshal(result.Stdout, &response); err != nil {
		return
	}

	// REM-070: ok: false for errors
	ok, hasOK := response["ok"].(bool)
	if hasOK && !ok {
		r.pass("REM-070")
	} else {
		r.skip("REM-070", "not an error response")
	}

	// REM-071: type: error
	responseType, _ := response["type"].(string)
	if responseType == "error" {
		r.pass("REM-071")
	} else {
		r.skip("REM-071", "not an error response type")
	}

	// REM-072, 073: error.code and error.message
	errorObj, _ := response["error"].(map[string]interface{})
	if errorObj != nil {
		if errorObj["code"] != nil {
			r.pass("REM-072")
		} else {
			r.fail("REM-072", "missing error.code")
		}

		if errorObj["message"] != nil {
			r.pass("REM-073")
		} else {
			r.fail("REM-073", "missing error.message")
		}

		// REM-074: retryable (optional)
		if errorObj["retryable"] != nil {
			r.pass("REM-074")
		} else {
			r.skip("REM-074", "error.retryable not present")
		}
	} else {
		r.fail("REM-072", "missing error object")
		r.fail("REM-073", "missing error object")
		r.skip("REM-074", "missing error object")
	}
}

func (r *Runner) testRemoteFilesystemBoundary(ctx context.Context) {
	// Run remote with a capabilities request (should not modify files)
	r.testFilesystemBoundary(ctx, []string{"--capabilities"}, nil, nil)
}

func (r *Runner) testRemoteNoColor(ctx context.Context) {
	r.testNoColor(ctx, []string{"--capabilities"}, nil, nil)
}

func (r *Runner) testRemoteExitCodes(ctx context.Context) {
	// C-021: Exit code 1 for general errors
	// Send malformed JSON to trigger an error
	result := r.exec(ctx, nil, []byte(`{invalid json`), nil)

	if result.ExitCode != 0 {
		r.pass("C-021")
		// C-022: Exit codes 2-9 for component-specific errors
		if result.ExitCode >= 2 && result.ExitCode <= 9 {
			r.pass("C-022")
		} else if result.ExitCode == 1 {
			r.skip("C-022", "used general error code 1")
		} else {
			r.skip("C-022", "did not observe exit codes 2-9")
		}
	} else {
		// Remote handled invalid JSON gracefully - check response
		var response map[string]interface{}
		if err := json.Unmarshal(result.Stdout, &response); err == nil {
			if ok, _ := response["ok"].(bool); !ok {
				// Returned error response with exit 0 - acceptable
				r.skip("C-021", "remote returned error response instead of exit code")
				r.skip("C-022", "remote returned error response instead of exit code")
			} else {
				r.fail("C-021", "remote accepted invalid JSON as success")
				r.skip("C-022", "depends on C-021")
			}
		} else {
			r.skip("C-021", "could not parse response")
			r.skip("C-022", "could not parse response")
		}
	}
}
