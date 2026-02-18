package schema

import (
	"encoding/json"
	"strings"
	"testing"
)

// FuzzParseCatalog tests catalog JSON parsing with fuzzed inputs.
// Catalog parsing is tolerant (ignores unknown fields for forward compatibility).
func FuzzParseCatalog(f *testing.F) {
	// Valid minimal catalog
	f.Add([]byte(`{"schema_version":1,"generated_at":"2024-01-15T10:30:00Z","source":{"registry":"github"},"tools":[]}`))

	// Catalog with tools
	f.Add([]byte(`{
		"schema_version": 1,
		"generated_at": "2024-01-15T10:30:00Z",
		"source": {"registry": "github", "url": "https://example.com"},
		"tools": [
			{"name": "tool1", "publisher": "org", "repo_url": "https://github.com/org/tool1", "description": "A tool"}
		]
	}`))

	// Unknown fields (should be ignored)
	f.Add([]byte(`{"schema_version":1,"source":{},"tools":[],"unknown_field":"value","another":123}`))

	// Missing optional fields
	f.Add([]byte(`{"schema_version":1,"source":{},"tools":[{"name":"x"}]}`))

	// Empty
	f.Add([]byte(`{}`))
	f.Add([]byte(`[]`)) // wrong type
	f.Add([]byte(``))

	// Invalid JSON
	f.Add([]byte(`{invalid`))
	f.Add([]byte(`{"tools": [`)) // truncated

	// Deeply nested (potential stack overflow)
	deep := `{"tools":[{"name":"x","config":`
	for i := 0; i < 100; i++ {
		deep += `{"nested":`
	}
	deep += `"value"`
	for i := 0; i < 100; i++ {
		deep += `}`
	}
	deep += `}]}`
	f.Add([]byte(deep))

	// Large number of tools
	var manyTools strings.Builder
	manyTools.WriteString(`{"schema_version":1,"source":{},"tools":[`)
	for i := 0; i < 100; i++ {
		if i > 0 {
			manyTools.WriteString(",")
		}
		manyTools.WriteString(`{"name":"tool` + string(rune('a'+i%26)) + `"}`)
	}
	manyTools.WriteString(`]}`)
	f.Add([]byte(manyTools.String()))

	// Invalid URLs in tools
	f.Add([]byte(`{"schema_version":1,"source":{},"tools":[{"name":"x","repo_url":"not-a-url"}]}`))
	f.Add([]byte(`{"schema_version":1,"source":{},"tools":[{"name":"x","repo_url":"http://insecure.com"}]}`))
	f.Add([]byte(`{"schema_version":1,"source":{},"tools":[{"name":"x","repo_url":"https://github.com/org/repo/"}]}`)) // trailing slash

	f.Fuzz(func(t *testing.T, data []byte) {
		cat, err := ParseCatalog(data)

		if err == nil && cat != nil {
			// Run validation
			warnings := cat.Validate()

			// Property: After Validate(), repo_url is either valid https or blank
			for _, tool := range cat.Tools {
				if tool.RepoURL != "" {
					if !strings.HasPrefix(tool.RepoURL, "https://") {
						t.Errorf("non-https repo_url after validate: %q", tool.RepoURL)
					}
					if strings.HasSuffix(tool.RepoURL, "/") {
						t.Errorf("trailing slash in repo_url after validate: %q", tool.RepoURL)
					}
				}
				if tool.Homepage != "" {
					if !strings.HasPrefix(tool.Homepage, "https://") && !strings.HasPrefix(tool.Homepage, "http://") {
						t.Errorf("invalid homepage protocol after validate: %q", tool.Homepage)
					}
				}
			}

			// Just log warnings for visibility during fuzzing
			if len(warnings) > 0 {
				t.Logf("validation warnings: %v", warnings)
			}
		}
	})
}

// FuzzParseMeta tests meta file parsing with fuzzed inputs.
// Meta parsing is strict (rejects unknown fields, trailing data).
func FuzzParseMeta(f *testing.F) {
	// Valid minimal meta
	f.Add([]byte(`{"meta_version":1,"last_status":"ok"}`))

	// Valid full meta
	f.Add([]byte(`{
		"meta_version": 1,
		"last_status": "ok",
		"etag": "\"abc123\"",
		"last_modified": "Mon, 15 Jan 2024 10:30:00 GMT",
		"fetched_at": "2024-01-15T10:30:00Z",
		"source_url": "https://registry.example.com/catalog.json",
		"last_attempt_at": "2024-01-15T10:30:00Z"
	}`))

	// Other status values
	f.Add([]byte(`{"meta_version":1,"last_status":"not_modified"}`))
	f.Add([]byte(`{"meta_version":1,"last_status":"error","last_error":"connection refused"}`))

	// Unknown fields (should be REJECTED for meta)
	f.Add([]byte(`{"meta_version":1,"last_status":"ok","unknown_field":"value"}`))

	// Trailing data (should be REJECTED)
	f.Add([]byte(`{"meta_version":1,"last_status":"ok"}{"extra":"data"}`))
	f.Add([]byte(`{"meta_version":1,"last_status":"ok"}null`))
	f.Add([]byte(`{"meta_version":1,"last_status":"ok"} `))  // trailing space is ok
	f.Add([]byte(`{"meta_version":1,"last_status":"ok"}\n`)) // trailing newline is ok

	// Empty and invalid
	f.Add([]byte(`{}`))
	f.Add([]byte(``))
	f.Add([]byte(`not json`))

	f.Fuzz(func(t *testing.T, data []byte) {
		meta, err := ParseMeta(data)

		// Property: If parsing succeeds, verify no panic occurs
		// MetaVersion and LastStatus validation is lenient for forward compat
		_ = meta // success case: parsing completed without panic

		// Property: Unknown fields should cause error
		var decoded map[string]interface{}
		if json.Unmarshal(data, &decoded) == nil {
			// Check if there are unknown fields
			// Note: Go's JSON decoder uses case-insensitive field matching,
			// so we need to check with lowercase keys
			knownFields := map[string]bool{
				"meta_version": true, "last_status": true, "etag": true,
				"last_modified": true, "fetched_at": true, "source_url": true,
				"last_attempt_at": true, "last_error": true, "last_http_status": true,
			}
			hasUnknown := false
			for k := range decoded {
				if !knownFields[strings.ToLower(k)] {
					hasUnknown = true
					break
				}
			}
			if hasUnknown && err == nil {
				t.Errorf("ParseMeta accepted unknown fields in: %s", string(data))
			}
		}
	})
}

// FuzzValidateRepoURL tests repo URL validation.
func FuzzValidateRepoURL(f *testing.F) {
	f.Add("https://github.com/org/repo")
	f.Add("https://github.com/org/repo/") // trailing slash - invalid
	f.Add("http://github.com/org/repo")   // http - invalid
	f.Add("github.com/org/repo")          // no scheme - invalid
	f.Add("")
	f.Add("https://example.com") // no path - invalid
	f.Add("https://a/b")

	f.Fuzz(func(t *testing.T, url string) {
		result := ValidateRepoURL(url)

		if result != "" {
			// Property: Valid URLs must be https
			if !strings.HasPrefix(result, "https://") {
				t.Errorf("ValidateRepoURL returned non-https: %q", result)
			}
			// Property: No trailing slash
			if strings.HasSuffix(result, "/") {
				t.Errorf("ValidateRepoURL returned trailing slash: %q", result)
			}
			// Property: Must have path component
			afterScheme := strings.TrimPrefix(result, "https://")
			if !strings.Contains(afterScheme, "/") {
				t.Errorf("ValidateRepoURL returned URL without path: %q", result)
			}
		}

		// Property: Empty input -> empty output
		if url == "" && result != "" {
			t.Errorf("ValidateRepoURL returned non-empty for empty input: %q", result)
		}
	})
}

// FuzzValidateURL tests general URL validation.
func FuzzValidateURL(f *testing.F) {
	f.Add("https://example.com")
	f.Add("http://example.com")
	f.Add("ftp://example.com") // invalid - not http(s)
	f.Add("")
	f.Add("example.com")
	f.Add("//example.com")

	f.Fuzz(func(t *testing.T, url string) {
		result := ValidateURL(url)

		if result != "" {
			// Property: Valid URLs must be http or https
			if !strings.HasPrefix(result, "https://") && !strings.HasPrefix(result, "http://") {
				t.Errorf("ValidateURL returned non-http(s): %q", result)
			}
		}

		// Property: Empty input -> empty output
		if url == "" && result != "" {
			t.Errorf("ValidateURL returned non-empty for empty input: %q", result)
		}
	})
}
