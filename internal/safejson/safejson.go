// Package safejson provides secure JSON parsing with mandatory size validation
// and duplicate key rejection by default.
//
// # Quick Start
//
// For parsing untrusted JSON (API responses, user uploads, config files):
//
//	var config Config
//	if err := safejson.Unmarshal(data, limits.ConfigFile, &config); err != nil {
//	    return err
//	}
//
// For streaming from an io.Reader:
//
//	if err := safejson.DecodeReader(resp.Body, "api", limits.JSONResponse, &result); err != nil {
//	    return err
//	}
//
// # Why Not encoding/json?
//
// This package wraps encoding/json to ensure all JSON parsing goes through
// security validation BEFORE the actual parse. This prevents attacks via:
//   - Large payload parsing (memory exhaustion DoS)
//   - Duplicate keys (malicious field overwriting - last-value-wins)
//
// JSON duplicate keys are particularly dangerous because Go's json.Unmarshal
// silently uses the last value, allowing attackers to send {"admin": false, "admin": true}
// and have the true value win. This package rejects such input by default.
//
// All packages needing to parse JSON should import this package instead of
// encoding/json directly. An import guard test enforces this boundary.
//
// # Serialization
//
// For marshaling (serialization), use encoding/json directly - there are no
// security concerns with serialization, and this package intentionally does
// not re-export Marshal functions to avoid confusion.
package safejson

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/locktivity/epack/internal/boundedio"
	"github.com/locktivity/epack/internal/jsonutil"
	"github.com/locktivity/epack/internal/limits"
)

// Unmarshal parses JSON data with size validation and duplicate key rejection.
//
// SECURITY: This function validates size limits BEFORE parsing and rejects
// JSON with duplicate keys (which json.Unmarshal silently ignores).
//
// This is the recommended function for parsing all untrusted JSON input.
// For the rare case where duplicate keys must be tolerated (e.g., legacy
// systems known to produce them), use [UnmarshalPermissive].
func Unmarshal(data []byte, limit limits.SizeLimit, v any) error {
	maxSize := limit.Bytes()
	if int64(len(data)) > maxSize {
		return fmt.Errorf("JSON data exceeds maximum size: %d > %d bytes", len(data), maxSize)
	}

	// SECURITY: Reject duplicate keys which could indicate tampering.
	if err := jsonutil.ValidateNoDuplicateKeys(data); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}

	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("parsing JSON: %w", err)
	}
	return nil
}

// UnmarshalPermissive parses JSON with size validation but WITHOUT duplicate key rejection.
//
// WARNING: Only use this for systems known to produce duplicate keys where you
// have validated the security implications. For untrusted input, use [Unmarshal].
//
// Duplicate keys allow attackers to override field values (last-value-wins).
func UnmarshalPermissive(data []byte, limit limits.SizeLimit, v any) error {
	maxSize := limit.Bytes()
	if int64(len(data)) > maxSize {
		return fmt.Errorf("JSON data exceeds maximum size: %d > %d bytes", len(data), maxSize)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("parsing JSON: %w", err)
	}
	return nil
}

// DecodeReader parses JSON from a reader with size limits and duplicate key validation.
//
// SECURITY: This function provides defense-in-depth for external API responses by:
//   - Enforcing size limits before reading
//   - Rejecting JSON with duplicate keys (which json.Unmarshal silently ignores)
//
// Use this for external API responses where duplicate keys could indicate:
//   - Malformed responses from compromised servers
//   - Injection attacks attempting to override fields
//
// For internal/trusted sources where duplicate key checking is not needed,
// use [DecodeReaderPermissive].
func DecodeReader(r io.Reader, name string, limit limits.SizeLimit, v any) error {
	data, err := boundedio.ReadReaderWithLimit(r, name, limit)
	if err != nil {
		return err
	}

	// SECURITY: Validate no duplicate keys before unmarshaling.
	if err := jsonutil.ValidateNoDuplicateKeys(data); err != nil {
		return fmt.Errorf("invalid JSON from %s: %w", name, err)
	}

	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("parsing JSON from %s: %w", name, err)
	}
	return nil
}

// DecodeReaderPermissive parses JSON from a reader with size limits but no duplicate key check.
//
// WARNING: Only use this when parsing responses from systems known to produce
// duplicate keys, or when the source is fully trusted and performance is critical.
//
// For untrusted external APIs, prefer [DecodeReader] which includes duplicate key validation.
func DecodeReaderPermissive(r io.Reader, name string, limit limits.SizeLimit, v any) error {
	data, err := boundedio.ReadReaderWithLimit(r, name, limit)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("parsing JSON from %s: %w", name, err)
	}
	return nil
}
