// Package jsonutil provides hardened JSON decoding helpers for untrusted input.
// Invariants: duplicate object keys are rejected; strict mode can reject unknown fields.
package jsonutil

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/locktivity/epack/errors"
)

// MaxSafeInt is the maximum integer exactly representable in JSON (2^53 - 1).
const MaxSafeInt int64 = (1 << 53) - 1

// ValidateNoDuplicateKeys checks for duplicate object keys in JSON.
// Uses streaming because json.Unmarshal silently keeps only the last duplicate.
func ValidateNoDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))

	var keyStack []map[string]struct{} // seen keys per nested object
	var expectKey []bool               // true = expecting key, false = expecting value
	var pathStack []string             // current JSON path segments

	buildPath := func() string {
		if len(pathStack) == 0 {
			return "$"
		}
		return "$." + strings.Join(pathStack, ".")
	}

	valueDone := func() {
		if len(expectKey) > 0 {
			expectKey[len(expectKey)-1] = true
		}
	}

	for {
		token, err := decoder.Token()

		if err == io.EOF {
			return nil
		}
		if err != nil {
			return errors.E(errors.InvalidJSON, "invalid JSON", err)
		}

		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{':
				keyStack = append(keyStack, make(map[string]struct{}))
				expectKey = append(expectKey, true)
			case '}':
				if len(keyStack) == 0 {
					return errors.E(errors.InvalidJSON, "unexpected closing brace", nil)
				}
				keyStack = keyStack[:len(keyStack)-1]
				expectKey = expectKey[:len(expectKey)-1]
				if len(pathStack) > 0 {
					pathStack = pathStack[:len(pathStack)-1]
				}
				valueDone()
			case '[':
				// Arrays don't have keys, so we don't push anything onto the keyStack.
			case ']':
				if len(pathStack) > 0 {
					pathStack = pathStack[:len(pathStack)-1]
				}
				valueDone()
			}
			continue
		}

		if len(expectKey) > 0 && expectKey[len(expectKey)-1] {
			key, ok := token.(string)
			if !ok {
				return errors.E(errors.InvalidJSON, fmt.Sprintf("expected string key at %s, got %T", buildPath(), token), nil)
			}

			seen := keyStack[len(keyStack)-1]
			if _, exists := seen[key]; exists {
				return errors.E(errors.DuplicateKeys, fmt.Sprintf("duplicate key %q at %s", key, buildPath()), nil)
			}
			seen[key] = struct{}{}
			pathStack = append(pathStack, key)
			expectKey[len(expectKey)-1] = false
			continue
		}

		valueDone()
	}
}

// DecodeNoDup decodes JSON into a Go struct while enforcing no duplicate keys.
// Unknown fields are allowed for forward compatibility.
func DecodeNoDup[T any](jsonBytes []byte) (T, error) {
	var out T

	if err := ValidateNoDuplicateKeys(jsonBytes); err != nil {
		return out, err
	}

	if err := json.Unmarshal(jsonBytes, &out); err != nil {
		return out, errors.E(errors.InvalidJSON, "invalid JSON", err)
	}

	return out, nil
}

// DecodeStrict decodes JSON into a Go struct while enforcing no duplicate keys and disallowing unknown fields.
func DecodeStrict[T any](jsonBytes []byte) (T, error) {
	var out T

	if err := ValidateNoDuplicateKeys(jsonBytes); err != nil {
		return out, err
	}

	decoder := json.NewDecoder(bytes.NewReader(jsonBytes))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()

	if err := decoder.Decode(&out); err != nil {
		return out, errors.E(errors.InvalidJSON, "invalid JSON", err)
	}

	// Check for trailing data - must reject both:
	// 1. Complete extra values like "{}{}" (extra decodes successfully)
	// 2. Incomplete trailing data like "{}{" (extra fails but More() is true)
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return out, errors.E(errors.InvalidJSON, "invalid JSON: trailing data after top-level value", nil)
	} else if decoder.More() {
		// Decoder couldn't parse trailing data but there are more tokens
		// This catches cases like "{}{" where trailing data is incomplete
		return out, errors.E(errors.InvalidJSON, "invalid JSON: incomplete trailing data", nil)
	}

	return out, nil
}
