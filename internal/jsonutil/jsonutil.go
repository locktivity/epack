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
	state := duplicateKeyState{}

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return errors.E(errors.InvalidJSON, "invalid JSON", err)
		}

		if delimiter, ok := token.(json.Delim); ok {
			if err := state.handleDelimiter(delimiter); err != nil {
				return err
			}
			continue
		}

		if state.expectsKey() {
			if err := state.handleKeyToken(token); err != nil {
				return err
			}
		} else {
			state.valueDone()
		}
	}
}

type duplicateKeyState struct {
	keyStack  []map[string]struct{}
	expectKey []bool
	pathStack []string
}

func (s *duplicateKeyState) buildPath() string {
	if len(s.pathStack) == 0 {
		return "$"
	}
	return "$." + strings.Join(s.pathStack, ".")
}

func (s *duplicateKeyState) valueDone() {
	if len(s.expectKey) > 0 {
		s.expectKey[len(s.expectKey)-1] = true
	}
}

func (s *duplicateKeyState) expectsKey() bool {
	return len(s.expectKey) > 0 && s.expectKey[len(s.expectKey)-1]
}

func (s *duplicateKeyState) handleDelimiter(delimiter json.Delim) error {
	switch delimiter {
	case '{':
		s.keyStack = append(s.keyStack, make(map[string]struct{}))
		s.expectKey = append(s.expectKey, true)
	case '}':
		if len(s.keyStack) == 0 {
			return errors.E(errors.InvalidJSON, "unexpected closing brace", nil)
		}
		s.keyStack = s.keyStack[:len(s.keyStack)-1]
		s.expectKey = s.expectKey[:len(s.expectKey)-1]
		if len(s.pathStack) > 0 {
			s.pathStack = s.pathStack[:len(s.pathStack)-1]
		}
		s.valueDone()
	case ']':
		if len(s.pathStack) > 0 {
			s.pathStack = s.pathStack[:len(s.pathStack)-1]
		}
		s.valueDone()
	}
	return nil
}

func (s *duplicateKeyState) handleKeyToken(token json.Token) error {
	key, ok := token.(string)
	if !ok {
		return errors.E(errors.InvalidJSON, fmt.Sprintf("expected string key at %s, got %T", s.buildPath(), token), nil)
	}

	seen := s.keyStack[len(s.keyStack)-1]
	if _, exists := seen[key]; exists {
		return errors.E(errors.DuplicateKeys, fmt.Sprintf("duplicate key %q at %s", key, s.buildPath()), nil)
	}
	seen[key] = struct{}{}
	s.pathStack = append(s.pathStack, key)
	s.expectKey[len(s.expectKey)-1] = false
	return nil
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
