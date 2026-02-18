package verify

import (
	"fmt"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/limits"
)

// ValidateAttestationSize checks that attestation data is within size limits.
func ValidateAttestationSize(data []byte) error {
	if int64(len(data)) > limits.Attestation.Bytes() {
		return errors.E(errors.AttestationTooLarge,
			fmt.Sprintf("attestation size %d exceeds limit %d bytes",
				len(data), limits.Attestation.Bytes()), nil)
	}
	return nil
}

// ValidateAttestationDepth checks that JSON nesting depth is within limits.
// This prevents stack overflow during parsing of deeply nested structures.
func ValidateAttestationDepth(data []byte) error {
	maxDepth := 0
	currentDepth := 0
	inString := false
	escaped := false

	for _, b := range data {
		if escaped {
			escaped = false
			continue
		}
		if b == '\\' && inString {
			escaped = true
			continue
		}
		if b == '"' {
			inString = !inString
			continue
		}
		if inString {
			continue
		}

		switch b {
		case '{', '[':
			currentDepth++
			if currentDepth > maxDepth {
				maxDepth = currentDepth
			}
			if currentDepth > limits.MaxAttestationJSONDepth {
				return errors.E(errors.InvalidAttestation,
					fmt.Sprintf("attestation JSON depth %d exceeds limit %d",
						currentDepth, limits.MaxAttestationJSONDepth), nil)
			}
		case '}', ']':
			currentDepth--
		}
	}

	return nil
}

// ValidateAttestation performs size and depth validation before parsing.
func ValidateAttestation(data []byte) error {
	if err := ValidateAttestationSize(data); err != nil {
		return err
	}
	return ValidateAttestationDepth(data)
}
