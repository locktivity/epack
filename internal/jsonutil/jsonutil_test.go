package jsonutil

import (
	"testing"

	"github.com/locktivity/epack/errors"
)

func TestValidateNoDuplicateKeys(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "no duplicate keys",
			input:   `{"a": 1, "b": 2}`,
			wantErr: false,
		},
		{
			name:    "duplicate keys",
			input:   `{"a": 1, "a": 2}`,
			wantErr: true,
		},
		{
			name:    "nested duplicate keys",
			input:   `{"a": {"b": 1, "b": 2}}`,
			wantErr: true,
		},
		{
			name:    "array with duplicate keys",
			input:   `[{"a": 1}, {"a": 2}]`,
			wantErr: false, // Arrays can have duplicate keys in their objects
		},
		{
			name:    "complex nested structure with duplicates",
			input:   `{"a": {"b": 1, "c": {"d": 1, "d": 2}}}, "e": 1}`,
			wantErr: true,
		},
		{
			name:    "empty object",
			input:   `{}`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateNoDuplicateKeys([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateNoDuplicateKeys() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDecodeStrict(t *testing.T) {
	type Payload struct {
		A int `json:"a"`
	}

	tests := []struct {
		name    string
		input   string
		want    Payload
		wantErr error
	}{
		{
			name:  "valid payload",
			input: `{"a": 1}`,
			want:  Payload{A: 1},
		},
		{
			name:    "duplicate keys",
			input:   `{"a": 1, "a": 2}`,
			wantErr: errors.E(errors.DuplicateKeys, "duplicate key \"a\" at $.a", nil),
		},
		{
			name:    "invalid JSON",
			input:   `{"a": 1,`,
			wantErr: errors.E(errors.InvalidJSON, "invalid JSON: unexpected EOF", nil),
		},
		{
			name:    "extra fields",
			input:   `{"a": 1, "b": 2}`,
			wantErr: errors.E(errors.InvalidJSON, "invalid JSON: json: unknown field \"b\"", nil),
		},
		{
			name:    "nested duplicate keys",
			input:   `{"a": {"b": 1, "b": 2}}`,
			wantErr: errors.E(errors.DuplicateKeys, "duplicate key \"b\" at $.a.b", nil),
		},
		{
			name:    "trailing data",
			input:   `{"a": 1} extra`,
			wantErr: errors.E(errors.InvalidJSON, "invalid JSON: invalid character 'e' looking for beginning of value", nil),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeStrict[Payload]([]byte(tt.input))
			if (err != nil && tt.wantErr == nil) || (err == nil && tt.wantErr != nil) {
				t.Errorf("DecodeStrict() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.wantErr != nil {
				if err.Error() != tt.wantErr.Error() {
					t.Errorf("DecodeStrict() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}
			if got != tt.want {
				t.Errorf("DecodeStrict() = %v, want %v", got, tt.want)
			}
		})
	}
}
