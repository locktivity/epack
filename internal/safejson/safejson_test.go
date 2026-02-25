package safejson

import (
	"bytes"
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/limits"
)

func TestUnmarshal(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		maxSize limits.SizeLimit
		wantErr bool
	}{
		{
			name:    "valid small object",
			data:    []byte(`{"name":"test","value":42}`),
			maxSize: 100,
			wantErr: false,
		},
		{
			name:    "exceeds size limit",
			data:    []byte(`{"name":"test","value":42}`),
			maxSize: 10,
			wantErr: true,
		},
		{
			name:    "exactly at limit",
			data:    []byte(`{"a":1}`),
			maxSize: 7,
			wantErr: false,
		},
		{
			name:    "invalid JSON",
			data:    []byte(`{invalid`),
			maxSize: 100,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result map[string]any
			err := Unmarshal(tt.data, tt.maxSize, &result)
			if (err != nil) != tt.wantErr {
				t.Errorf("Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDecodeReader(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		maxSize limits.SizeLimit
		wantErr bool
	}{
		{
			name:    "valid from reader",
			data:    `{"key":"value"}`,
			maxSize: 100,
			wantErr: false,
		},
		{
			name:    "exceeds size from reader",
			data:    `{"key":"value"}`,
			maxSize: 5,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bytes.NewReader([]byte(tt.data))
			var result map[string]any
			err := DecodeReader(reader, "test", tt.maxSize, &result)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeReader() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDecodeReader_SizeError(t *testing.T) {
	// Create data larger than limit
	largeData := `{"data":"` + strings.Repeat("x", 1000) + `"}`
	reader := bytes.NewReader([]byte(largeData))

	var result map[string]any
	err := DecodeReader(reader, "large", limits.SizeLimit(100), &result)
	if err == nil {
		t.Error("expected error for oversized data")
	}
	if !strings.Contains(err.Error(), "exceeds size limit") {
		t.Errorf("expected size limit error, got: %v", err)
	}
}

func TestUnmarshal_DuplicateKeyRejection(t *testing.T) {
	// Unmarshal should reject duplicate keys by default
	data := []byte(`{"admin": false, "admin": true}`)
	var result map[string]any
	err := Unmarshal(data, limits.ConfigFile, &result)
	if err == nil {
		t.Error("expected error for duplicate keys")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("expected duplicate key error, got: %v", err)
	}
}

func TestUnmarshalPermissive_AllowsDuplicateKeys(t *testing.T) {
	// UnmarshalPermissive should allow duplicate keys (uses last value)
	data := []byte(`{"admin": false, "admin": true}`)
	var result map[string]bool
	err := UnmarshalPermissive(data, limits.ConfigFile, &result)
	if err != nil {
		t.Errorf("UnmarshalPermissive() error = %v", err)
	}
	// Go uses last value for duplicate keys
	if !result["admin"] {
		t.Error("expected admin=true (last value wins)")
	}
}

func TestDecodeReader_DuplicateKeyRejection(t *testing.T) {
	// DecodeReader should reject duplicate keys
	data := `{"admin": false, "admin": true}`
	reader := bytes.NewReader([]byte(data))
	var result map[string]any
	err := DecodeReader(reader, "test", limits.ConfigFile, &result)
	if err == nil {
		t.Error("expected error for duplicate keys")
	}
}

func TestDecodeReaderPermissive_AllowsDuplicateKeys(t *testing.T) {
	// DecodeReaderPermissive should allow duplicate keys
	data := `{"admin": false, "admin": true}`
	reader := bytes.NewReader([]byte(data))
	var result map[string]bool
	err := DecodeReaderPermissive(reader, "test", limits.ConfigFile, &result)
	if err != nil {
		t.Errorf("DecodeReaderPermissive() error = %v", err)
	}
}
