package boundedio

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/locktivity/epack/internal/limits"
)

func TestReadFileWithLimit(t *testing.T) {
	dir := t.TempDir()

	// Create test files
	smallFile := filepath.Join(dir, "small.txt")
	if err := os.WriteFile(smallFile, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}

	largeFile := filepath.Join(dir, "large.txt")
	largeData := make([]byte, 1000)
	if err := os.WriteFile(largeFile, largeData, 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		path      string
		limit     limits.SizeLimit
		wantData  []byte
		wantErr   bool
		wantPhase string
	}{
		{
			name:     "under-limit",
			path:     smallFile,
			limit:    100,
			wantData: []byte("hello"),
			wantErr:  false,
		},
		{
			name:     "at-limit",
			path:     smallFile,
			limit:    5,
			wantData: []byte("hello"),
			wantErr:  false,
		},
		{
			name:      "over-limit-stat",
			path:      largeFile,
			limit:     100,
			wantErr:   true,
			wantPhase: "stat",
		},
		{
			name:    "not-found",
			path:    filepath.Join(dir, "nonexistent.txt"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := ReadFileWithLimit(tt.path, tt.limit)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadFileWithLimit() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				if tt.wantPhase != "" {
					if berr, ok := err.(*BoundedReadError); ok {
						if berr.Phase != tt.wantPhase {
							t.Errorf("BoundedReadError.Phase = %q, want %q", berr.Phase, tt.wantPhase)
						}
					}
				}
				return
			}
			if !bytes.Equal(data, tt.wantData) {
				t.Errorf("ReadFileWithLimit() = %q, want %q", data, tt.wantData)
			}
		})
	}
}

func TestReadWithLimit(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(testFile, []byte("hello world"), 0644); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(testFile)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	data, err := ReadWithLimit(f, "test.txt", limits.SizeLimit(100))
	if err != nil {
		t.Fatalf("ReadWithLimit() error = %v", err)
	}
	if string(data) != "hello world" {
		t.Errorf("ReadWithLimit() = %q, want %q", data, "hello world")
	}
}

func TestReadReaderWithLimit(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		limit    limits.SizeLimit
		wantData string
		wantErr  bool
	}{
		{
			name:     "under-limit",
			input:    "hello",
			limit:    100,
			wantData: "hello",
			wantErr:  false,
		},
		{
			name:     "at-limit",
			input:    "hello",
			limit:    5,
			wantData: "hello",
			wantErr:  false,
		},
		{
			name:    "over-limit",
			input:   "hello world",
			limit:   5,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader([]byte(tt.input))
			data, err := ReadReaderWithLimit(r, "test", tt.limit)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadReaderWithLimit() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && string(data) != tt.wantData {
				t.Errorf("ReadReaderWithLimit() = %q, want %q", data, tt.wantData)
			}
		})
	}
}

func TestBoundedReadError(t *testing.T) {
	err := &BoundedReadError{
		Path:   "test.txt",
		Limit:  100,
		Actual: 200,
		Phase:  "stat",
	}

	if !IsBoundedReadError(err) {
		t.Error("IsBoundedReadError returned false for BoundedReadError")
	}

	msg := err.Error()
	if msg == "" {
		t.Error("BoundedReadError.Error() returned empty string")
	}

	// Test with non-BoundedReadError
	if IsBoundedReadError(os.ErrNotExist) {
		t.Error("IsBoundedReadError returned true for os.ErrNotExist")
	}
}
