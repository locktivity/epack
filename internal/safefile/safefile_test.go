//go:build !windows

package safefile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/locktivity/epack/errors"
)

func TestValidateAbsoluteFile(t *testing.T) {
	// Create a temp directory structure for testing
	tempDir := t.TempDir()

	// Create a valid file inside tempDir
	validFile := filepath.Join(tempDir, "profiles", "test.yaml")
	if err := os.MkdirAll(filepath.Dir(validFile), 0755); err != nil {
		t.Fatalf("failed to create test dir: %v", err)
	}
	if err := os.WriteFile(validFile, []byte("test content"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Create a file outside tempDir (sibling directory)
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "outside.yaml")
	if err := os.WriteFile(outsideFile, []byte("outside content"), 0644); err != nil {
		t.Fatalf("failed to create outside file: %v", err)
	}

	// Create a symlink inside tempDir pointing to a valid file
	symlinkPath := filepath.Join(tempDir, "profiles", "link.yaml")
	if err := os.Symlink(validFile, symlinkPath); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	// Create a directory (not a regular file)
	dirPath := filepath.Join(tempDir, "profiles", "subdir")
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		t.Fatalf("failed to create subdir: %v", err)
	}

	tests := []struct {
		name      string
		root      string
		absPath   string
		wantErr   bool
		errCode   errors.Code
		errSubstr string
	}{
		{
			name:    "valid file within root",
			root:    tempDir,
			absPath: validFile,
			wantErr: false,
		},
		{
			name:      "file outside root",
			root:      tempDir,
			absPath:   outsideFile,
			wantErr:   true,
			errCode:   errors.PathTraversal,
			errSubstr: "escapes root",
		},
		{
			name:      "symlink rejected",
			root:      tempDir,
			absPath:   symlinkPath,
			wantErr:   true,
			errCode:   errors.SymlinkNotAllowed,
			errSubstr: "symlink",
		},
		{
			name:      "directory rejected",
			root:      tempDir,
			absPath:   dirPath,
			wantErr:   true,
			errSubstr: "not a regular file",
		},
		{
			name:      "nonexistent file",
			root:      tempDir,
			absPath:   filepath.Join(tempDir, "profiles", "nonexistent.yaml"),
			wantErr:   true,
			errSubstr: "does not exist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ValidateAbsoluteFile(tt.root, tt.absPath)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
					return
				}
				if tt.errCode != "" && errors.CodeOf(err) != tt.errCode {
					t.Errorf("expected error code %v, got %v", tt.errCode, errors.CodeOf(err))
				}
				if tt.errSubstr != "" && !containsSubstring(err.Error(), tt.errSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if result != tt.absPath {
				t.Errorf("expected result %q, got %q", tt.absPath, result)
			}
		})
	}
}

func TestValidateRegularFile(t *testing.T) {
	// Create a temp directory structure for testing
	tempDir := t.TempDir()

	// Create a valid file inside tempDir
	if err := os.MkdirAll(filepath.Join(tempDir, "profiles"), 0755); err != nil {
		t.Fatalf("failed to create test dir: %v", err)
	}
	validFile := filepath.Join(tempDir, "profiles", "test.yaml")
	if err := os.WriteFile(validFile, []byte("test content"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	tests := []struct {
		name    string
		root    string
		relPath string
		wantErr bool
	}{
		{
			name:    "valid relative path",
			root:    tempDir,
			relPath: "profiles/test.yaml",
			wantErr: false,
		},
		{
			name:    "path traversal rejected",
			root:    tempDir,
			relPath: "../etc/passwd",
			wantErr: true,
		},
		{
			name:    "absolute path rejected",
			root:    tempDir,
			relPath: "/etc/passwd",
			wantErr: true,
		},
		{
			name:    "nonexistent file",
			root:    tempDir,
			relPath: "profiles/nonexistent.yaml",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ValidateRegularFile(tt.root, tt.relPath)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			// Result should be the absolute path
			expectedAbs := filepath.Join(tempDir, tt.relPath)
			if result != expectedAbs {
				t.Errorf("expected result %q, got %q", expectedAbs, result)
			}
		})
	}
}

func TestCheckContainment(t *testing.T) {
	tempDir := t.TempDir()
	outsideDir := t.TempDir()

	tests := []struct {
		name    string
		root    string
		absPath string
		wantRel string
		wantErr bool
	}{
		{
			name:    "file within root",
			root:    tempDir,
			absPath: filepath.Join(tempDir, "profiles", "test.yaml"),
			wantRel: filepath.Join("profiles", "test.yaml"),
			wantErr: false,
		},
		{
			name:    "file at root",
			root:    tempDir,
			absPath: filepath.Join(tempDir, "test.yaml"),
			wantRel: "test.yaml",
			wantErr: false,
		},
		{
			name:    "file outside root",
			root:    tempDir,
			absPath: filepath.Join(outsideDir, "outside.yaml"),
			wantErr: true,
		},
		{
			name:    "parent traversal",
			root:    tempDir,
			absPath: filepath.Join(tempDir, "..", "outside.yaml"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rel, err := checkContainment(tt.root, tt.absPath)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if rel != tt.wantRel {
				t.Errorf("expected rel %q, got %q", tt.wantRel, rel)
			}
		})
	}
}

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
