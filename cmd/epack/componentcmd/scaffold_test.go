//go:build components

package componentcmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateProjectName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		errMsg  string
	}{
		// Valid names
		{"simple name", "my-project", false, ""},
		{"with dots", "my.project", false, ""},
		{"with underscore", "my_project", false, ""},
		{"mixed case", "MyProject", false, ""},
		{"numbers", "project123", false, ""},

		// Invalid: empty
		{"empty", "", true, "cannot be empty"},

		// Invalid: path separators
		{"forward slash", "my/project", true, "path separators"},
		{"backslash", "my\\project", true, "path separators"},

		// Invalid: path traversal
		{"dot dot", "..", true, "path traversal segment"},
		{"dot dot prefix", "../foo", true, "path separators"}, // slash caught first
		{"dot dot embedded", "foo..bar", true, "double-dot"},

		// Invalid: Windows-forbidden characters
		{"less than", "foo<bar", true, "Windows-forbidden characters"},
		{"greater than", "foo>bar", true, "Windows-forbidden characters"},
		{"colon", "foo:bar", true, "Windows-forbidden characters"},
		{"quote", "foo\"bar", true, "Windows-forbidden characters"},
		{"pipe", "foo|bar", true, "Windows-forbidden characters"},
		{"question", "foo?bar", true, "Windows-forbidden characters"},
		{"asterisk", "foo*bar", true, "Windows-forbidden characters"},

		// Invalid: trailing dots and spaces
		{"trailing dot", "foo.", true, "trailing dot or space"},
		{"trailing space", "foo ", true, "trailing dot or space"},

		// Invalid: Windows absolute paths
		{"windows drive", "C:foo", true, "absolute path"},
		{"windows drive lower", "c:foo", true, "absolute path"},

		// Invalid: Windows reserved names
		{"CON", "CON", true, "reserved on Windows"},
		{"con lowercase", "con", true, "reserved on Windows"},
		{"PRN", "PRN", true, "reserved on Windows"},
		{"AUX", "aux", true, "reserved on Windows"},
		{"NUL", "nul", true, "reserved on Windows"},
		{"COM1", "COM1", true, "reserved on Windows"},
		{"LPT1", "lpt1", true, "reserved on Windows"},
		// Reserved names with extensions
		{"con.txt", "con.txt", true, "reserved on Windows"},
		{"CON.md", "CON.md", true, "reserved on Windows"},
		{"lpt1.log", "lpt1.log", true, "reserved on Windows"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProjectName(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateProjectName(%q) = nil, want error containing %q", tt.input, tt.errMsg)
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidateProjectName(%q) error = %q, want error containing %q", tt.input, err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateProjectName(%q) = %v, want nil", tt.input, err)
				}
			}
		})
	}
}

func TestParseGitRemoteURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		// GitHub HTTPS
		{"github https with .git", "https://github.com/acme/api.git", "acme/api"},
		{"github https without .git", "https://github.com/acme/api", "acme/api"},

		// GitHub SSH
		{"github ssh colon", "git@github.com:acme/api.git", "acme/api"},
		{"github ssh scheme", "ssh://git@github.com/acme/api.git", "acme/api"},

		// GitLab nested groups (takes last two segments)
		{"gitlab nested", "https://gitlab.com/acme/platform/api.git", "platform/api"},
		{"gitlab deeply nested", "https://gitlab.com/a/b/c/d/repo.git", "d/repo"},

		// Edge cases
		{"single segment", "https://github.com/repo.git", ""},
		{"empty", "", ""},
		{"just host", "github.com", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseGitRemoteURL(tt.url)
			if got != tt.want {
				t.Errorf("parseGitRemoteURL(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestUpdateManagedBlock(t *testing.T) {
	start := "# >>> start >>>"
	end := "# <<< end <<<"
	content := "managed content"

	tests := []struct {
		name     string
		existing string
		want     string
	}{
		{
			name:     "empty file",
			existing: "",
			want:     "# >>> start >>>\nmanaged content\n# <<< end <<<\n",
		},
		{
			name:     "file with content, no block",
			existing: "existing content\n",
			want:     "existing content\n\n# >>> start >>>\nmanaged content\n# <<< end <<<\n",
		},
		{
			name:     "file with content no trailing newline",
			existing: "existing content",
			want:     "existing content\n\n# >>> start >>>\nmanaged content\n# <<< end <<<\n",
		},
		{
			name:     "file with existing block",
			existing: "before\n# >>> start >>>\nold content\n# <<< end <<<\nafter\n",
			want:     "before\n# >>> start >>>\nmanaged content\n# <<< end <<<\nafter\n",
		},
		{
			name:     "only managed block",
			existing: "# >>> start >>>\nold\n# <<< end <<<\n",
			want:     "# >>> start >>>\nmanaged content\n# <<< end <<<\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := updateManagedBlock(tt.existing, start, end, content)
			if got != tt.want {
				t.Errorf("updateManagedBlock() =\n%q\nwant\n%q", got, tt.want)
			}
		})
	}
}

func TestScaffold(t *testing.T) {
	// Create a temp directory for testing
	tmpDir := t.TempDir()
	projectDir := filepath.Join(tmpDir, "test-project")

	// Create the project directory
	if err := os.MkdirAll(projectDir, 0755); err != nil {
		t.Fatalf("failed to create project dir: %v", err)
	}

	// Run scaffold
	result, err := Scaffold(ScaffoldOptions{
		ProjectName: "test-project",
		TargetDir:   projectDir,
		SkipSample:  true, // Skip sample since it's not embedded yet
		SkipGit:     true, // Skip git for test
		Force:       false,
	})
	if err != nil {
		t.Fatalf("Scaffold() error = %v", err)
	}

	// Check result
	if result.TargetDir != projectDir {
		t.Errorf("TargetDir = %q, want %q", result.TargetDir, projectDir)
	}

	// Check files were created
	expectedFiles := []string{configFileName, gitignoreFile, filepath.Join(packsDir, gitkeepFile), readmeFile}
	for _, f := range expectedFiles {
		path := filepath.Join(projectDir, f)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("expected file %q to exist", f)
		}
	}

	// Check epack.yaml content
	configContent, err := os.ReadFile(filepath.Join(projectDir, configFileName))
	if err != nil {
		t.Fatalf("failed to read config: %v", err)
	}
	if !strings.Contains(string(configContent), "stream:") {
		t.Error("config should contain stream")
	}
	if !strings.Contains(string(configContent), "output: packs/") {
		t.Error("config should contain output: packs/")
	}

	// Check .gitignore has managed block
	gitignoreContent, err := os.ReadFile(filepath.Join(projectDir, gitignoreFile))
	if err != nil {
		t.Fatalf("failed to read .gitignore: %v", err)
	}
	if !strings.Contains(string(gitignoreContent), gitignoreBlockStart) {
		t.Error(".gitignore should contain managed block start marker")
	}
	if !strings.Contains(string(gitignoreContent), gitignoreBlockEnd) {
		t.Error(".gitignore should contain managed block end marker")
	}
	if !strings.Contains(string(gitignoreContent), "packs/*.epack") {
		t.Error(".gitignore should ignore generated .epack files")
	}
	if !strings.Contains(string(gitignoreContent), ".epack/*") {
		t.Error(".gitignore should ignore runtime .epack state by default")
	}
	if !strings.Contains(string(gitignoreContent), "!.epack/hooks/") {
		t.Error(".gitignore should keep .epack/hooks tracked")
	}
	if !strings.Contains(string(gitignoreContent), "!.epack/hooks/**") {
		t.Error(".gitignore should keep hook files under .epack/hooks tracked")
	}

	// Check README quickstart uses .epack extension
	readmeContent, err := os.ReadFile(filepath.Join(projectDir, readmeFile))
	if err != nil {
		t.Fatalf("failed to read README: %v", err)
	}
	if !strings.Contains(string(readmeContent), "epack sign packs/*.epack") {
		t.Error("README should use .epack extension in sign example")
	}
}

func TestScaffoldIdempotent(t *testing.T) {
	tmpDir := t.TempDir()

	// First scaffold
	result1, err := Scaffold(ScaffoldOptions{
		ProjectName: "idempotent-test",
		TargetDir:   tmpDir,
		SkipSample:  true,
		SkipGit:     true,
		Force:       false,
	})
	if err != nil {
		t.Fatalf("First Scaffold() error = %v", err)
	}

	// Read original config
	originalConfig, _ := os.ReadFile(filepath.Join(tmpDir, configFileName))

	// Second scaffold with SkipConfig (simulating init on existing project)
	result2, err := Scaffold(ScaffoldOptions{
		ProjectName:    "idempotent-test",
		TargetDir:      tmpDir,
		SkipSample:     true,
		SkipGit:        true,
		Force:          false,
		SkipConfig:     true,
		AlreadyInitted: true,
	})
	if err != nil {
		t.Fatalf("Second Scaffold() error = %v", err)
	}

	// Check AlreadyInitted is set
	if !result2.AlreadyInitted {
		t.Error("Second scaffold should have AlreadyInitted=true")
	}

	// Check config wasn't changed
	currentConfig, _ := os.ReadFile(filepath.Join(tmpDir, configFileName))
	if string(originalConfig) != string(currentConfig) {
		t.Error("Config should not have changed with SkipConfig=true")
	}

	// Check .gitignore still has managed block (and only one)
	gitignoreContent, _ := os.ReadFile(filepath.Join(tmpDir, gitignoreFile))
	count := strings.Count(string(gitignoreContent), gitignoreBlockStart)
	if count != 1 {
		t.Errorf("Expected 1 managed block start marker, got %d", count)
	}

	// First result should not have AlreadyInitted
	if result1.AlreadyInitted {
		t.Error("First scaffold should have AlreadyInitted=false")
	}
}

func TestIsDirNonEmpty(t *testing.T) {
	tmpDir := t.TempDir()

	// Empty directory
	emptyDir := filepath.Join(tmpDir, "empty")
	if err := os.MkdirAll(emptyDir, 0755); err != nil {
		t.Fatal(err)
	}
	nonEmpty, err := IsDirNonEmpty(emptyDir)
	if err != nil {
		t.Fatalf("IsDirNonEmpty error: %v", err)
	}
	if nonEmpty {
		t.Error("empty dir should not be non-empty")
	}

	// Non-empty directory
	nonEmptyDir := filepath.Join(tmpDir, "nonempty")
	if err := os.MkdirAll(nonEmptyDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nonEmptyDir, "file.txt"), []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	nonEmpty, err = IsDirNonEmpty(nonEmptyDir)
	if err != nil {
		t.Fatalf("IsDirNonEmpty error: %v", err)
	}
	if !nonEmpty {
		t.Error("non-empty dir should be non-empty")
	}

	// Non-existent directory
	nonEmpty, err = IsDirNonEmpty(filepath.Join(tmpDir, "nonexistent"))
	if err != nil {
		t.Fatalf("IsDirNonEmpty error for nonexistent: %v", err)
	}
	if nonEmpty {
		t.Error("non-existent dir should not be non-empty")
	}
}
