package collector

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/locktivity/epack/pack"
	"github.com/locktivity/epack/pack/builder"
)

func requireSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlinks unavailable: %v", err)
		}
		t.Fatal(err)
	}
}

func resultEnvelope(t *testing.T, entries ...map[string]any) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"type":             "epack_result",
		"protocol_version": 1,
		"artifacts":        entries,
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseCollectorOutput_FileArtifacts(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		wantErr bool
	}{
		{
			name:   "file artifact with path",
			output: `{"protocol_version":1,"artifacts":[{"file":"documents/policy.pdf","path":"artifacts/documents/policy.pdf"}]}`,
		},
		{
			name:    "file and data are mutually exclusive",
			output:  `{"protocol_version":1,"artifacts":[{"file":"a.pdf","data":{"x":1},"path":"artifacts/a.pdf"}]}`,
			wantErr: true,
		},
		{
			name:    "file requires path",
			output:  `{"protocol_version":1,"artifacts":[{"file":"a.pdf"}]}`,
			wantErr: true,
		},
		{
			name:    "file rejects traversal",
			output:  `{"protocol_version":1,"artifacts":[{"file":"../escape.pdf","path":"artifacts/escape.pdf"}]}`,
			wantErr: true,
		},
		{
			name:    "file rejects absolute paths",
			output:  `{"protocol_version":1,"artifacts":[{"file":"/etc/passwd","path":"artifacts/passwd"}]}`,
			wantErr: true,
		},
		{
			name:    "entry with neither file nor data is rejected",
			output:  `{"protocol_version":1,"artifacts":[{"path":"artifacts/x"}]}`,
			wantErr: true,
		},
		{
			name:   "entry with explicit null data is preserved",
			output: `{"protocol_version":1,"artifacts":[{"data":null,"path":"artifacts/x.json"}]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envelope, err := ParseCollectorOutput([]byte(tt.output))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got envelope %+v", envelope)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseCollectorOutput failed: %v", err)
			}
			if len(envelope.Artifacts) == 0 {
				t.Fatal("expected an artifact")
			}
			if tt.name == "entry with explicit null data is preserved" {
				return
			}
			if envelope.Artifacts[0].File == "" {
				t.Fatal("expected File to be populated")
			}
		})
	}
}

func TestAddCollectorArtifacts_StagedFile(t *testing.T) {
	stagingDir := t.TempDir()
	pdfBytes := []byte("%PDF-1.4 staged test content")
	if err := os.MkdirAll(filepath.Join(stagingDir, "documents"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stagingDir, "documents", "policy.pdf"), pdfBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	b := builder.New("test-stream")
	results := []RunResult{
		{
			Collector: "documents",
			Success:   true,
			OutputDir: stagingDir,
			Output: resultEnvelope(t,
				map[string]any{"data": map[string]any{"documents": []any{map[string]any{"name": "Policy"}}}, "path": "artifacts/documents.json"},
				map[string]any{"file": "documents/policy.pdf", "path": "artifacts/documents/policy.pdf"},
			),
		},
	}

	if err := addCollectorArtifacts(b, results, "2026-07-07T10:00:00Z"); err != nil {
		t.Fatalf("addCollectorArtifacts failed: %v", err)
	}

	packPath := filepath.Join(t.TempDir(), "out.epack")
	if err := b.Build(packPath); err != nil {
		t.Fatalf("building pack: %v", err)
	}

	p, err := pack.Open(packPath)
	if err != nil {
		t.Fatalf("opening pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	got, err := p.ReadFileUntrusted("artifacts/documents/policy.pdf")
	if err != nil {
		t.Fatalf("reading staged artifact from pack: %v", err)
	}
	if string(got.UnsafeBytes()) != string(pdfBytes) {
		t.Errorf("staged artifact bytes mismatch: got %q want %q", got.UnsafeBytes(), pdfBytes)
	}
}

func TestAddCollectorArtifacts_StagedFileErrors(t *testing.T) {
	stagingDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(stagingDir, "real.pdf"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	requireSymlink(t, filepath.Join(stagingDir, "real.pdf"), filepath.Join(stagingDir, "link.pdf"))

	outsideDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(outsideDir, "policy.pdf"), []byte("host secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	requireSymlink(t, outsideDir, filepath.Join(stagingDir, "documents"))

	// Unix rejection messages come from the O_NOFOLLOW open walk; the Windows
	// best-effort walk in safefile reports a single message for both shapes.
	symlinkFileMsg := "refusing to read symlink"
	symlinkDirMsg := "refusing symlink or non-directory component"
	if runtime.GOOS == "windows" {
		symlinkFileMsg = "refusing symlink component"
		symlinkDirMsg = "refusing symlink component"
	}

	tests := []struct {
		name         string
		outputDir    string
		file         string
		wantSubstr   string
		wantNotExist bool
	}{
		{name: "missing staging dir", outputDir: "", file: "real.pdf", wantSubstr: "no staging directory was provided"},
		{name: "missing file", outputDir: stagingDir, file: "absent.pdf", wantNotExist: true},
		{name: "symlink rejected", outputDir: stagingDir, file: "link.pdf", wantSubstr: symlinkFileMsg},
		{name: "symlinked intermediate directory rejected", outputDir: stagingDir, file: "documents/policy.pdf", wantSubstr: symlinkDirMsg},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := builder.New("test-stream")
			results := []RunResult{
				{
					Collector: "documents",
					Success:   true,
					OutputDir: tt.outputDir,
					Output:    resultEnvelope(t, map[string]any{"file": tt.file, "path": "artifacts/documents/out.pdf"}),
				},
			}

			err := addCollectorArtifacts(b, results, "2026-07-07T10:00:00Z")
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if tt.wantSubstr != "" && !strings.Contains(err.Error(), tt.wantSubstr) {
				t.Errorf("expected error containing %q, got %q", tt.wantSubstr, err)
			}
			if tt.wantNotExist && !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("expected fs.ErrNotExist, got %q", err)
			}
		})
	}
}

func TestCollectResultClose(t *testing.T) {
	dir := t.TempDir()
	staged := filepath.Join(dir, "staging")
	if err := os.MkdirAll(staged, 0o700); err != nil {
		t.Fatal(err)
	}

	result := &CollectResult{Results: []RunResult{{Collector: "documents", OutputDir: staged}}}
	if err := result.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}

	if _, err := os.Stat(staged); !os.IsNotExist(err) {
		t.Errorf("expected staging dir removed, stat err: %v", err)
	}
}
