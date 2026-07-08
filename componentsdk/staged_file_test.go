package componentsdk

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// A downstream test double should not need staging methods.
type baseOnlyContext struct{}

func (baseOnlyContext) Context() context.Context       { return context.Background() }
func (baseOnlyContext) Name() string                   { return "" }
func (baseOnlyContext) Config() map[string]any         { return nil }
func (baseOnlyContext) Level() Level                   { return LevelTrust }
func (baseOnlyContext) Secret(string) string           { return "" }
func (baseOnlyContext) Status(string)                  {}
func (baseOnlyContext) Progress(int64, int64, string)  {}
func (baseOnlyContext) Emit([]CollectedArtifact) error { return nil }

var _ CollectorContext = baseOnlyContext{}

func TestStagingOptionalInterface(t *testing.T) {
	if _, ok := Staging(baseOnlyContext{}); ok {
		t.Error("a base-only context must not satisfy StagingContext")
	}

	dir := t.TempDir()
	s, ok := Staging(&collectorContext{outputDir: dir})
	if !ok {
		t.Fatal("collectorContext must satisfy StagingContext")
	}
	if s.OutputDir() != dir {
		t.Errorf("OutputDir = %q, want %q", s.OutputDir(), dir)
	}
}

func requireSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlinks unavailable: %v", err)
		}
		t.Fatal(err)
	}
}

func stagedContext(t *testing.T) (*collectorContext, string) {
	t.Helper()
	dir := t.TempDir()
	return &collectorContext{name: "test", outputDir: dir}, dir
}

func TestStageFile(t *testing.T) {
	ctx, dir := stagedContext(t)

	f, name, err := ctx.StageFile("documents/policy.pdf")
	if err != nil {
		t.Fatalf("StageFile failed: %v", err)
	}
	if name != "documents/policy.pdf" {
		t.Errorf("unexpected returned path: %s", name)
	}
	if _, err := f.WriteString("content"); err != nil {
		t.Fatalf("writing staged file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing staged file: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "documents", "policy.pdf"))
	if err != nil || string(got) != "content" {
		t.Errorf("staged file mismatch: %q err=%v", got, err)
	}
}

func TestStageFileRejectsEscapes(t *testing.T) {
	ctx, _ := stagedContext(t)

	for _, rel := range []string{"../escape.pdf", "/abs.pdf"} {
		if f, _, err := ctx.StageFile(rel); err == nil {
			_ = f.Close()
			t.Errorf("expected error for %q", rel)
		}
	}
}

func TestWriteStagedFile(t *testing.T) {
	ctx, dir := stagedContext(t)

	rel, err := ctx.WriteStagedFile("documents/policy.pdf", []byte("content"))
	if err != nil {
		t.Fatalf("WriteStagedFile failed: %v", err)
	}
	if rel != "documents/policy.pdf" {
		t.Errorf("unexpected returned path: %s", rel)
	}
	got, err := os.ReadFile(filepath.Join(dir, "documents", "policy.pdf"))
	if err != nil || string(got) != "content" {
		t.Errorf("staged file mismatch: %q err=%v", got, err)
	}
}

func TestWriteStagedFileRejectsEscapes(t *testing.T) {
	ctx, _ := stagedContext(t)

	for _, rel := range []string{"../escape.pdf", "/abs.pdf"} {
		if _, err := ctx.WriteStagedFile(rel, []byte("x")); err == nil {
			t.Errorf("expected error for %q", rel)
		}
	}
}

func TestStagingHelpersRejectSymlinkedSubdir(t *testing.T) {
	ctx, dir := stagedContext(t)
	outside := t.TempDir()
	requireSymlink(t, outside, filepath.Join(dir, "documents"))

	if _, err := ctx.WriteStagedFile("documents/policy.pdf", []byte("x")); err == nil {
		t.Error("WriteStagedFile wrote through a symlinked subdirectory")
	}
	if f, _, err := ctx.StageFile("documents/policy.pdf"); err == nil {
		_ = f.Close()
		t.Error("StageFile created through a symlinked subdirectory")
	}
	if _, err := os.Stat(filepath.Join(outside, "policy.pdf")); err == nil {
		t.Error("bytes escaped the staging directory via the symlink")
	}
}

func TestStageFileRequiresOutputDir(t *testing.T) {
	ctx := &collectorContext{name: "test"}

	if _, _, err := ctx.StageFile("a.pdf"); err == nil {
		t.Fatal("expected error when OutputDir is unset")
	}
}

func TestStagedFileRel(t *testing.T) {
	ctx, dir := stagedContext(t)
	if err := os.MkdirAll(filepath.Join(dir, "documents"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "documents", "policy.pdf"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("relative path", func(t *testing.T) {
		rel, err := ctx.stagedFileRel(CollectedArtifact{File: "documents/policy.pdf", Path: "artifacts/documents/policy.pdf"})
		if err != nil {
			t.Fatalf("stagedFileRel failed: %v", err)
		}
		if rel != "documents/policy.pdf" {
			t.Errorf("unexpected rel: %s", rel)
		}
	})

	t.Run("absolute path inside staging dir", func(t *testing.T) {
		rel, err := ctx.stagedFileRel(CollectedArtifact{
			File: filepath.Join(dir, "documents", "policy.pdf"),
			Path: "artifacts/documents/policy.pdf",
		})
		if err != nil {
			t.Fatalf("stagedFileRel failed: %v", err)
		}
		if rel != "documents/policy.pdf" {
			t.Errorf("unexpected rel: %s", rel)
		}
	})

	t.Run("requires path", func(t *testing.T) {
		if _, err := ctx.stagedFileRel(CollectedArtifact{File: "documents/policy.pdf"}); err == nil {
			t.Fatal("expected error for missing Path")
		}
	})

	t.Run("rejects data alongside file", func(t *testing.T) {
		artifact := CollectedArtifact{File: "documents/policy.pdf", Path: "artifacts/x.pdf", Data: map[string]any{"a": 1}}
		if _, err := ctx.stagedFileRel(artifact); err == nil {
			t.Fatal("expected error for File with Data")
		}
	})

	t.Run("rejects outside staging dir", func(t *testing.T) {
		outside := filepath.Join(t.TempDir(), "outside.pdf")
		if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ctx.stagedFileRel(CollectedArtifact{File: outside, Path: "artifacts/outside.pdf"}); err == nil {
			t.Fatal("expected error for file outside staging dir")
		}
	})

	t.Run("rejects missing file", func(t *testing.T) {
		if _, err := ctx.stagedFileRel(CollectedArtifact{File: "documents/absent.pdf", Path: "artifacts/absent.pdf"}); err == nil {
			t.Fatal("expected error for missing file")
		}
	})

	t.Run("rejects symlinked intermediate directory", func(t *testing.T) {
		outsideDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(outsideDir, "aliased.pdf"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		requireSymlink(t, outsideDir, filepath.Join(dir, "linked-dir"))
		if _, err := ctx.stagedFileRel(CollectedArtifact{File: "linked-dir/aliased.pdf", Path: "artifacts/aliased.pdf"}); err == nil {
			t.Fatal("expected error for symlinked intermediate directory")
		}
	})

	t.Run("requires output dir", func(t *testing.T) {
		bare := &collectorContext{name: "test"}
		if _, err := bare.stagedFileRel(CollectedArtifact{File: "a.pdf", Path: "artifacts/a.pdf"}); err == nil {
			t.Fatal("expected error when OutputDir is unset")
		}
	})
}
