package remoteconfig

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/internal/remote"
)

func sampleConfig(revision int, body string) remote.ConfigPullResult {
	return remote.ConfigPullResult{
		ID:       "pipe_1",
		Name:     "northwind-production",
		Title:    "Northwind production",
		Stream:   "northwind/production",
		RunsIn:   "My laptop",
		Revision: revision,
		Files: map[string]string{
			"epack.yaml":                   body,
			".locktivity/manifest.json":    `{"schema_version":1}` + "\n",
			".epack/hooks/pre-collect.sh":  "#!/bin/sh\n",
			".epack/hooks/post-collect.sh": "#!/bin/sh\n",
		},
		Shas: map[string]string{
			"epack.yaml":                "x",
			".locktivity/manifest.json": "x",
		},
		Lockfile: "schema_version: 1\n",
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(data)
}

func TestWrite_CreatesFolderAndState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "northwind-production")
	fixed := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

	result, err := Write(sampleConfig(1, "stream: northwind/production\n"), "locktivity", Options{Dir: dir, FilesDir: ".locktivity", Now: func() time.Time { return fixed }})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !result.Created {
		t.Error("Created = false, want true")
	}
	if len(result.Written) != 5 {
		t.Errorf("Written = %v, want 5 files", result.Written)
	}
	if got := readFile(t, filepath.Join(dir, "epack.yaml")); got != "stream: northwind/production\n" {
		t.Errorf("epack.yaml = %q", got)
	}
	if got := readFile(t, filepath.Join(dir, "epack.lock.yaml")); got != "schema_version: 1\n" {
		t.Errorf("epack.lock.yaml = %q", got)
	}

	state, err := LoadState(dir)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if state == nil || state.Revision != 1 || state.Remote != "locktivity" || state.Name != "northwind-production" || state.ID != "pipe_1" {
		t.Fatalf("state = %+v", state)
	}
	if state.PulledAt != "2026-09-30T12:00:00Z" {
		t.Errorf("PulledAt = %q", state.PulledAt)
	}
	if _, ok := state.Files["epack.yaml"]; !ok {
		t.Error("managed file not recorded")
	}
	if _, ok := state.Files[".epack/hooks/pre-collect.sh"]; ok {
		t.Error("user-owned hook must not be recorded as managed")
	}
	if _, ok := state.Files["epack.lock.yaml"]; !ok {
		t.Error("lockfile not recorded as managed")
	}
}

func TestWrite_SameRevisionIsCurrent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cfg")
	cfg := sampleConfig(1, "a\n")
	if _, err := Write(cfg, "locktivity", Options{Dir: dir, FilesDir: ".locktivity"}); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	result, err := Write(cfg, "locktivity", Options{Dir: dir, FilesDir: ".locktivity"})
	if err != nil {
		t.Fatalf("second Write: %v", err)
	}
	if !result.Current() || result.Created {
		t.Errorf("second write should be current and not created: %+v", result)
	}
}

func TestWrite_HooksFollowTheTemplateUntilEdited(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cfg")
	first := sampleConfig(1, "a\n")
	if _, err := Write(first, "locktivity", Options{Dir: dir, FilesDir: ".locktivity"}); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	pre := filepath.Join(dir, ".epack/hooks/pre-collect.sh")
	post := filepath.Join(dir, ".epack/hooks/post-collect.sh")
	if template, err := IsRemoteTemplate(dir, ".epack/hooks/pre-collect.sh"); err != nil || !template {
		t.Fatalf("a freshly written hook should be the remote's template: %v, %v", template, err)
	}
	if err := os.WriteFile(post, []byte("#!/bin/sh\necho mine\n"), 0o755); err != nil {
		t.Fatalf("editing hook: %v", err)
	}

	second := sampleConfig(2, "b\n")
	second.Files[".epack/hooks/pre-collect.sh"] = "#!/bin/sh\n# new template\n"
	second.Files[".epack/hooks/post-collect.sh"] = "#!/bin/sh\n# new template\n"
	if _, err := Write(second, "locktivity", Options{Dir: dir, FilesDir: ".locktivity"}); err != nil {
		t.Fatalf("second Write: %v", err)
	}
	if got := readFile(t, pre); got != "#!/bin/sh\n# new template\n" {
		t.Errorf("unedited hook should follow the new template, got %q", got)
	}
	if got := readFile(t, post); got != "#!/bin/sh\necho mine\n" {
		t.Errorf("edited hook was overwritten: %q", got)
	}
	if template, _ := IsRemoteTemplate(dir, ".epack/hooks/post-collect.sh"); template {
		t.Error("an edited hook must not count as the remote's template")
	}
	if template, _ := IsRemoteTemplate(dir, ".epack/hooks/pre-collect.sh"); !template {
		t.Error("the refreshed hook should still be the remote's template")
	}
}

func TestIsRemoteTemplate_FalseWithoutAPullRecord(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".epack", "hooks"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".epack/hooks/pre-collect.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("writing hook: %v", err)
	}
	if template, err := IsRemoteTemplate(dir, ".epack/hooks/pre-collect.sh"); err != nil || template {
		t.Fatalf("IsRemoteTemplate = %v, %v; want false", template, err)
	}
}

func TestWrite_NewRevisionReplacesUnmodifiedManagedFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cfg")
	if _, err := Write(sampleConfig(1, "a\n"), "locktivity", Options{Dir: dir, FilesDir: ".locktivity"}); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	hook := filepath.Join(dir, ".epack/hooks/pre-collect.sh")
	if err := os.WriteFile(hook, []byte("#!/bin/sh\necho mine\n"), 0o755); err != nil {
		t.Fatalf("editing hook: %v", err)
	}

	result, err := Write(sampleConfig(2, "b\n"), "locktivity", Options{Dir: dir, FilesDir: ".locktivity"})
	if err != nil {
		t.Fatalf("second Write: %v", err)
	}
	if got := readFile(t, filepath.Join(dir, "epack.yaml")); got != "b\n" {
		t.Errorf("epack.yaml = %q, want the new revision", got)
	}
	if got := readFile(t, hook); got != "#!/bin/sh\necho mine\n" {
		t.Errorf("edited hook was overwritten: %q", got)
	}
	if result.State.Revision != 2 {
		t.Errorf("revision = %d, want 2", result.State.Revision)
	}
}

func TestWrite_RefusesLocalChangesUnlessForced(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cfg")
	if _, err := Write(sampleConfig(1, "a\n"), "locktivity", Options{Dir: dir, FilesDir: ".locktivity"}); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "epack.yaml"), []byte("edited\n"), 0o644); err != nil {
		t.Fatalf("editing: %v", err)
	}

	_, err := Write(sampleConfig(2, "b\n"), "locktivity", Options{Dir: dir, FilesDir: ".locktivity"})
	var changes *LocalChangesError
	if !errors.As(err, &changes) {
		t.Fatalf("err = %v, want LocalChangesError", err)
	}
	if len(changes.Paths) != 1 || changes.Paths[0] != "epack.yaml" {
		t.Errorf("Paths = %v", changes.Paths)
	}
	if got := readFile(t, filepath.Join(dir, "epack.yaml")); got != "edited\n" {
		t.Errorf("refused write still changed the file: %q", got)
	}

	if _, err := Write(sampleConfig(2, "b\n"), "locktivity", Options{Dir: dir, FilesDir: ".locktivity", Force: true}); err != nil {
		t.Fatalf("forced Write: %v", err)
	}
	if got := readFile(t, filepath.Join(dir, "epack.yaml")); got != "b\n" {
		t.Errorf("forced write did not replace the file: %q", got)
	}
}

func TestWrite_RefusesOccupiedFolderWithoutState(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatalf("seeding: %v", err)
	}
	if _, err := Write(sampleConfig(1, "a\n"), "locktivity", Options{Dir: dir, FilesDir: ".locktivity"}); !errors.Is(err, ErrNotCloned) {
		t.Fatalf("err = %v, want ErrNotCloned", err)
	}
	if _, err := Write(sampleConfig(1, "a\n"), "locktivity", Options{Dir: dir, FilesDir: ".locktivity", Force: true}); err != nil {
		t.Fatalf("forced Write: %v", err)
	}
}

func TestWrite_DefaultsFolderToName(t *testing.T) {
	base := t.TempDir()
	oldWd, _ := os.Getwd()
	if err := os.Chdir(base); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() { _ = os.Chdir(oldWd) }()

	result, err := Write(sampleConfig(1, "a\n"), "locktivity", Options{FilesDir: ".locktivity"})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if filepath.Base(result.Dir) != "northwind-production" {
		t.Errorf("Dir = %q", result.Dir)
	}
}

func TestWrite_RejectsEscapingPaths(t *testing.T) {
	cfg := sampleConfig(1, "a\n")
	cfg.Files["../outside.yaml"] = "x"
	if _, err := Write(cfg, "locktivity", Options{Dir: filepath.Join(t.TempDir(), "cfg"), FilesDir: ".locktivity"}); err == nil {
		t.Fatal("expected an error for a path outside the folder")
	}
}

func TestLoadState_NilWhenAbsent(t *testing.T) {
	state, err := LoadState(t.TempDir())
	if err != nil || state != nil {
		t.Fatalf("LoadState = %v, %v; want nil, nil", state, err)
	}
}

func TestWrite_RefusesHiddenPathsOutsideTheManifestAndHooks(t *testing.T) {
	refused := []string{
		".epack/collectors/tls/v1.0.0/darwin-arm64/tls",
		".epack/remotes/locktivity/v0.3.0/darwin-arm64/locktivity",
		".epack/remote-config.json",
		".epack/hooks/.hidden.sh",
		".epack/hooks/nested/pre-collect.sh",
		".git/hooks/pre-commit",
		".ssh/authorized_keys",
		".locktivity/.secret",
		"profiles/.hidden.json",
		"bad\x1bname.yaml",
	}
	for _, path := range refused {
		cfg := sampleConfig(1, "a\n")
		cfg.Files[path] = "x"
		if _, err := Write(cfg, "locktivity", Options{Dir: filepath.Join(t.TempDir(), "cfg"), FilesDir: ".locktivity"}); err == nil {
			t.Errorf("Write accepted %q", path)
		}
	}

	allowed := []string{".locktivity/manifest.json", ".epack/hooks/pre-collect.sh", "profiles/soc2.json", "mappings/controls.yaml"}
	for _, path := range allowed {
		cfg := sampleConfig(1, "a\n")
		cfg.Files[path] = "x"
		if _, err := Write(cfg, "locktivity", Options{Dir: filepath.Join(t.TempDir(), "cfg"), FilesDir: ".locktivity"}); err != nil {
			t.Errorf("Write refused %q: %v", path, err)
		}
	}
}

func TestWrite_RefusesASymlinkedFolder(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	link := filepath.Join(base, "cfg")
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := Write(sampleConfig(1, "a\n"), "locktivity", Options{Dir: link, FilesDir: ".locktivity", Force: true}); err == nil {
		t.Fatal("expected a symlinked folder to be refused")
	}
}

func TestValidateFolderName(t *testing.T) {
	for _, name := range []string{"northwind-production", "Northwind Production", "a1"} {
		if err := ValidateFolderName(name); err != nil {
			t.Errorf("ValidateFolderName(%q) = %v", name, err)
		}
	}
	for _, name := range []string{"", ".", "..", ".ssh", "a/b", `a\b`, "x\x00y", strings.Repeat("n", MaxFolderNameLength+1)} {
		if err := ValidateFolderName(name); err == nil {
			t.Errorf("ValidateFolderName(%q) accepted an unsafe name", name)
		}
	}
}

func TestWrite_DefaultFolderMustBeAPlainName(t *testing.T) {
	cfg := sampleConfig(1, "a\n")
	cfg.Name = ".ssh"
	if _, err := Write(cfg, "locktivity", Options{}); err == nil {
		t.Fatal("expected a hidden default folder name to be refused")
	}
}

func TestWriteRefusesHiddenPathsOutsideTheDeclaredFolder(t *testing.T) {
	cfg := sampleConfig(1, "stream: northwind/production\n")

	if _, err := Write(cfg, "locktivity", Options{Dir: t.TempDir()}); err == nil || !strings.Contains(err.Error(), ".locktivity/manifest.json") {
		t.Fatalf("a pull with no declared folder must refuse the manifest, got %v", err)
	}

	if _, err := Write(cfg, "locktivity", Options{Dir: t.TempDir(), FilesDir: ".acme"}); err == nil || !strings.Contains(err.Error(), ".locktivity/manifest.json") {
		t.Fatalf("a pull must refuse another remote's folder, got %v", err)
	}

	acme := sampleConfig(1, "stream: northwind/production\n")
	delete(acme.Files, ".locktivity/manifest.json")
	delete(acme.Shas, ".locktivity/manifest.json")
	acme.Files[".acme/state.json"] = "{}"
	acme.Shas[".acme/state.json"] = "x"
	if _, err := Write(acme, "acme", Options{Dir: t.TempDir(), FilesDir: ".acme"}); err != nil {
		t.Fatalf("the declared folder must be allowed: %v", err)
	}

	for _, path := range []string{".acme/.hidden", ".git/hooks/pre-commit", ".epack/collectors/x", "sub/.secret"} {
		if allowedPath(path, ".acme") {
			t.Errorf("%s must be refused", path)
		}
	}
	for _, path := range []string{"epack.yaml", "config/okta.yaml", ".acme/manifest.json", ".epack/hooks/pre-collect.sh"} {
		if !allowedPath(path, ".acme") {
			t.Errorf("%s must be allowed", path)
		}
	}
}

func TestWriteNamesTheRefusedHiddenPathAndTheDeclaredFolder(t *testing.T) {
	_, err := Write(sampleConfig(1, "stream: northwind/production\n"), "locktivity", Options{Dir: t.TempDir()})
	var hidden *HiddenPathError
	if !errors.As(err, &hidden) || hidden.Path != ".locktivity/manifest.json" || hidden.FilesDir != "" {
		t.Fatalf("want a HiddenPathError for the manifest with no declared folder, got %v", err)
	}

	_, err = Write(sampleConfig(1, "stream: northwind/production\n"), "acme", Options{Dir: t.TempDir(), FilesDir: ".acme"})
	if !errors.As(err, &hidden) || hidden.FilesDir != ".acme" {
		t.Fatalf("want the declared folder on the error, got %v", err)
	}
}
