package tracemap

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fixtureDir is the fixture collector as a module of its own, which TestMain
// writes once, since loading it compiles the SDK beneath it.
var fixtureDir string

func TestMain(m *testing.M) {
	dir, err := writeFixture()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fixtureDir = dir
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// writeFixture copies testdata/fixture into a module that requires this
// checkout of epack, with its go.sum for the dependencies they share.
func writeFixture() (string, error) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp("", "tracemap-fixture-")
	if err != nil {
		return "", err
	}
	src := filepath.Join("testdata", "fixture")
	err = filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		target := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		return "", err
	}
	mod := "module example.com/epack-collector-fixture\n\ngo 1.26.0\n\nrequire github.com/locktivity/epack v0.0.0\n\nreplace github.com/locktivity/epack => " + repoRoot + "\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0o644); err != nil {
		return "", err
	}
	sum, err := os.ReadFile(filepath.Join(repoRoot, "go.sum"))
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "go.sum"), sum, 0o644); err != nil {
		return "", err
	}
	// The go commands the package runs see these, as in a collector's own
	// checkout outside any workspace.
	for k, v := range map[string]string{"GOWORK": "off", "GOFLAGS": "-mod=mod"} {
		if err := os.Setenv(k, v); err != nil {
			return "", err
		}
	}
	return dir, nil
}

var fixtureProgram = sync.OnceValues(func() (*program, error) {
	return loadProgram(context.Background(), fixtureDir)
})

// fixtureAnalysis loads the fixture's packages once for every test.
func fixtureAnalysis(t *testing.T) *analysis {
	t.Helper()
	if testing.Short() {
		t.Skip("loads a module, which compiles the SDK")
	}
	prog, err := fixtureProgram()
	if err != nil {
		t.Fatal(err)
	}
	return newAnalysis(prog)
}

// fixtureLines returns the fixture collector's source lines, numbered from 1.
func fixtureLines(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixtureDir, "internal", "collector", "collector.go"))
	if err != nil {
		t.Fatal(err)
	}
	return append([]string{""}, strings.Split(string(data), "\n")...)
}
