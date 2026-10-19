package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/safefile"
)

// indexFile is the index collectortest writes beside the scenario
// directories.
const indexFile = "scenarios.json"

// tree is a COLLECTORTEST_OUT directory: <suite>/<scenario>/ holds the files
// one scenario run wrote, its artifacts at their pack paths under
// artifacts/.
type tree struct {
	scenarios map[string]*scenario
	// schemas maps a scenario's key, then an artifact's pack path, to the
	// artifact's schema, as the index gives it. A path the index lists with
	// an empty schema maps to "": the collector emitted it with none.
	schemas map[string]map[string]string
}

type scenario struct {
	suite string
	name  string
	// files holds each file's bytes by its slash-separated path within the
	// scenario directory.
	files map[string][]byte
}

func (s *scenario) key() string { return s.suite + "/" + s.name }

func loadTree(dir string) (*tree, error) {
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}
	t := &tree{scenarios: map[string]*scenario{}, schemas: map[string]map[string]string{}}
	if err := t.readIndex(root, ""); err != nil {
		return nil, err
	}
	suites, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	for _, suite := range suites {
		if !suite.IsDir() {
			continue
		}
		suiteDir := filepath.Join(root, suite.Name())
		if err := t.readIndex(suiteDir, suite.Name()); err != nil {
			return nil, err
		}
		entries, err := os.ReadDir(suiteDir)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			files, err := readFiles(filepath.Join(suiteDir, entry.Name()))
			if err != nil {
				return nil, err
			}
			sc := &scenario{suite: suite.Name(), name: entry.Name(), files: files}
			t.scenarios[sc.key()] = sc
		}
	}
	return t, nil
}

// readFiles reads every regular file under dir. Symlinks are left out, as
// collectortest writes none.
func readFiles(dir string) (map[string][]byte, error) {
	files := map[string][]byte{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		data, err := safefile.ReadFileBeneath(dir, rel, limits.Artifact)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		files[filepath.ToSlash(rel)] = data
		return nil
	})
	return files, err
}

// readIndex takes artifact schemas from dir's index, if it has one, where
// dir is the tree's root or, with suite set, that suite's directory. The
// pack builder needs them, since the validator matches a requirement to the
// artifacts whose manifest entry carries its schema. Any object in the index
// with string "path" and "schema" members counts, wherever it sits, as long
// as its scenario can be told: from a path given relative to the tree or the
// suite, or else from the "dir" or "scenario" of an enclosing object, and in
// the root index its suite from an enclosing "suite".
func (t *tree) readIndex(dir, suite string) error {
	data, err := safefile.ReadFileBeneath(dir, indexFile, limits.JSONResponse)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading %s: %w", filepath.Join(dir, indexFile), err)
	}
	var index any
	if err := json.Unmarshal(data, &index); err != nil {
		return fmt.Errorf("reading %s: %w", filepath.Join(dir, indexFile), err)
	}
	t.collectSchemas(index, indexScope{suite: suite})
	return nil
}

// indexScope is where in a tree an index entry sits: the suite whose index
// holds it, or else the one an enclosing object names, and the scenario
// directory an enclosing object names.
type indexScope struct {
	suite, scenario string
}

func (t *tree) collectSchemas(v any, at indexScope) {
	switch v := v.(type) {
	case map[string]any:
		if suite, ok := v["suite"].(string); ok && at.suite == "" {
			at.suite = suite
		}
		for _, key := range []string{"scenario", "dir"} {
			if dir, ok := v[key].(string); ok && dir != "" {
				at.scenario = dir
			}
		}
		path, _ := v["path"].(string)
		if schema, listed := v["schema"].(string); listed {
			if key, pack := at.locate(path); key != "" {
				t.noteSchema(key, pack, schema)
			}
		}
		for _, key := range sortedKeys(v) {
			t.collectSchemas(v[key], at)
		}
	case []any:
		for _, item := range v {
			t.collectSchemas(item, at)
		}
	}
}

// locate returns the key of the scenario an index path belongs to and the
// path within its pack. The path may be given relative to the scenario
// directory, the suite's, or the tree; the scope fills in what it leaves
// out. It returns "" when the scenario cannot be told.
func (at indexScope) locate(path string) (key, pack string) {
	path = filepath.ToSlash(path)
	var dirs []string
	if !strings.HasPrefix(path, "artifacts/") {
		i := strings.Index(path, "/artifacts/")
		if i < 0 {
			return "", ""
		}
		dirs, path = strings.Split(path[:i], "/"), path[i+1:]
	}
	suite, scenario := at.suite, at.scenario
	switch len(dirs) {
	case 0:
	case 1:
		scenario = dirs[0]
	case 2:
		suite, scenario = dirs[0], dirs[1]
	default:
		return "", ""
	}
	if suite == "" || scenario == "" {
		return "", ""
	}
	return suite + "/" + scenario, path
}

// noteSchema records an artifact's schema in a scenario, keeping one the
// index already gave over an empty one.
func (t *tree) noteSchema(key, path, schema string) {
	byPath := t.schemas[key]
	if byPath == nil {
		byPath = map[string]string{}
		t.schemas[key] = byPath
	}
	if prior, seen := byPath[path]; !seen || prior == "" {
		byPath[path] = schema
	}
}

// schema returns the schema of the artifact at path in the scenario with
// key from t's index, or from other's when t's does not list the path for
// that scenario. A path t's index lists with an empty schema has none,
// whatever other's says, so the controls that read an artifact whose schema
// the head dropped show the change rather than passing on the base's
// schema. Each scenario stands alone: another scenario's schema for the
// same path never applies.
func (t *tree) schema(key, path string, other *tree) string {
	if s, listed := t.schemas[key][path]; listed {
		return s
	}
	return other.schemas[key][path]
}

// hasSchema reports whether t's index gives any artifact a schema.
func (t *tree) hasSchema() bool {
	for _, byPath := range t.schemas {
		for _, s := range byPath {
			if s != "" {
				return true
			}
		}
	}
	return false
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
