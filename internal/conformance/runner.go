package conformance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// getVectorBasePath returns the absolute path to the test vectors directory.
// It locates the path relative to this source file, which works regardless
// of the current working directory when tests are run.
func getVectorBasePath() string {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		// Fallback to relative path
		return "../evidence-pack/test-vectors"
	}
	// Go from conformance/runner.go -> epack -> evidence-pack/test-vectors
	dir := filepath.Dir(currentFile)      // conformance/
	moduleRoot := filepath.Dir(dir)       // epack/
	parentDir := filepath.Dir(moduleRoot) // apps/
	return filepath.Join(parentDir, "evidence-pack", "test-vectors")
}

// VectorsAvailable returns true if the test vectors directory exists.
func VectorsAvailable() bool {
	_, err := os.Stat(getVectorBasePath())
	return err == nil
}

// SkipIfNoVectors skips the test if the test vectors directory is not available.
func SkipIfNoVectors(t *testing.T) {
	t.Helper()
	if !VectorsAvailable() {
		t.Skip("test vectors not available (../evidence-pack/test-vectors not found)")
	}
}

// LoadVector loads and unmarshals a JSON test vector file.
func LoadVector[T any](category, filename string) (*T, error) {
	path := filepath.Join(getVectorBasePath(), category, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// LoadVectorRaw loads a test vector file as raw JSON.
func LoadVectorRaw(category, filename string) (json.RawMessage, error) {
	path := filepath.Join(getVectorBasePath(), category, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(data), nil
}

// ListVectorFiles returns all JSON files in a vector category directory.
func ListVectorFiles(category string) ([]string, error) {
	dir := filepath.Join(getVectorBasePath(), category)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			files = append(files, e.Name())
		}
	}
	return files, nil
}

// VectorPath returns the full path to a vector file.
func VectorPath(category, filename string) string {
	return filepath.Join(getVectorBasePath(), category, filename)
}

// FixturePath returns the full path to a fixture file referenced by a vector.
func FixturePath(category, fixturePath string) string {
	return filepath.Join(getVectorBasePath(), category, fixturePath)
}
