package pack

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/locktivity/epack/internal/ziputil"
)

// FuzzOpen tests the Open function with fuzzed zip archives.
func FuzzOpen(f *testing.F) {
	// Seed with valid pack structures
	f.Add(validPackBytes())
	f.Add(emptyArtifactsPackBytes())
	f.Add(multipleArtifactsPackBytes())

	// Seed with edge cases
	f.Add([]byte{})
	f.Add([]byte("not a zip file"))
	f.Add([]byte{0x50, 0x4B, 0x03, 0x04})

	f.Fuzz(func(t *testing.T, data []byte) {
		tmpDir := t.TempDir()
		tmpFile := filepath.Join(tmpDir, "test.zip")

		if err := os.WriteFile(tmpFile, data, 0644); err != nil {
			return
		}

		pack, err := Open(tmpFile)
		if err != nil {
			return
		}
		defer func() { _ = pack.Close() }()

		for _, artifact := range pack.manifest.Artifacts {
			if artifact.Type == "embedded" {
				_, _ = pack.ReadFileUntrusted(artifact.Path)
			}
		}
	})
}

// FuzzValidatePath tests path validation with fuzzed paths.
func FuzzValidatePath(f *testing.F) {
	f.Add("manifest.json")
	f.Add("artifacts/test.json")
	f.Add("artifacts/subdir/nested/file.json")
	f.Add("")
	f.Add(".")
	f.Add("..")
	f.Add("../etc/passwd")
	f.Add("/etc/passwd")
	f.Add("CON")
	f.Add("file\x00name.txt")

	f.Fuzz(func(t *testing.T, path string) {
		// Should not panic regardless of input
		_ = ziputil.ValidatePath(path)
	})
}

// FuzzReadFileWithLimits tests the limit enforcement.
func FuzzReadFileWithLimits(f *testing.F) {
	f.Add([]byte("hello"), int64(100), int64(100))
	f.Add([]byte("hello world"), int64(5), int64(100))
	f.Add([]byte("hello world"), int64(100), int64(5))
	f.Add([]byte{}, int64(0), int64(0))
	f.Add(bytes.Repeat([]byte("x"), 1000), int64(500), int64(500))

	f.Fuzz(func(t *testing.T, content []byte, artifactLimit, packLimit int64) {
		if artifactLimit < 0 || packLimit < 0 {
			return
		}

		var buf bytes.Buffer
		w := zip.NewWriter(&buf)
		fw, _ := w.Create("test.txt")
		_, _ = fw.Write(content)
		_ = w.Close()

		r, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
		if err != nil || len(r.File) == 0 {
			return
		}

		_, _ = readFileWithLimits(r.File[0], artifactLimit, packLimit)
	})
}

// FuzzIndexZip tests zip indexing with fuzzed file names.
func FuzzIndexZip(f *testing.F) {
	f.Add("file.txt", "artifacts/data.json")
	f.Add("../escape", "normal.txt")
	f.Add("/absolute", "relative")
	f.Add("", "valid.txt")
	f.Add("CON", "PRN")

	f.Fuzz(func(t *testing.T, name1, name2 string) {
		var buf bytes.Buffer
		w := zip.NewWriter(&buf)

		if name1 != "" {
			if fw, err := w.Create(name1); err == nil {
				_, _ = fw.Write([]byte("content1"))
			}
		}
		if name2 != "" {
			if fw, err := w.Create(name2); err == nil {
				_, _ = fw.Write([]byte("content2"))
			}
		}

		_ = w.Close()

		r, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
		if err != nil {
			return
		}

		_, _ = indexZip(r)
	})
}

func validPackBytes() []byte {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	size := json.Number("100")
	manifest := Manifest{
		SpecVersion: "1.0",
		Stream:      "test-stream",
		GeneratedAt: "2024-01-15T10:30:00Z",
		PackDigest:  "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		Sources:     []Source{{Name: "test", Version: "1.0.0"}},
		Artifacts: []Artifact{{
			Type:   "embedded",
			Path:   "artifacts/test.json",
			Digest: "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			Size:   &size,
		}},
	}

	manifestData, _ := json.Marshal(manifest)
	fw, _ := w.Create("manifest.json")
	_, _ = fw.Write(manifestData)

	fw, _ = w.Create("artifacts/test.json")
	_, _ = fw.Write([]byte(`{"test": "data"}`))

	_ = w.Close()
	return buf.Bytes()
}

func emptyArtifactsPackBytes() []byte {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	manifest := Manifest{
		SpecVersion: "1.0",
		Stream:      "test-stream",
		GeneratedAt: "2024-01-15T10:30:00Z",
		PackDigest:  "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		Sources:     []Source{{Name: "test", Version: "1.0.0"}},
		Artifacts:   []Artifact{},
	}

	manifestData, _ := json.Marshal(manifest)
	fw, _ := w.Create("manifest.json")
	_, _ = fw.Write(manifestData)

	_, _ = w.Create("artifacts/")

	_ = w.Close()
	return buf.Bytes()
}

func multipleArtifactsPackBytes() []byte {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	size := json.Number("50")
	manifest := Manifest{
		SpecVersion: "1.0",
		Stream:      "test-stream",
		GeneratedAt: "2024-01-15T10:30:00Z",
		PackDigest:  "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		Sources:     []Source{{Name: "test", Version: "1.0.0"}},
		Artifacts: []Artifact{
			{
				Type:   "embedded",
				Path:   "artifacts/one.json",
				Digest: "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
				Size:   &size,
			},
			{
				Type:   "embedded",
				Path:   "artifacts/two.json",
				Digest: "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
				Size:   &size,
			},
		},
	}

	manifestData, _ := json.Marshal(manifest)
	fw, _ := w.Create("manifest.json")
	_, _ = fw.Write(manifestData)

	fw, _ = w.Create("artifacts/one.json")
	_, _ = fw.Write([]byte(`{"id": 1}`))

	fw, _ = w.Create("artifacts/two.json")
	_, _ = fw.Write([]byte(`{"id": 2}`))

	_ = w.Close()
	return buf.Bytes()
}
