package surface

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/safefile"
)

// Call is one request a recording holds.
type Call struct {
	Scenario  string
	Operation string
	Method    string
	URL       string
}

// recordingFile is the part of a collectortest recording the surface check
// reads. Other fields are ignored, so the kit's format can grow.
type recordingFile struct {
	Name      string `json:"name"`
	Responses []struct {
		Operation string `json:"operation"`
		Method    string `json:"method"`
		URL       string `json:"url"`
	} `json:"responses"`
}

// LoadCalls reads every recording in dir, a directory beneath root.
func LoadCalls(root, dir string) ([]Call, error) {
	entries, err := os.ReadDir(filepath.Join(root, dir))
	if err != nil {
		return nil, err
	}
	var calls []Call
	var files []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			files = append(files, entry.Name())
		}
	}
	sort.Strings(files)
	for _, name := range files {
		rel := filepath.Join(dir, name)
		data, err := safefile.ReadFileBeneath(root, rel, limits.Artifact)
		if err != nil {
			return nil, err
		}
		var rec recordingFile
		if err := json.Unmarshal(data, &rec); err != nil {
			return nil, fmt.Errorf("%s: %w", rel, err)
		}
		scenario := rec.Name
		if scenario == "" {
			scenario = strings.TrimSuffix(name, ".json")
		}
		for _, r := range rec.Responses {
			method := r.Method
			if method == "" {
				method = "GET"
			}
			calls = append(calls, Call{Scenario: scenario, Operation: r.Operation, Method: method, URL: r.URL})
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%s holds no recordings", dir)
	}
	return calls, nil
}
