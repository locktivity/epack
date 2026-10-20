package tracemap

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// source reads the module's files for the text of the lines a map names.
type source struct {
	root  string
	files map[string][]string
}

func newSource(root string) *source {
	return &source{root: root, files: map[string][]string{}}
}

// line returns the text of a line, named as file:line relative to the
// module root, without its line ending.
func (s *source) line(ref string) (string, error) {
	file, n, ok := SplitLine(ref)
	if !ok {
		return "", fmt.Errorf("%q is not file:line", ref)
	}
	lines, ok := s.files[file]
	if !ok {
		path := filepath.Join(s.root, filepath.FromSlash(file))
		if rel, err := filepath.Rel(s.root, path); err != nil || strings.HasPrefix(rel, "..") {
			return "", fmt.Errorf("%s is outside the module", file)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("reading %s: %w", file, err)
		}
		lines = strings.Split(string(data), "\n")
		s.files[file] = lines
	}
	if n > len(lines) {
		return "", fmt.Errorf("%s has no line %d", file, n)
	}
	return strings.TrimSuffix(lines[n-1], "\r"), nil
}

// gapLines merges the gap sources every suite recorded for a field, as the
// lines the field lists, and adds their text to lines. A source that names
// no line of the module fails, since the SDK names each one relative to the
// module root and the map could not show it.
func gapLines(traces []*FieldTrace, src *source, lines Lines) ([]string, error) {
	var refs []string
	for _, ft := range traces {
		for _, ref := range ft.Gaps {
			refs = addString(refs, ref)
		}
	}
	for _, ref := range refs {
		text, err := src.line(ref)
		if err != nil {
			return nil, fmt.Errorf("gap source %s: %w", ref, err)
		}
		lines[ref] = text
	}
	sort.Slice(refs, func(i, j int) bool { return lineLess(refs[i], refs[j]) })
	return refs, nil
}
