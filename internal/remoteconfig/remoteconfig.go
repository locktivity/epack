// Package remoteconfig writes a configuration pulled from a remote into a
// folder and records what it wrote, so the next pull can tell the remote's
// changes from the person's own edits.
package remoteconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/remote"
	"github.com/locktivity/epack/internal/safefile"
)

// StateFile records, inside the folder, where the files came from and the
// digest of each managed file as written.
const StateFile = ".epack/remote-config.json"

// State is the record of the last pull into a folder. Files holds the
// digest of each managed file as written. Templates holds the digest of each
// file the person owns as the remote delivered it: a file still matching its
// template is the remote's, not the person's.
type State struct {
	Remote    string            `json:"remote"`
	ID        string            `json:"id,omitempty"`
	Name      string            `json:"name"`
	Title     string            `json:"title,omitempty"`
	Stream    string            `json:"stream,omitempty"`
	RunsIn    string            `json:"runs_in,omitempty"`
	Revision  int               `json:"revision"`
	PulledAt  string            `json:"pulled_at"`
	Files     map[string]string `json:"files"`
	Templates map[string]string `json:"templates,omitempty"`
}

// Options controls where and how a configuration is written.
type Options struct {
	// Dir is the folder to write into. Empty means a folder named after the
	// configuration under the working directory.
	Dir string
	// Force overwrites files the person has edited and writes into folders
	// that no pull created.
	Force bool
	// Now is the clock for the pull timestamp; nil means time.Now.
	Now func() time.Time
	// FilesDir is the hidden folder the remote declared for its own files
	// in its capabilities; empty means a pull may carry none.
	FilesDir string
}

// Result describes what a pull wrote.
type Result struct {
	Dir     string
	State   *State
	Created bool
	Written []string
	Kept    []string
}

// Current reports whether the folder already matched the revision.
func (r *Result) Current() bool {
	return len(r.Written) == 0
}

// LocalChangesError lists managed files edited since the last pull that the
// new revision would overwrite.
type LocalChangesError struct {
	Paths []string
}

func (e *LocalChangesError) Error() string {
	return fmt.Sprintf("local changes in %s would be overwritten (pass --force to replace them)", strings.Join(e.Paths, ", "))
}

// ErrNotCloned means the folder has files but no record of a pull.
var ErrNotCloned = errors.New("folder already has files and no record of a pull (pass --force to write into it anyway)")

type entry struct {
	path    string
	data    []byte
	managed bool
}

// Write puts the configuration's files into the folder and records them.
// Managed files are replaced when they still match the previous pull and
// refused when the person changed them. Files the person owns follow the
// remote's template until the person edits them, and are then left alone.
func Write(cfg remote.ConfigPullResult, remoteName string, opts Options) (*Result, error) {
	dir, err := targetDir(cfg, opts)
	if err != nil {
		return nil, err
	}
	entries, err := planEntries(dir, cfg, opts.FilesDir)
	if err != nil {
		return nil, err
	}
	prev, err := LoadState(dir)
	if err != nil {
		return nil, err
	}
	if prev == nil && !opts.Force {
		occupied, err := hasFiles(dir)
		if err != nil {
			return nil, err
		}
		if occupied {
			return nil, ErrNotCloned
		}
	}
	toWrite, kept, err := decide(dir, entries, prev, opts.Force)
	if err != nil {
		return nil, err
	}
	if err := safefile.EnsureBaseDir(dir); err != nil {
		return nil, fmt.Errorf("creating %s: %w", dir, err)
	}
	written := make([]string, 0, len(toWrite))
	for _, e := range toWrite {
		if err := safefile.WriteFile(dir, e.path, e.data); err != nil {
			return nil, fmt.Errorf("writing %s: %w", e.path, err)
		}
		written = append(written, e.path)
	}
	state := buildState(cfg, remoteName, entries, opts)
	if err := safefile.WriteJSON(dir, StateFile, state); err != nil {
		return nil, fmt.Errorf("recording the pull: %w", err)
	}
	return &Result{Dir: dir, State: state, Created: prev == nil, Written: written, Kept: kept}, nil
}

// LoadState reads the record of the last pull, or nil when there is none.
func LoadState(dir string) (*State, error) {
	if _, err := os.Lstat(filepath.Join(dir, StateFile)); os.IsNotExist(err) {
		return nil, nil
	}
	data, err := safefile.ReadFileBeneath(dir, StateFile, limits.ConfigFile)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", StateFile, err)
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", StateFile, err)
	}
	return &state, nil
}

// MaxFolderNameLength bounds a configuration name used as a folder.
const MaxFolderNameLength = 128

// ValidateFolderName accepts one plain path segment: no separators, no
// hidden or relative names, no control characters.
func ValidateFolderName(name string) error {
	switch {
	case name == "":
		return errors.New("a configuration name is needed, as in northwind-production")
	case len(name) > MaxFolderNameLength:
		return fmt.Errorf("configuration name %q is longer than %d characters", name, MaxFolderNameLength)
	case strings.HasPrefix(name, "."):
		return fmt.Errorf("configuration name %q cannot start with a dot", name)
	case strings.ContainsAny(name, `/\`):
		return fmt.Errorf("configuration name %q cannot contain path separators", name)
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return fmt.Errorf("configuration name %q contains control characters", name)
		}
	}
	return nil
}

func targetDir(cfg remote.ConfigPullResult, opts Options) (string, error) {
	dir := opts.Dir
	if dir == "" {
		if err := ValidateFolderName(cfg.Name); err != nil {
			return "", err
		}
		dir = cfg.Name
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	if info, err := os.Lstat(abs); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("refusing to write into %s: it is a symlink", dir)
	}
	return abs, nil
}

// allowedPath keeps a pulled configuration to what a project is made of.
// Hidden paths are refused except the folder the remote declared for its
// own files and the hook scripts, so a remote cannot plant files where
// sync, git, or a shell would pick them up as something already trusted.
func allowedPath(path, filesDir string) bool {
	segments := strings.Split(filepath.ToSlash(filepath.Clean(path)), "/")
	if !anyHidden(segments) {
		return true
	}
	if filesDir != "" && segments[0] == filesDir && len(segments) > 1 && !anyHidden(segments[1:]) {
		return true
	}
	return len(segments) == 3 && segments[0] == ".epack" && segments[1] == "hooks" &&
		strings.HasSuffix(segments[2], ".sh") && !strings.HasPrefix(segments[2], ".")
}

// HiddenPathError is a pulled file at a hidden path the remote may not
// write. FilesDir is the folder the remote declared, empty when it declared
// none, which is how an adapter from before files_dir looks.
type HiddenPathError struct {
	Path     string
	FilesDir string
}

func (e *HiddenPathError) Error() string {
	return fmt.Sprintf("configuration file %q is not a path epack writes: hidden paths other than %s.epack/hooks/*.sh are refused", e.Path, filesDirHint(e.FilesDir))
}

func filesDirHint(filesDir string) string {
	if filesDir == "" {
		return ""
	}
	return filesDir + "/ and "
}

func anyHidden(segments []string) bool {
	for _, segment := range segments {
		if strings.HasPrefix(segment, ".") {
			return true
		}
	}
	return false
}

func hasControlCharacters(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func planEntries(dir string, cfg remote.ConfigPullResult, filesDir string) ([]entry, error) {
	managedAll := len(cfg.Shas) == 0
	entries := make([]entry, 0, len(cfg.Files)+1)
	for path, content := range cfg.Files {
		_, managed := cfg.Shas[path]
		entries = append(entries, entry{path: path, data: []byte(content), managed: managed || managedAll})
	}
	if _, listed := cfg.Files[lockfile.FileName]; cfg.Lockfile != "" && !listed {
		entries = append(entries, entry{path: lockfile.FileName, data: []byte(cfg.Lockfile), managed: true})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })
	for _, e := range entries {
		if e.path == "" || strings.HasSuffix(e.path, "/") || hasControlCharacters(e.path) {
			return nil, fmt.Errorf("configuration file path %q is not allowed", e.path)
		}
		if _, err := safefile.ValidatePath(dir, e.path); err != nil {
			return nil, fmt.Errorf("configuration file %q: %w", e.path, err)
		}
		if !allowedPath(e.path, filesDir) {
			return nil, &HiddenPathError{Path: e.path, FilesDir: filesDir}
		}
	}
	return entries, nil
}

func decide(dir string, entries []entry, prev *State, force bool) (toWrite []entry, kept []string, err error) {
	var changed []string
	for _, e := range entries {
		local, exists, err := readLocal(filepath.Join(dir, e.path))
		if err != nil {
			return nil, nil, err
		}
		switch {
		case !exists:
			toWrite = append(toWrite, e)
		case bytes.Equal(local, e.data):
			kept = append(kept, e.path)
		case !e.managed:
			if templateMatches(prev, e.path, local) {
				toWrite = append(toWrite, e)
			} else {
				kept = append(kept, e.path)
			}
		case force || recordedMatches(prev, e.path, local):
			toWrite = append(toWrite, e)
		default:
			changed = append(changed, e.path)
		}
	}
	if len(changed) > 0 {
		return nil, nil, &LocalChangesError{Paths: changed}
	}
	return toWrite, kept, nil
}

func readLocal(path string) ([]byte, bool, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("reading %s: %w", path, err)
	}
	return data, true, nil
}

func recordedMatches(prev *State, path string, local []byte) bool {
	if prev == nil {
		return false
	}
	recorded, ok := prev.Files[path]
	return ok && recorded == digest(local)
}

func templateMatches(prev *State, path string, local []byte) bool {
	if prev == nil {
		return false
	}
	delivered, ok := prev.Templates[path]
	return ok && delivered == digest(local)
}

// IsRemoteTemplate reports whether the file at relPath still matches the
// version the remote delivered, which makes it the remote's file rather than
// the person's. A folder with no pull record has no templates.
func IsRemoteTemplate(dir, relPath string) (bool, error) {
	state, err := LoadState(dir)
	if err != nil || state == nil {
		return false, err
	}
	delivered, ok := state.Templates[relPath]
	if !ok {
		return false, nil
	}
	local, exists, err := readLocal(filepath.Join(dir, relPath))
	if err != nil || !exists {
		return false, err
	}
	return delivered == digest(local), nil
}

func hasFiles(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return len(entries) > 0, nil
}

func buildState(cfg remote.ConfigPullResult, remoteName string, entries []entry, opts Options) *State {
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	files := make(map[string]string)
	templates := make(map[string]string)
	for _, e := range entries {
		if e.managed {
			files[e.path] = digest(e.data)
		} else {
			templates[e.path] = digest(e.data)
		}
	}
	return &State{
		Remote:    remoteName,
		ID:        cfg.ID,
		Name:      cfg.Name,
		Title:     cfg.Title,
		Stream:    cfg.Stream,
		RunsIn:    cfg.RunsIn,
		Revision:  cfg.Revision,
		PulledAt:  now().UTC().Format(time.RFC3339),
		Files:     files,
		Templates: templates,
	}
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
