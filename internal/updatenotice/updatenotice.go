// Package updatenotice tells a person at a terminal, at most once a day,
// that a newer epack release is out and how to upgrade to it.
package updatenotice

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/locktivity/epack/internal/component/github"
	"github.com/locktivity/epack/internal/component/semver"
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/safefile"
	"github.com/locktivity/epack/internal/safejson"
	"github.com/locktivity/epack/internal/userconfig"
)

// DisableEnvVar turns the notice off when set to any value.
const DisableEnvVar = "EPACK_NO_UPDATE_NOTIFIER"

// StateFileName is the file in the user config directory that records when
// epack last checked for a release and what it found.
const StateFileName = "update-check.json"

const (
	checkInterval  = 24 * time.Hour
	defaultTimeout = 2 * time.Second
	defaultAPIURL  = "https://api.github.com"
	releasesURL    = "https://github.com/locktivity/epack/releases/latest"
)

// Options is what a check needs.
type Options struct {
	// Version is the running epack's version.
	Version string
	// Terminal is set when stderr is a terminal.
	Terminal bool
	// CI is set when the command runs in CI mode.
	CI bool
	// Getenv and Now replace os.Getenv and the clock when set.
	Getenv func(string) string
	Now    func() time.Time
	// StatePath is the state file; empty means StateFileName in the user
	// config directory.
	StatePath string
	// BaseURL is the GitHub API asked for the latest release; empty means
	// api.github.com.
	BaseURL string
	// Executable is the running binary, whose path says how epack was
	// installed; empty means os.Executable.
	Executable string
	// Timeout bounds the check from Start through Wait; zero means two
	// seconds.
	Timeout time.Duration
}

// Check is a check under way. A nil Check is one that did not start.
type Check struct {
	line   chan string
	done   <-chan struct{}
	cancel context.CancelFunc
}

// Start begins a check in the background, or returns nil without touching
// the network or the state file when stderr is not a terminal, the command
// runs in CI, the running build is not a stable release, or DisableEnvVar
// is set. The check never fails or panics; anything that goes wrong leaves
// the notice out.
func Start(ctx context.Context, opts Options) *Check {
	opts = withDefaults(opts)
	if !opts.Terminal || opts.CI || opts.Getenv(DisableEnvVar) != "" {
		return nil
	}
	if _, ok := stableVersion(opts.Version); !ok {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	c := &Check{line: make(chan string, 1), done: ctx.Done(), cancel: cancel}
	go func() {
		defer func() { _ = recover() }()
		c.line <- check(ctx, opts)
	}()
	return c
}

// Wait returns the notice to print, or "" when there is none or the check
// ran out of time. It never waits past the check's timeout.
func (c *Check) Wait() string {
	if c == nil {
		return ""
	}
	defer c.cancel()
	select {
	case line := <-c.line:
		return line
	case <-c.done:
		return ""
	}
}

func withDefaults(opts Options) Options {
	if opts.Getenv == nil {
		opts.Getenv = os.Getenv
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.BaseURL == "" {
		opts.BaseURL = defaultAPIURL
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}
	return opts
}

// state is what the state file records.
type state struct {
	CheckedAt time.Time `json:"checked_at"`
	Latest    string    `json:"latest,omitempty"`
}

// check asks for the latest release when the last check is a day old,
// records what it found, and returns the notice when that release is newer
// than the running one.
func check(ctx context.Context, opts Options) string {
	path := opts.StatePath
	if path == "" {
		dir, err := userconfig.Dir()
		if err != nil {
			return ""
		}
		path = filepath.Join(dir, StateFileName)
	}
	now := opts.Now().UTC()
	last := loadState(path)
	if elapsed := now.Sub(last.CheckedAt); elapsed >= 0 && elapsed < checkInterval {
		return ""
	}
	// The attempt is recorded before the request so a slow or failing one
	// waits out the day like any other. One that cannot be recorded would
	// repeat with every command, so it does not run.
	if saveState(path, state{CheckedAt: now, Latest: last.Latest}) != nil {
		return ""
	}
	latest, ok := latestRelease(ctx, opts.BaseURL)
	if !ok {
		return ""
	}
	_ = saveState(path, state{CheckedAt: now, Latest: latest.Raw})
	return notice(opts, latest)
}

// loadState reads the state file. A missing, unreadable, or corrupt file
// reads as no check yet.
func loadState(path string) state {
	data, err := safefile.ReadFile(path, limits.ConfigFile)
	if err != nil {
		return state{}
	}
	var st state
	if err := safejson.Unmarshal(data, limits.ConfigFile, &st); err != nil {
		return state{}
	}
	return st
}

// saveState writes the state file, readable only by the user.
func saveState(path string, st state) error {
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := safefile.EnsureBaseDir(dir); err != nil {
		return err
	}
	return safefile.WriteFilePrivate(dir, filepath.Base(path), data)
}

// latestRelease asks GitHub, without credentials, for the newest epack
// release. The latest-release endpoint leaves out drafts and prereleases.
func latestRelease(ctx context.Context, baseURL string) (*semver.Version, bool) {
	client, err := github.NewAnonymousClient(baseURL)
	if err != nil {
		return nil, false
	}
	release, err := client.FetchLatestRelease(ctx, "locktivity", "epack")
	if err != nil {
		return nil, false
	}
	return stableVersion(release.TagName)
}

// stableVersion parses a release version. A local build ("dev"), a
// prerelease, or a build between tags is not one.
func stableVersion(v string) (*semver.Version, bool) {
	parsed, err := semver.ParseVersion(v)
	if err != nil || parsed.Prerelease != "" {
		return nil, false
	}
	return parsed, true
}

// notice names latest and how to upgrade to it, or is empty when the
// running release is as new.
func notice(opts Options, latest *semver.Version) string {
	running, ok := stableVersion(opts.Version)
	if !ok || semver.Compare(latest, running) <= 0 {
		return ""
	}
	return fmt.Sprintf("epack %s is available (you have %s). %s", plain(latest), plain(running), upgradeHint(opts.Executable))
}

func plain(v *semver.Version) string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// upgradeHint is how to upgrade this epack: with brew when Homebrew
// installed it, else from the releases page.
func upgradeHint(executable string) string {
	if formula := homebrewFormula(executable); formula != "" {
		return "Upgrade with: brew upgrade " + formula
	}
	return "Download it from: " + releasesURL
}

var formulaPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9@+._-]*$`)

// homebrewFormula names the formula that installed the binary at path.
// Homebrew keeps it at <prefix>/Cellar/<formula>/<version>/bin and links it
// into <prefix>/bin.
func homebrewFormula(path string) string {
	if path == "" {
		exe, err := os.Executable()
		if err != nil {
			return ""
		}
		path = exe
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i := 0; i+3 < len(parts); i++ {
		if parts[i] == "Cellar" && parts[i+3] == "bin" && formulaPattern.MatchString(parts[i+1]) {
			return parts[i+1]
		}
	}
	return ""
}
