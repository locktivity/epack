package updatenotice

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

var start = time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)

const releasesNotice = "epack 0.6.0 is available (you have 0.5.1). Download it from: https://github.com/locktivity/epack/releases/latest"

type releaseServer struct {
	*httptest.Server
	hits          atomic.Int32
	authorization atomic.Value
}

// newReleaseServer answers the latest-release request with tag.
func newReleaseServer(t *testing.T, tag string) *releaseServer {
	t.Helper()
	s := &releaseServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		s.authorization.Store(r.Header.Get("Authorization"))
		if r.URL.Path != "/repos/locktivity/epack/releases/latest" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"tag_name": %q, "assets": []}`, tag)
	}))
	t.Cleanup(s.Close)
	return s
}

func testOptions(t *testing.T, baseURL string) Options {
	t.Helper()
	return Options{
		Version:    "0.5.1",
		Terminal:   true,
		Getenv:     func(string) string { return "" },
		Now:        func() time.Time { return start },
		StatePath:  filepath.Join(t.TempDir(), ".epack", StateFileName),
		BaseURL:    baseURL,
		Executable: filepath.Join(t.TempDir(), "bin", "epack"),
		Timeout:    5 * time.Second,
	}
}

func at(opts Options, later time.Duration) Options {
	opts.Now = func() time.Time { return start.Add(later) }
	return opts
}

func run(opts Options) string {
	return Start(context.Background(), opts).Wait()
}

func TestStart_SilentWithNoRequestWhenTheNoticeDoesNotApply(t *testing.T) {
	server := newReleaseServer(t, "v0.6.0")
	cases := map[string]func(*Options){
		"in CI":                    func(o *Options) { o.CI = true },
		"stderr is not a terminal": func(o *Options) { o.Terminal = false },
		"opted out": func(o *Options) {
			o.Getenv = func(name string) string {
				if name == DisableEnvVar {
					return "1"
				}
				return ""
			}
		},
		"dev build":          func(o *Options) { o.Version = "dev" },
		"no version":         func(o *Options) { o.Version = "" },
		"not a version":      func(o *Options) { o.Version = "unknown" },
		"build between tags": func(o *Options) { o.Version = "0.5.1-3-gabc1234" },
		"dirty build":        func(o *Options) { o.Version = "0.5.1-dirty" },
		"prerelease":         func(o *Options) { o.Version = "0.6.0-rc.1" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			opts := testOptions(t, server.URL)
			change(&opts)
			if check := Start(context.Background(), opts); check != nil {
				t.Errorf("a check started: %q", check.Wait())
			}
			if _, err := os.Stat(opts.StatePath); !os.IsNotExist(err) {
				t.Errorf("state file should be untouched, stat err = %v", err)
			}
		})
	}
	if n := server.hits.Load(); n != 0 {
		t.Errorf("requests = %d, want none", n)
	}
}

func TestWait_NamesTheNewerReleaseAndHowToUpgrade(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ghp_example")
	server := newReleaseServer(t, "v0.6.0")

	opts := testOptions(t, server.URL)
	if got := run(opts); got != releasesNotice {
		t.Errorf("notice = %q\nwant     %q", got, releasesNotice)
	}
	if n := server.hits.Load(); n != 1 {
		t.Errorf("requests = %d, want 1", n)
	}
	if auth := server.authorization.Load(); auth != "" {
		t.Errorf("Authorization = %q, want none", auth)
	}
	st := loadState(opts.StatePath)
	if !st.CheckedAt.Equal(start) || st.Latest != "v0.6.0" {
		t.Errorf("state = %+v, want checked at %s finding v0.6.0", st, start)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(opts.StatePath)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("state file mode = %o, want 600", perm)
		}
	}

	brew := testOptions(t, server.URL)
	brew.Version = "v0.5.1"
	brew.Executable = filepath.Join(t.TempDir(), "Cellar", "epack", "0.5.1", "bin", "epack")
	if got, want := run(brew), "epack 0.6.0 is available (you have 0.5.1). Upgrade with: brew upgrade epack"; got != want {
		t.Errorf("Homebrew notice = %q\nwant              %q", got, want)
	}
}

func TestWait_SilentWhenTheLatestReleaseIsNotNewer(t *testing.T) {
	for _, tag := range []string{"v0.5.1", "0.5.1", "v0.5.0", "v0.4.9"} {
		t.Run(tag, func(t *testing.T) {
			server := newReleaseServer(t, tag)
			opts := testOptions(t, server.URL)
			if got := run(opts); got != "" {
				t.Errorf("notice = %q, want none", got)
			}
			if n := server.hits.Load(); n != 1 {
				t.Errorf("requests = %d, want 1", n)
			}
		})
	}
}

func TestWait_ChecksAtMostOnceADay(t *testing.T) {
	server := newReleaseServer(t, "v0.6.0")
	opts := testOptions(t, server.URL)

	if got := run(opts); got != releasesNotice {
		t.Fatalf("first notice = %q", got)
	}
	if got := run(at(opts, 23*time.Hour)); got != "" {
		t.Errorf("a run within the day printed %q", got)
	}
	if n := server.hits.Load(); n != 1 {
		t.Errorf("requests within the day = %d, want 1", n)
	}
	if got := run(at(opts, 25*time.Hour)); got != releasesNotice {
		t.Errorf("a run the next day printed %q", got)
	}
	if n := server.hits.Load(); n != 2 {
		t.Errorf("requests by the next day = %d, want 2", n)
	}
}

func TestWait_FailingOrSlowServerPrintsNothingWithinTheTimeout(t *testing.T) {
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer failing.Close()
	released := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-released:
		}
	}))
	defer slow.Close()
	defer close(released)
	garbled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name": `))
	}))
	defer garbled.Close()

	servers := map[string]string{"failing": failing.URL, "slow": slow.URL, "garbled": garbled.URL}
	for name, url := range servers {
		t.Run(name, func(t *testing.T) {
			opts := testOptions(t, url)
			opts.Timeout = 300 * time.Millisecond
			began := time.Now()
			if got := run(opts); got != "" {
				t.Errorf("notice = %q, want none", got)
			}
			if waited := time.Since(began); waited > 3*time.Second {
				t.Errorf("waited %s for a %s check", waited, opts.Timeout)
			}
			if st := loadState(opts.StatePath); !st.CheckedAt.Equal(start) {
				t.Errorf("the attempt should be recorded so the day passes without another: %+v", st)
			}
		})
	}
}

func TestCheck_ToleratesABadStateFile(t *testing.T) {
	server := newReleaseServer(t, "v0.6.0")

	corrupt := testOptions(t, server.URL)
	writeState(t, corrupt.StatePath, "{not json")
	if got := run(corrupt); got != releasesNotice {
		t.Errorf("a corrupt state file should read as no check yet; notice = %q", got)
	}

	future := testOptions(t, server.URL)
	writeState(t, future.StatePath, `{"checked_at": "2026-10-20T09:00:00Z"}`)
	if got := run(future); got != releasesNotice {
		t.Errorf("a check recorded after now should not hold off the next; notice = %q", got)
	}

	blocked := testOptions(t, server.URL)
	if err := os.MkdirAll(blocked.StatePath, 0o700); err != nil {
		t.Fatal(err)
	}
	before := server.hits.Load()
	if got := run(blocked); got != "" {
		t.Errorf("notice = %q, want none", got)
	}
	if server.hits.Load() != before {
		t.Error("a check that cannot be recorded should make no request")
	}
}

func writeState(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestHomebrewFormula(t *testing.T) {
	cases := map[string]string{
		"/opt/homebrew/Cellar/epack/0.5.1/bin/epack":                        "epack",
		"/home/linuxbrew/.linuxbrew/Cellar/epack-core/0.5.1/bin/epack-core": "epack-core",
		"/usr/local/bin/epack":                                              "",
		"/Users/dana/Cellar/epack":                                          "",
		"/opt/homebrew/Cellar/Not A Formula/0.5.1/bin/epack":                "",
	}
	for path, want := range cases {
		if got := homebrewFormula(path); got != want {
			t.Errorf("homebrewFormula(%q) = %q, want %q", path, got, want)
		}
	}

	if runtime.GOOS == "windows" {
		return
	}
	prefix := t.TempDir()
	keg := filepath.Join(prefix, "Cellar", "epack", "0.5.1", "bin")
	if err := os.MkdirAll(keg, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keg, "epack"), nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(prefix, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(prefix, "bin", "epack")
	if err := os.Symlink(filepath.Join("..", "Cellar", "epack", "0.5.1", "bin", "epack"), link); err != nil {
		t.Fatal(err)
	}
	if got := homebrewFormula(link); got != "epack" {
		t.Errorf("homebrewFormula through the bin link = %q, want epack", got)
	}
}
