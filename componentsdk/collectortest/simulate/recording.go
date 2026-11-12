package simulate

import (
	"cmp"
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk/collectortest"
)

// Recording compares a simulator's answers for the sandbox roster with a
// recording of the sandbox, so the simulator cannot drift from the vendor
// unseen: a field, type, count, or vocabulary value it gets wrong fails in
// the change that brings a new recording.
type Recording struct {
	// Path is the recording. Env, when set in the environment, names
	// another one. The check skips when there is none.
	Path, Env string
	Options   collectortest.CompareOptions
	// Keep picks the responses to compare, such as those from one host.
	// Nil keeps every one.
	Keep func(collectortest.Response) bool
	// Rewrite, when set, rewrites each URL on both sides before they are
	// lined up, such as an object ID in a path, which differs between the
	// sandbox and the simulator.
	Rewrite func(url string) string
	// Known lists, by each difference's String, the ways the simulator is
	// known to differ, with why each is left.
	Known map[string]string
	// Simulate answers for the sandbox roster at the recording's time.
	Simulate func(t *testing.T, recordedAt time.Time) []collectortest.Response
}

// CheckRecording fails on each difference between the recording and the
// simulator that Known does not list, and on each Known entry that no
// longer differs. A call only the simulator answers is left out, since a
// simulator answers the calls of every level and a sandbox records at one.
func CheckRecording(t *testing.T, rec Recording) {
	t.Helper()
	path := rec.Path
	if rec.Env != "" {
		path = cmp.Or(os.Getenv(rec.Env), path)
	}
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		t.Skipf("no recording at %s", path)
	}
	scenario, err := collectortest.LoadScenario(path)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var head struct {
		RecordedAt time.Time `json:"recorded_at"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		t.Fatal(err)
	}
	prepare := func(rs []collectortest.Response) []collectortest.Response {
		var out []collectortest.Response
		for _, r := range rs {
			if rec.Keep != nil && !rec.Keep(r) {
				continue
			}
			if rec.Rewrite != nil {
				r.URL = rec.Rewrite(r.URL)
			}
			out = append(out, r)
		}
		return out
	}
	diffs := collectortest.CompareResponses(prepare(scenario.Responses), prepare(rec.Simulate(t, head.RecordedAt)), rec.Options)
	seen := map[string]bool{}
	for _, d := range diffs {
		if d.Kind == collectortest.OnlySimulated {
			continue
		}
		seen[d.String()] = true
		if why, known := rec.Known[d.String()]; known {
			t.Logf("known: %s (%s)", d, why)
			continue
		}
		t.Errorf("%s", d)
	}
	for _, d := range slices.Sorted(maps.Keys(rec.Known)) {
		if !seen[d] {
			t.Errorf("listed as known, but the simulator now matches the recording: %s", d)
		}
	}
}
