package shadow

import (
	"reflect"
	"testing"
)

func TestThreeWay(t *testing.T) {
	runs := trio[map[string]int]{
		Locked1:   map[string]int{"same": 1, "changed": 1, "removed": 1, "flaky": 1, "only1": 1, "only1b": 1},
		Locked2:   map[string]int{"same": 1, "changed": 1, "removed": 1, "flaky": 2, "only2": 1},
		Candidate: map[string]int{"same": 1, "changed": 2, "added": 1, "flaky": 1, "only1b": 1},
	}
	equal := func(a, b int) bool { return a == b }
	want := map[string]verdict{
		"same": kept, "changed": changed, "removed": removed, "added": added,
		"flaky": noisy, "only1": noisy, "only1b": noisy, "only2": noisy,
	}
	if got := threeWay(runs, equal); !reflect.DeepEqual(got, want) {
		t.Errorf("threeWay = %v, want %v", got, want)
	}
	// Without same, only presence counts.
	want["changed"], want["flaky"] = kept, kept
	if got := threeWay(runs, nil); !reflect.DeepEqual(got, want) {
		t.Errorf("threeWay by presence = %v, want %v", got, want)
	}
}

func TestTrioInRunOrder(t *testing.T) {
	names := trio[string]{Locked1: "locked-1", Locked2: "locked-2", Candidate: "candidate"}
	var got []string
	for _, name := range names.inRunOrder() {
		got = append(got, *name)
	}
	if want := []string{"locked-1", "candidate", "locked-2"}; !reflect.DeepEqual(got, want) {
		t.Errorf("run order = %v, want %v", got, want)
	}
	lengths := mapTrio(names, func(s string) int { return len(s) })
	if want := (trio[int]{Locked1: 8, Locked2: 8, Candidate: 9}); lengths != want {
		t.Errorf("mapTrio = %+v, want %+v", lengths, want)
	}
}
