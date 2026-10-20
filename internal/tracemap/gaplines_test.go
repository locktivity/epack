package tracemap

import (
	"reflect"
	"strings"
	"testing"
)

func TestGapLinesMergeSuitesAndCarryTheirText(t *testing.T) {
	src := newSource(fixtureDir)
	lines := Lines{}
	refs, err := gapLines([]*FieldTrace{
		{Gaps: []string{"internal/collector/gaps.go:12", "internal/collector/collector.go:9"}},
		{Gaps: []string{"internal/collector/gaps.go:12"}},
		{},
	}, src, lines)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"internal/collector/collector.go:9", "internal/collector/gaps.go:12"}; !reflect.DeepEqual(refs, want) {
		t.Errorf("gap lines = %v, want %v, each once", refs, want)
	}
	if got := lines["internal/collector/gaps.go:12"]; !strings.Contains(got, "l.rec.NotCollected(") {
		t.Errorf("gap line text = %q", got)
	}
	for _, bad := range []string{"internal/collector/gaps.go:999", "internal/collector/missing.go:1", "../outside.go:1", "gaps.go"} {
		if _, err := gapLines([]*FieldTrace{{Gaps: []string{bad}}}, src, Lines{}); err == nil {
			t.Errorf("gap source %q names no line of the module, yet it was accepted", bad)
		}
	}
}
