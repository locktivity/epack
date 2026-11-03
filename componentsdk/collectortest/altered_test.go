package collectortest

import (
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk"
)

func TestPickOpsKeepsWhatEachCheckAlters(t *testing.T) {
	dns := &dnsServer{}
	dns.ops = map[string]bool{"lookup": true}
	k := &kit{
		suite: Suite{Insensitive: []string{"quiet"}},
		baseline: &componentsdk.InProcessResult{
			Operations: []componentsdk.OperationCalls{
				{Name: componentsdk.UnnamedOperation, Calls: 1},
				{Name: "list", Calls: 2},
				{Name: "quiet", Calls: 1},
				{Name: "sorted", Calls: 1},
				{Name: "idle"},
				{Name: "lookup", Calls: 1},
			},
			Result: &componentsdk.CollectorResult{Calls: componentsdk.ResultCalls{
				Operations: []componentsdk.OperationCalls{{Name: "reported"}, {Name: "quiet"}, {Name: "lookup"}},
			}},
		},
		baselineNet: &network{dns: dns, endpoints: &endpointSet{}},
	}
	for _, c := range []struct {
		check string
		pick  opPick
		want  string
	}{
		{"order", opPick{skipInsensitive: true, exempt: []string{"sorted"}}, "list"},
		{"pages", opPick{exempt: []string{"sorted"}}, "list quiet"},
		{"credentials", opPick{}, "list quiet sorted"},
		{"faults", opPick{anyKind: true}, "list quiet sorted lookup"},
		{"sensitivity", opPick{fromResult: true, uncalled: true, skipInsensitive: true}, "reported"},
	} {
		var got []string
		for _, op := range k.pickOps(c.pick) {
			got = append(got, op.Name)
		}
		if strings.Join(got, " ") != c.want {
			t.Errorf("%s picks %q, want %q", c.check, got, c.want)
		}
	}
}
