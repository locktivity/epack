package collector

import (
	"reflect"
	"testing"
)

func TestUnmatchedKindsReadsTheResult(t *testing.T) {
	output := func(collect string) []byte {
		return []byte(`{"type":"epack_result","protocol_version":1,"artifacts":[
{"path":"artifacts/aws.json","data":{}},
{"path":"artifacts/aws.collector-result.json","schema":"evidencepack/collector-result@v1","data":{"collector":{"name":"aws"},"outcome":{"status":"collected"}` + collect + `}}
]}`)
	}
	listed := output(`,"collect":{"listed":["cloud-posture","idp-posture"],"unmatched":["idp-posture"]}`)
	if got := UnmatchedKinds(RunResult{Collector: "aws", Success: true, Output: listed}); !reflect.DeepEqual(got, []string{"idp-posture"}) {
		t.Errorf("UnmatchedKinds = %v, want the kind the run never wrote", got)
	}
	for name, r := range map[string]RunResult{
		"no collect key": {Success: true, Output: output("")},
		"failed run":     {Success: false, Output: listed},
		"no output":      {Success: true},
	} {
		if got := UnmatchedKinds(r); got != nil {
			t.Errorf("%s: UnmatchedKinds = %v, want none", name, got)
		}
	}
}
