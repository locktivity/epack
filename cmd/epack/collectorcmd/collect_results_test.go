//go:build components

package collectorcmd

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/collector"
)

func TestCollectorResultsWarnAboutKindsTheRunNeverWrote(t *testing.T) {
	var buf bytes.Buffer
	result := `{"type":"epack_result","protocol_version":1,"artifacts":[
{"path":"artifacts/aws.collector-result.json","schema":"evidencepack/collector-result@v1","data":{"collector":{"name":"aws"},"outcome":{"status":"collected"},"collect":{"listed":["idp-posture"],"unmatched":["idp-posture"]}}}]}`
	printCollectorResults(output.New(&buf, io.Discard, output.Options{NoColor: true}), []collector.RunResult{
		{Collector: "aws", Success: true, Output: []byte(result)},
		{Collector: "okta", Error: errors.New("auth failed")},
	})
	for _, want := range []string{"collected aws", "warning: collect lists idp-posture, which aws never wrote", "FAILED okta: auth failed"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("output = %q, want %q", buf.String(), want)
		}
	}
}
