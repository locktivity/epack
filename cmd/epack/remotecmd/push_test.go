//go:build components

package remotecmd

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/push"
	"github.com/locktivity/epack/internal/remote"
)

func TestOutputPushResult_UsesAWebResultLink(t *testing.T) {
	page := "https://app.locktivity.com/evidence_packs/packs/pack_123"
	for _, tc := range []struct {
		links map[string]string
		want  string
	}{
		{links: map[string]string{"pack": page}, want: page},
		{links: map[string]string{"view": page}, want: page},
		{links: map[string]string{"release": page}, want: page},
		{links: map[string]string{"pack": page, "view": "https://example.com"}, want: page},
		{links: map[string]string{"pack": "javascript:alert(1)", "view": page}, want: page},
		{links: map[string]string{"pack": "file:///etc/passwd"}},
		{},
	} {
		var stdout bytes.Buffer
		result := &push.Result{Release: &remote.ReleaseResult{ReleaseID: "rel_123"}, Links: tc.links}
		if err := outputPushResult(output.New(&stdout, &stdout, output.Options{}), "locktivity", "evidence.epack", result, time.Second); err != nil {
			t.Fatal(err)
		}
		got := stdout.String()
		if tc.want == "" && strings.Contains(got, "View:") || tc.want != "" && !strings.Contains(got, "View: "+tc.want) {
			t.Fatalf("links = %v, output = %s", tc.links, got)
		}
	}
}
