package outputcheck

import "testing"

func TestMeasuredValues(t *testing.T) {
	s := mustCompile(t, `{
		"type": "object",
		"properties": {
			"provider": {"type": "string"},
			"mfa_pct": {"type": ["integer", "null"], "x-epack-method": "Counts users with an active factor."},
			"enabled": {"type": "boolean"},
			"rows": {"type": "array", "items": {"type": "object", "properties": {"open": {"type": "integer", "x-epack-method": "Counts open alerts."}}}},
			"note": {"type": ["string", "null"]}
		}
	}`)
	doc := mustDecode(t, `{"provider": "x", "mfa_pct": null, "enabled": true, "rows": [{"open": 1}, {"open": 2}], "note": null}`)
	got := map[string]string{}
	for _, v := range MeasuredValues(s, doc) {
		got[v.Pointer] = v.Method
	}
	want := map[string]string{
		"/mfa_pct": "Counts users with an active factor.", "/enabled": "",
		"/rows/0/open": "Counts open alerts.", "/rows/1/open": "Counts open alerts.",
	}
	if len(got) != len(want) {
		t.Fatalf("MeasuredValues = %v, want %v", got, want)
	}
	for p, m := range want {
		if method, ok := got[p]; !ok || method != m {
			t.Errorf("%s: method %q (listed %v), want %q", p, method, ok, m)
		}
	}
}
