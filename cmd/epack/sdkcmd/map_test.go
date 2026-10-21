//go:build components

package sdkcmd

import (
	"bytes"
	"testing"

	"github.com/locktivity/epack/internal/tracemap"
)

func TestWarnUncodedListsFieldsOperationsFeedWithNoCode(t *testing.T) {
	code := []tracemap.CodeLine{{Role: tracemap.RoleAssign, Line: "internal/collector/collector.go:10"}}
	m := &tracemap.Map{Artifacts: map[string]map[string]*tracemap.Field{
		"artifacts/m365.json": {
			"/passwordPolicy/requireUppercaseCharacters": {Operations: []string{"m365.policy.get"}},
		},
		"artifacts/email-dns.json": {
			"/domains/*/spf/valid": {Operations: []string{"dns.spf.lookup"}},
			"/domains/*/spf":       {Operations: []string{"dns.spf.lookup"}},
			"/domains/*/mx":        {Operations: []string{"dns.mx.lookup"}, Code: code},
			"/domains/*/domain":    {},
		},
	}}
	var stderr bytes.Buffer
	warnUncoded(&stderr, m)
	want := "warning: the trace map has no code for 3 of the fields that operations feed:\n" +
		"  artifacts/email-dns.json /domains/*/spf\n" +
		"  artifacts/email-dns.json /domains/*/spf/valid\n" +
		"  artifacts/m365.json /passwordPolicy/requireUppercaseCharacters\n"
	if stderr.String() != want {
		t.Errorf("warning =\n%s\nwant\n%s", stderr.String(), want)
	}

	stderr.Reset()
	warnUncoded(&stderr, &tracemap.Map{Artifacts: map[string]map[string]*tracemap.Field{
		"artifacts/email-dns.json": {"/domains/*/mx": {Operations: []string{"dns.mx.lookup"}, Code: code}},
	}})
	if stderr.Len() != 0 {
		t.Errorf("warned about a map whose fields with operations all have code:\n%s", stderr.String())
	}
}
