package componenttypes

import "testing"

func TestSchemaKind(t *testing.T) {
	for id, want := range map[string]string{
		"evidencepack/vuln-scanning@v1": "vuln-scanning",
		"acme.dev/posture@v12":          "posture",
		"evidencepack/vcs-posture":      "",
		"vcs-posture@v1":                "",
		"":                              "",
	} {
		got, ok := SchemaKind(id)
		if got != want || ok != (want != "") {
			t.Errorf("SchemaKind(%q) = %q, %v; want %q", id, got, ok, want)
		}
	}
}
