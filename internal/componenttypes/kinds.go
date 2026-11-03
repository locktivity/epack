package componenttypes

import "regexp"

// schemaKind matches a schema ID such as evidencepack/vuln-scanning@v1 and
// captures its kind, vuln-scanning.
var schemaKind = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*/([a-z0-9][a-z0-9-]*)@v[0-9]+$`)

// SchemaKind returns the kind of evidence a schema ID names, such as
// vuln-scanning for evidencepack/vuln-scanning@v1. ok is false for a string
// that is not a schema ID of that form.
func SchemaKind(schemaID string) (kind string, ok bool) {
	m := schemaKind.FindStringSubmatch(schemaID)
	if m == nil {
		return "", false
	}
	return m[1], true
}
