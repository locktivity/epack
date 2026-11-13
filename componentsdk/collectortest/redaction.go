package collectortest

import "github.com/locktivity/epack/componentsdk"

// checkRedaction reports each run of letters and digits that redaction hid
// as a possible secret from a gap, its advice, a run warning, or a failure
// message. The kit's scenarios hold no real secrets, and the run's own
// secrets are removed first, so such a run is almost always an identifier
// the reader needs, such as an API error code or path.
func (k *kit) checkRedaction(check, name string, res componentsdk.InProcessResult) {
	for _, h := range res.Redacted {
		k.violate("redaction", name, "%s has %q hidden as a possible secret. Runs of 40 or more letters, digits, + and / are hidden unless they read as words. "+
			"Reword the text so the run reads as words or is broken up. If a scenario's text holds a secret on purpose, waive the redaction check", h.Where, h.Text)
	}
}
