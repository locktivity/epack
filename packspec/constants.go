package packspec

const (
	// SpecVersion is the evidence pack manifest spec version.
	SpecVersion = "1.0"

	// DSSEPayloadType is the DSSE payload type for in-toto statements.
	DSSEPayloadType = "application/vnd.in-toto+json"

	// SigstoreBundleMediaType is the required media type for embedded attestations.
	SigstoreBundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"
)
