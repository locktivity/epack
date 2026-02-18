package pack

import (
	"strings"
	"testing"
)

func FuzzParseManifest(f *testing.F) {
	validDigest := "sha256:" + strings.Repeat("a", 64)

	// Seed with valid manifest
	f.Add([]byte(`{"spec_version":"1.0","stream":"s","generated_at":"2024-01-01T00:00:00Z","pack_digest":"` + validDigest + `","sources":[],"artifacts":[]}`))

	// Seed with manifest containing artifact
	f.Add([]byte(`{"spec_version":"1.0","stream":"s","generated_at":"2024-01-01T00:00:00Z","pack_digest":"` + validDigest + `","sources":[],"artifacts":[{"type":"embedded","path":"a.json","digest":"` + validDigest + `","size":100}]}`))

	// Seed with invalid inputs
	f.Add([]byte(`{}`))
	f.Add([]byte(`invalid`))
	f.Add([]byte(`{"a":{"a":{"a":1}}}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(``))
	f.Add([]byte(`null`))

	// Deeply nested
	f.Add([]byte(`{"a":{"b":{"c":{"d":{"e":{"f":1}}}}}}`))

	// Large array
	f.Add([]byte(`{"spec_version":"1.0","stream":"s","generated_at":"2024-01-01T00:00:00Z","pack_digest":"` + validDigest + `","sources":[],"artifacts":[` + strings.Repeat(`{"type":"embedded","path":"a.json","digest":"`+validDigest+`","size":1},`, 10) + `{"type":"embedded","path":"a.json","digest":"` + validDigest + `","size":1}]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Just ensure it doesn't panic - we don't care about the result
		_, _ = ParseManifest(data)
	})
}
