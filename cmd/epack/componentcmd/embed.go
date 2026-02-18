//go:build components

package componentcmd

import (
	_ "embed"
)

// samplePackData contains the embedded sample.epack file.
// This pack includes demo artifacts for users to explore with
// `epack inspect` and `epack list` commands.
//
// Regenerate with: go run cmd/epack/componentcmd/gensample/main.go
//
//go:embed sample.epack
var samplePackData []byte
