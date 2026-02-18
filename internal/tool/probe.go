//go:build components

package tool

import (
	"context"
	"os/exec"

	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/toolcap"
	"github.com/locktivity/epack/internal/toolprotocol"
)

// CapabilitiesTimeout is the maximum time to wait for --capabilities response.
// Exported for use in tests and documentation.
const CapabilitiesTimeout = toolcap.Timeout

// ProbeCapabilities runs --capabilities on a tool and parses the JSON response.
// Sets EPACK_MODE=capabilities to signal the tool that this is a probe, not execution.
// SECURITY: See toolcap.Probe for security properties.
func ProbeCapabilities(ctx context.Context, binaryPath string) (*toolprotocol.Capabilities, error) {
	return toolcap.Probe(ctx, binaryPath)
}

// FindToolInPATH searches for a tool binary in PATH.
// Returns the full path to the binary, or empty string if not found.
func FindToolInPATH(toolName string) string {
	binaryName := componenttypes.ToolBinaryPrefix + toolName
	path, err := exec.LookPath(binaryName)
	if err != nil {
		return ""
	}
	return path
}
