package dispatch

import (
	"fmt"
	"os"
	"strings"

	"github.com/locktivity/epack/internal/componenttypes"
)

// WrapperFlags holds parsed wrapper-level flags.
type WrapperFlags struct {
	PackPath             string // --pack <path>
	OutputDir            string // --output-dir <path>
	JSONMode             bool   // --json
	QuietMode            bool   // --quiet
	HasSeparator         bool   // true if "--" was used to separate wrapper args from tool args
	InsecureAllowUnpinned bool   // --insecure-allow-unpinned: allow unverified PATH execution
}

// ParseWrapperArgs separates wrapper flags from tool args.
//
// Wrapper flags can be set via:
//   - CLI flags: --pack, --output-dir, --json, --quiet
//   - Environment variables: EPACK_PACK, EPACK_OUTPUT_DIR, EPACK_JSON, EPACK_QUIET
//
// CLI flags take precedence over environment variables.
// Use "--" to explicitly end wrapper flags and pass remaining args to the tool.
// Without "--", wrapper flags are parsed until an unrecognized flag is encountered.
//
// Returns (WrapperFlags, toolArgs, error)
func ParseWrapperArgs(args []string) (WrapperFlags, []string, error) {
	// Start with env var defaults
	flags := WrapperFlagsFromEnv()
	var toolArgs []string

	for i := 0; i < len(args); i++ {
		arg := args[i]

		// "--" ends wrapper flag parsing; everything after goes to tool
		if arg == "--" {
			flags.HasSeparator = true
			if i+1 < len(args) {
				toolArgs = args[i+1:]
			}
			return flags, toolArgs, nil
		}

		// Parse wrapper flags - CLI overrides env vars
		switch {
		case arg == "--pack" || arg == "-p":
			if i+1 >= len(args) {
				return flags, nil, fmt.Errorf("--pack requires an argument")
			}
			i++
			flags.PackPath = args[i]
		case strings.HasPrefix(arg, "--pack="):
			flags.PackPath = strings.TrimPrefix(arg, "--pack=")
		case arg == "--output-dir" || arg == "-o":
			if i+1 >= len(args) {
				return flags, nil, fmt.Errorf("--output-dir requires an argument")
			}
			i++
			flags.OutputDir = args[i]
		case strings.HasPrefix(arg, "--output-dir="):
			flags.OutputDir = strings.TrimPrefix(arg, "--output-dir=")
		case arg == "--json":
			flags.JSONMode = true
		case arg == "--quiet" || arg == "-q":
			flags.QuietMode = true
		case arg == "--insecure-allow-unpinned":
			flags.InsecureAllowUnpinned = true
		default:
			// Not a wrapper flag - everything from here goes to tool
			toolArgs = args[i:]
			return flags, toolArgs, nil
		}
	}

	return flags, toolArgs, nil
}

// WrapperFlagsFromEnv reads wrapper flags from environment variables.
// These provide defaults that can be overridden by CLI flags.
func WrapperFlagsFromEnv() WrapperFlags {
	return WrapperFlags{
		PackPath:              os.Getenv("EPACK_PACK"),
		OutputDir:             os.Getenv("EPACK_OUTPUT_DIR"),
		JSONMode:              os.Getenv("EPACK_JSON") == "true" || os.Getenv("EPACK_JSON") == "1",
		QuietMode:             os.Getenv("EPACK_QUIET") == "true" || os.Getenv("EPACK_QUIET") == "1",
		InsecureAllowUnpinned: componenttypes.InsecureAllowUnpinnedFromEnv(),
	}
}
