package dispatch

import (
	"fmt"
	"os"
	"strings"

	"github.com/locktivity/epack/internal/componenttypes"
)

// WrapperFlags holds parsed wrapper-level flags.
type WrapperFlags struct {
	PackPath              string // --pack <path>
	OutputDir             string // --output-dir <path>
	JSONMode              bool   // --json
	QuietMode             bool   // --quiet
	HasSeparator          bool   // true if "--" was used to separate wrapper args from tool args
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
	flags := WrapperFlagsFromEnv()
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			flags.HasSeparator = true
			if i+1 < len(args) {
				return flags, args[i+1:], nil
			}
			return flags, nil, nil
		}
		consumed, isWrapper, err := applyWrapperFlag(&flags, args, i)
		if err != nil {
			return flags, nil, err
		}
		if !isWrapper {
			return flags, args[i:], nil
		}
		i += consumed
	}
	return flags, nil, nil
}

func applyWrapperFlag(flags *WrapperFlags, args []string, i int) (consumed int, isWrapper bool, err error) {
	arg := args[i]
	if consumed, isWrapper, err := applyWrapperValueFlag(flags, args, i, arg); isWrapper || err != nil {
		return consumed, isWrapper, err
	}
	return applyWrapperBoolFlag(flags, arg)
}

func applyWrapperValueFlag(flags *WrapperFlags, args []string, i int, arg string) (int, bool, error) {
	switch {
	case arg == "--pack" || arg == "-p":
		value, err := requireNextArg(args, i, "--pack")
		if err != nil {
			return 0, true, err
		}
		flags.PackPath = value
		return 1, true, nil
	case strings.HasPrefix(arg, "--pack="):
		flags.PackPath = strings.TrimPrefix(arg, "--pack=")
		return 0, true, nil
	case arg == "--output-dir" || arg == "-o":
		value, err := requireNextArg(args, i, "--output-dir")
		if err != nil {
			return 0, true, err
		}
		flags.OutputDir = value
		return 1, true, nil
	case strings.HasPrefix(arg, "--output-dir="):
		flags.OutputDir = strings.TrimPrefix(arg, "--output-dir=")
		return 0, true, nil
	default:
		return 0, false, nil
	}
}

func applyWrapperBoolFlag(flags *WrapperFlags, arg string) (int, bool, error) {
	switch arg {
	case "--json":
		flags.JSONMode = true
		return 0, true, nil
	case "--quiet", "-q":
		flags.QuietMode = true
		return 0, true, nil
	case "--insecure-allow-unpinned":
		flags.InsecureAllowUnpinned = true
		return 0, true, nil
	default:
		return 0, false, nil
	}
}

func requireNextArg(args []string, i int, flag string) (string, error) {
	if i+1 >= len(args) {
		return "", fmt.Errorf("%s requires an argument", flag)
	}
	return args[i+1], nil
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
