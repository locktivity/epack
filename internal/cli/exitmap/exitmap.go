// Package exitmap provides centralized error-to-exit-code mapping for the CLI.
//
// All CLI commands should use ToExit() to convert internal errors to exit codes.
// This ensures consistent exit codes across the codebase and prevents exit code
// logic from being scattered across multiple packages.
//
// Security: All error messages are passed through redact.Error() before being
// returned to sanitize any sensitive information (tokens, secrets, etc.).
package exitmap

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	epackerrors "github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/exitcode"
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/redact"
	"github.com/locktivity/epack/internal/safefile"
)

// ToExit converts an error to an exit code and sanitized message.
// It extracts the exit code from errors.Error (which implements ExitCode()).
// Falls back to general error (exit code 1) for non-typed errors.
//
// The returned message is always sanitized via redact.Error().
func ToExit(err error) (msg string, code int) {
	if err == nil {
		return "", exitcode.Success
	}

	// Check for *errors.Error which has ExitCode() method
	var e *epackerrors.Error
	if errors.As(err, &e) {
		return redact.Error(err.Error()), e.ExitCode()
	}

	return redact.Error(err.Error()), exitcode.General
}

// Result holds the exit code and message from ToExit.
// This is a convenience type for commands that need to return both.
type Result struct {
	Code    int
	Message string
}

// ToExitResult is like ToExit but returns a Result struct.
func ToExitResult(err error) Result {
	msg, code := ToExit(err)
	return Result{Code: code, Message: msg}
}

// ErrorFileEnv names the environment variable holding the path epack appends
// machine-readable error details to. CI workflows read it to pass stable
// failure codes to 'epack remote report-lock' and job summaries without
// scraping logs.
const ErrorFileEnv = "EPACK_ERROR_FILE"

// collectorFailures is implemented by the error of a run whose collectors
// failed.
type collectorFailures interface {
	EachCollectorFailure(fn func(collector string, code epackerrors.Code, exit int, codeSource string))
}

// WriteErrorFile appends code=, exit=, and summary= lines for err to path,
// then a collector= line for each collector that failed, carrying that
// collector's own code=, exit=, and code_source= after its name. The summary is the first
// line of the sanitized error message. Write failures are returned but
// callers on the exit path typically ignore them: the error file is
// best-effort telemetry, never the primary error channel.
func WriteErrorFile(path string, err error) error {
	msg, exit := ToExit(err)
	code := "error"
	var e *epackerrors.Error
	if errors.As(err, &e) && e.Code != "" {
		code = string(e.Code)
	}
	summary := msg
	if i := strings.IndexByte(summary, '\n'); i >= 0 {
		summary = summary[:i]
	}
	var lines strings.Builder
	fmt.Fprintf(&lines, "code=%s\nexit=%d\nsummary=%s\n", code, exit, summary)
	var failed collectorFailures
	if errors.As(err, &failed) {
		failed.EachCollectorFailure(func(collector string, code epackerrors.Code, exit int, codeSource string) {
			fmt.Fprintf(&lines, "collector=%s code=%s exit=%d code_source=%s\n", collector, code, exit, codeSource)
		})
	}

	f, ferr := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if ferr != nil {
		return ferr
	}
	if _, werr := f.WriteString(lines.String()); werr != nil {
		_ = f.Close()
		return werr
	}
	return f.Close()
}

// CollectorFailure is one collector= line of an error file: a collector that
// failed, with its own failure code, exit code, and where the code came from.
type CollectorFailure struct {
	Collector  string `json:"collector"`
	Code       string `json:"code"`
	Exit       int    `json:"exit"`
	CodeSource string `json:"code_source,omitempty"`
}

// ReadCollectorFailures returns the collectors listed by the last error in
// the error file at path, when that error's code is code. Each failed command
// appends its own error, so earlier errors in the file never contribute. A
// missing, unreadable, or oversized file lists none: like the writer, this is
// best-effort telemetry.
func ReadCollectorFailures(path, code string) []CollectorFailure {
	if path == "" {
		return nil
	}
	data, err := safefile.ReadFile(path, limits.ErrorFile)
	if err != nil {
		return nil
	}
	var lastCode string
	var failures []CollectorFailure
	for _, line := range strings.Split(string(data), "\n") {
		if value, ok := strings.CutPrefix(line, "code="); ok {
			lastCode, failures = value, nil
			continue
		}
		if !strings.HasPrefix(line, "collector=") {
			continue
		}
		if failure, ok := parseCollectorFailure(line); ok {
			failures = append(failures, failure)
		}
	}
	if lastCode != code {
		return nil
	}
	return failures
}

func parseCollectorFailure(line string) (CollectorFailure, bool) {
	var failure CollectorFailure
	hasExit := false
	for _, field := range strings.Fields(line) {
		key, value, _ := strings.Cut(field, "=")
		switch key {
		case "collector":
			failure.Collector = value
		case "code":
			failure.Code = value
		case "code_source":
			failure.CodeSource = value
		case "exit":
			exit, err := strconv.Atoi(value)
			if err != nil {
				return CollectorFailure{}, false
			}
			failure.Exit, hasExit = exit, true
		}
	}
	return failure, failure.Collector != "" && failure.Code != "" && hasExit
}
