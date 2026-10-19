package collector

import (
	"errors"
	"fmt"
	"strings"

	"github.com/locktivity/epack/componentsdk"
	epackerrors "github.com/locktivity/epack/errors"
	collectorexec "github.com/locktivity/epack/internal/collector/exec"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/exitcode"
)

// Failure is one collector that failed in a run.
type Failure struct {
	// Collector is the collector's name.
	Collector string

	// Code classes the failure. A collector that exited non-zero is classed
	// by its exit code: config_invalid (2), auth_failed (3), network_error
	// (4), or collector_error for any other. A failure epack detected keeps
	// epack's code, such as timeout, invalid_output, or binary_not_found.
	Code epackerrors.Code

	// Exit is the collector's exit code when it exited non-zero, or -1 when
	// a signal ended it. For a failure epack detected it is the exit code
	// epack gives that failure, such as 13 for a timeout.
	Exit int

	// CodeSource says where Code came from: CodeFromCollector, CodeFromExit,
	// or CodeFromRunner. The last two are the runner's best guess, used only
	// when the collector reported no code itself.
	CodeSource string

	// Err is the error the run recorded for the collector.
	Err error
}

// Where a failure's code came from.
const (
	// CodeFromCollector is a code the collector reported in its failure
	// record.
	CodeFromCollector = "collector"
	// CodeFromExit is a code the runner inferred from the collector's exit
	// code.
	CodeFromExit = "exit_code"
	// CodeFromRunner is a failure epack observed itself, such as a timeout
	// or output it could not use.
	CodeFromRunner = "runner"
)

// Message is the failure's error as it reads after the collector's name.
func (f Failure) Message() string {
	return strings.TrimPrefix(f.Err.Error(), "collector ")
}

// Failures returns the collectors in results that failed, in order.
func Failures(results []RunResult) []Failure {
	var failures []Failure
	for _, r := range results {
		if r.Success || r.Error == nil {
			continue
		}
		code, exit, source := classifyFailure(r.Error)
		failures = append(failures, Failure{Collector: r.Collector, Code: code, Exit: exit, CodeSource: source, Err: r.Error})
	}
	return failures
}

func classifyFailure(err error) (epackerrors.Code, int, string) {
	var exitErr *collectorexec.ExitError
	var reported *ReportedFailure
	if errors.As(err, &reported) && componentsdk.Code(reported.Code).Valid() && errors.As(err, &exitErr) {
		return epackerrors.Code(reported.Code), exitErr.Code, CodeFromCollector
	}
	if errors.As(err, &exitErr) {
		switch exitErr.Code {
		case componenttypes.ExitConfigError:
			return epackerrors.CollectorConfigInvalid, exitErr.Code, CodeFromExit
		case componenttypes.ExitAuthError:
			return epackerrors.CollectorAuthFailed, exitErr.Code, CodeFromExit
		case componenttypes.ExitNetworkError:
			return epackerrors.NetworkError, exitErr.Code, CodeFromExit
		default:
			return epackerrors.CollectorError, exitErr.Code, CodeFromExit
		}
	}
	var e *epackerrors.Error
	if errors.As(err, &e) {
		return e.Code, e.ExitCode(), CodeFromRunner
	}
	return epackerrors.CollectorError, exitcode.General, CodeFromRunner
}

// ReportedFailure is the coded record a failing collector printed before it
// exited non-zero. It wraps the exit error, and its code takes precedence
// over the runner's guess from the exit code.
type ReportedFailure struct {
	Code       string
	Owner      string
	VendorCode string
	Message    string
	Err        error
}

func (e *ReportedFailure) Error() string { return e.Err.Error() }
func (e *ReportedFailure) Unwrap() error { return e.Err }

// FailedError is the error a run returns when collectors failed. Its message
// names them, and it unwraps to an epack error with code collect_failed. When
// one collector failed, epack exits with that collector's exit code if it is
// one of the protocol's 2-9, so it never reads as one of epack's own codes, or
// with epack's code for a failure epack detected, such as 13 for a timeout.
// Otherwise it exits 1.
type FailedError struct {
	Failures []Failure
}

func (e *FailedError) Error() string {
	if len(e.Failures) == 1 {
		return e.Failures[0].Collector + ": " + e.Failures[0].Message()
	}
	names := make([]string, 0, len(e.Failures))
	for _, f := range e.Failures {
		names = append(names, f.Collector)
	}
	return fmt.Sprintf("%d collectors failed: %s", len(e.Failures), strings.Join(names, ", "))
}

func (e *FailedError) Unwrap() error {
	exit := exitcode.General
	if len(e.Failures) == 1 {
		f := e.Failures[0]
		switch {
		case f.Exit >= 2 && f.Exit <= 9:
			exit = f.Exit
		case f.Code != epackerrors.CollectorError && f.Exit > 0:
			exit = f.Exit
		}
	}
	return &epackerrors.Error{Code: epackerrors.CollectFailed, Exit: exit, Message: e.Error()}
}

// EachCollectorFailure calls fn with each failed collector's name, code,
// exit, and code source, which the CLI lists in EPACK_ERROR_FILE.
func (e *FailedError) EachCollectorFailure(fn func(collector string, code epackerrors.Code, exit int, codeSource string)) {
	for _, f := range e.Failures {
		fn(f.Collector, f.Code, f.Exit, f.CodeSource)
	}
}
