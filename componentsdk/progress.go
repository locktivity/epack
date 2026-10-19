package componentsdk

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
)

// ProgressProtocolVersion is the version of the progress message protocol.
const ProgressProtocolVersion = 1

// Progress kinds.
const (
	ProgressKindStatus   = "status"
	ProgressKindProgress = "progress"
	// ProgressKindFailure carries a failing collector's code. Runners that
	// predate it drop it, as they drop any unknown kind.
	ProgressKindFailure = "failure"
)

// ProgressMessage is the JSON envelope for progress updates written to stdout.
// Components can emit zero or more progress messages during execution.
type ProgressMessage struct {
	Type            string `json:"type"`              // Always "epack_progress"
	ProtocolVersion int    `json:"protocol_version"`  // Progress protocol version
	Kind            string `json:"kind"`              // "status", "progress", or "failure"
	Message         string `json:"message"`           // Human-readable message
	Current         int64  `json:"current,omitempty"` // For kind="progress": current value
	Total           int64  `json:"total,omitempty"`   // For kind="progress": total value

	// For kind="failure": why the collector failed and whose move it is.
	Code       Code   `json:"code,omitempty"`
	Owner      Owner  `json:"owner,omitempty"`
	VendorCode string `json:"vendor_code,omitempty"`
}

// progressWriter handles writing progress messages to stdout.
// It is safe for concurrent use.
type progressWriter struct {
	mu  sync.Mutex
	out io.Writer
}

var defaultProgressWriter = &progressWriter{}

// writeStatus writes a status progress message to stdout.
func (w *progressWriter) writeStatus(message string) {
	w.write(ProgressMessage{
		Type:            "epack_progress",
		ProtocolVersion: ProgressProtocolVersion,
		Kind:            ProgressKindStatus,
		Message:         message,
	})
}

// writeProgress writes a progress message with current/total to stdout.
func (w *progressWriter) writeProgress(current, total int64, message string) {
	w.write(ProgressMessage{
		Type:            "epack_progress",
		ProtocolVersion: ProgressProtocolVersion,
		Kind:            ProgressKindProgress,
		Current:         current,
		Total:           total,
		Message:         message,
	})
}

// writeFailure writes a failing collector's coded record.
func (w *progressWriter) writeFailure(code Code, vendorCode, message string) {
	w.write(ProgressMessage{
		Type:            "epack_progress",
		ProtocolVersion: ProgressProtocolVersion,
		Kind:            ProgressKindFailure,
		Message:         message,
		Code:            code,
		Owner:           code.Owner(),
		VendorCode:      vendorCode,
	})
}

// write serializes and writes a progress message to stdout.
// Progress is best-effort: encoding and write failures are silently ignored.
func (w *progressWriter) write(msg ProgressMessage) {
	w.mu.Lock()
	defer w.mu.Unlock()

	data, err := json.Marshal(msg)
	if err != nil {
		return // Silently ignore encoding errors - progress is best-effort
	}
	out := w.out
	if out == nil {
		out = os.Stdout
	}
	// Write with newline for JSON lines format
	// Ignore write errors - progress is best-effort
	_, _ = fmt.Fprintln(out, string(data))
}
