//go:build windows

package execsafe

import (
	"errors"
	"os"
)

// Collector and tool execution is not supported on Windows; releases ship
// epack-core only. These fail closed so any execution path reached
// accidentally errors instead of running an unverified binary.
var errWindowsUnsupported = errors.New("verified binary execution is not supported on windows")

func openVerifiedSourceFile(_ string) (*os.File, error) {
	return nil, errWindowsUnsupported
}

// OpenBinaryNoFollow fails closed on Windows; see errWindowsUnsupported.
func OpenBinaryNoFollow(_ string) (int, error) {
	return -1, errWindowsUnsupported
}

// FstatInode fails closed on Windows; see errWindowsUnsupported.
func FstatInode(_ int) (uint64, error) {
	return 0, errWindowsUnsupported
}
