package validate

import (
	"fmt"
	"strings"
)

// WindowsReservedNames contains device names reserved on Windows.
// These names are case-insensitive and invalid even with extensions
// (e.g., "con", "CON", "con.txt" are all reserved).
//
// SECURITY: Use IsWindowsReserved or WindowsFilename to check names.
// Direct map access requires lowercase conversion first.
var WindowsReservedNames = map[string]struct{}{
	"con": {}, "prn": {}, "aux": {}, "nul": {},
	"com1": {}, "com2": {}, "com3": {}, "com4": {},
	"com5": {}, "com6": {}, "com7": {}, "com8": {}, "com9": {},
	"lpt1": {}, "lpt2": {}, "lpt3": {}, "lpt4": {},
	"lpt5": {}, "lpt6": {}, "lpt7": {}, "lpt8": {}, "lpt9": {},
}

// IsWindowsReserved checks if a name is a Windows reserved device name.
// Handles case-insensitivity and extension stripping (con.txt -> con).
func IsWindowsReserved(name string) bool {
	lower := strings.ToLower(name)
	baseName := lower
	if dotIdx := strings.Index(lower, "."); dotIdx > 0 {
		baseName = lower[:dotIdx]
	}
	_, reserved := WindowsReservedNames[baseName]
	return reserved
}

// WindowsFilename validates a filename is safe for use on Windows.
// Rejects:
//   - Reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
//   - Forbidden characters: < > : " | ? *
//   - Trailing dots and spaces (Windows silently strips these)
//
// Does NOT check path separators - use PathComponent for full validation.
func WindowsFilename(name string) error {
	if name == "" {
		return fmt.Errorf("filename cannot be empty")
	}

	// Check reserved names (case-insensitive, with or without extension)
	if IsWindowsReserved(name) {
		return fmt.Errorf("filename %q is reserved on Windows", name)
	}

	// Check forbidden characters: < > : " | ? *
	if strings.ContainsAny(name, "<>:\"|?*") {
		return fmt.Errorf("filename %q contains Windows-forbidden characters", name)
	}

	// Check trailing dots/spaces (Windows strips these, causing collisions)
	if strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return fmt.Errorf("filename %q has trailing dot or space", name)
	}

	return nil
}
