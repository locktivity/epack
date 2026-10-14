//go:build !linux

package secrets

// platformProbe has nothing to check before the library is called: macOS
// reports a locked keychain through security's own error, and Windows
// through CredWrite's.
func platformProbe(bool) error { return nil }
