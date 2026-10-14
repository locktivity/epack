//go:build linux

package secrets

import (
	"os"
	"path/filepath"

	dbus "github.com/godbus/dbus/v5"
)

// platformProbe walks the states go-keyring does not tell apart before the
// library is called: no session bus, no Secret Service on it, or a locked
// default collection. The library would otherwise call Prompt and wait for
// a dialog that never appears without a desktop.
func platformProbe(interactive bool) error {
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
		if runtimeDir == "" {
			return &StoreError{Code: CodeUnavailable, Message: "no session bus; run from a desktop session"}
		}
		if _, err := os.Stat(filepath.Join(runtimeDir, "bus")); err != nil {
			return &StoreError{Code: CodeUnavailable, Message: "no session bus; run from a desktop session"}
		}
	}
	conn, err := dbus.SessionBusPrivateNoAutoStartup()
	if err != nil {
		return &StoreError{Code: CodeUnavailable, Message: "no session bus; run from a desktop session", Err: err}
	}
	defer func() { _ = conn.Close() }()
	if err := conn.Auth(nil); err != nil {
		return &StoreError{Code: CodeUnavailable, Message: "no session bus; run from a desktop session", Err: err}
	}
	if err := conn.Hello(); err != nil {
		return &StoreError{Code: CodeUnavailable, Message: "no session bus; run from a desktop session", Err: err}
	}
	var hasOwner bool
	if err := conn.BusObject().Call("org.freedesktop.DBus.NameHasOwner", 0, "org.freedesktop.secrets").Store(&hasOwner); err != nil || !hasOwner {
		return &StoreError{Code: CodeUnavailable, Message: "no keyring service; install gnome-keyring or kwallet", Err: err}
	}
	collection := conn.Object("org.freedesktop.secrets", "/org/freedesktop/secrets/aliases/default")
	locked, err := collection.GetProperty("org.freedesktop.Secret.Collection.Locked")
	if err != nil {
		return nil
	}
	isLocked, _ := locked.Value().(bool)
	if !isLocked {
		return nil
	}
	if interactive && (os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != "") {
		return nil
	}
	return &StoreError{Code: CodeLocked, Message: "the login keyring is locked, which is the normal state after a key-based SSH login"}
}
