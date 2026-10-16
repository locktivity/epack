package secrets

import (
	"errors"
	"fmt"
)

// Code names why a store could not answer with a value.
type Code string

const (
	// CodeNotFound means no value is stored under that scope and name.
	CodeNotFound Code = "not_found"
	// CodeLocked means a store exists but needs an unlock or confirmation
	// the caller cannot give now.
	CodeLocked Code = "locked"
	// CodeUnavailable means there is no store at all: no session bus, no
	// keyring service, no logon session.
	CodeUnavailable Code = "unavailable"
	// CodeTooLarge means the value exceeds what the store can hold.
	CodeTooLarge Code = "too_large"
	// CodeBusy means another epack command holds this configuration's secrets.
	CodeBusy Code = "busy"
)

// StoreError is a store's typed answer when it has no value to give.
type StoreError struct {
	Code    Code
	Message string
	Err     error
}

func (e *StoreError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Code, e.Err)
	}
	return string(e.Code)
}

func (e *StoreError) Unwrap() error { return e.Err }

// CodeOf returns the typed code behind an error, or "" when the error is
// not a store answer.
func CodeOf(err error) Code {
	var storeErr *StoreError
	if errors.As(err, &storeErr) {
		return storeErr.Code
	}
	return ""
}

// UnlistedError means no component in the configuration lists the name.
type UnlistedError struct {
	Name string
}

func (e *UnlistedError) Error() string {
	return fmt.Sprintf("no component in this configuration lists %s; pass --unlisted to store it anyway", e.Name)
}

func notFound(name string) error {
	return &StoreError{Code: CodeNotFound, Message: fmt.Sprintf("no value stored for %s", name)}
}
