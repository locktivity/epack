package secrets

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/zalando/go-keyring"
)

// itemLimit bounds one keychain item so it fits every backend: Windows
// stops at 2,560 bytes per blob, and macOS at about 3,000 bytes for the
// service, account, and value together.
const itemLimit = 2048

// Keychain stores values in the operating system keychain through
// go-keyring: /usr/bin/security on macOS, the Secret Service over D-Bus on
// Linux, Credential Manager on Windows. A value too large for one item is
// split across a generation of chunk items that a header item describes.
type Keychain struct {
	probe   func(interactive bool) error
	backend keyringAPI
}

type keyringAPI interface {
	Get(service, user string) (string, error)
	Set(service, user, password string) error
	Delete(service, user string) error
}

type libraryKeyring struct{}

func (libraryKeyring) Get(service, user string) (string, error) { return keyring.Get(service, user) }
func (libraryKeyring) Set(service, user, password string) error {
	return keyring.Set(service, user, password)
}
func (libraryKeyring) Delete(service, user string) error { return keyring.Delete(service, user) }

// NewKeychain returns the keychain store for this platform.
func NewKeychain() *Keychain {
	return &Keychain{probe: platformProbe, backend: libraryKeyring{}}
}

// Kind implements Store.
func (k *Keychain) Kind() string { return "keychain" }

// header is the item stored under the variable's own name. A small value is
// inline. A large one names a generation of chunk items that together hold
// the base64 of the value, with the count, length, and digest a reader
// checks before trusting what it reassembled. Stale lists generations an
// interrupted replacement left behind; the next write removes them.
type header struct {
	Version    int               `json:"v"`
	Inline     *string           `json:"inline,omitempty"`
	Generation int               `json:"generation,omitempty"`
	Chunks     int               `json:"chunks,omitempty"`
	Length     int               `json:"length,omitempty"`
	SHA256     string            `json:"sha256,omitempty"`
	Stale      []staleGeneration `json:"stale,omitempty"`
}

type staleGeneration struct {
	Generation int `json:"generation"`
	Chunks     int `json:"chunks"`
}

func (h header) chunked() bool { return h.Inline == nil && h.Chunks > 0 }

func chunkAccount(name string, generation, index int) string {
	return fmt.Sprintf("%s#%d#%d", name, generation, index)
}

// Get implements Store.
func (k *Keychain) Get(scope Scope, name string, interactive bool) (string, error) {
	if err := k.ready(interactive); err != nil {
		return "", err
	}
	h, err := k.readHeader(scope, name)
	if err != nil {
		return "", err
	}
	if h.Inline != nil {
		return *h.Inline, nil
	}
	value, err := k.readChunks(scope, name, h)
	if err != nil {
		return "", err
	}
	return value, nil
}

// Set implements Store. The new value's chunks are written first, then the
// header, then the previous generation is removed, so an interruption
// before the header leaves the previous value readable and one after it
// leaves the new value readable.
func (k *Keychain) Set(scope Scope, name, value string, interactive bool) error {
	if len(value) > MaxValueBytes {
		return &StoreError{Code: CodeTooLarge, Message: fmt.Sprintf("%s is %d bytes; the keychain holds up to %d", name, len(value), MaxValueBytes)}
	}
	if err := k.ready(interactive); err != nil {
		return err
	}
	old, err := k.readHeader(scope, name)
	switch {
	case err == nil:
	case CodeOf(err) == CodeNotFound:
		old = nil
	default:
		return err
	}
	if old != nil {
		for _, stale := range old.Stale {
			k.deleteChunks(scope, name, stale)
		}
	}
	inline := value
	h := header{Version: 1, Inline: &inline}
	if encoded, err := json.Marshal(h); err == nil && len(encoded) <= itemLimit {
		if err := k.writeHeader(scope, name, h); err != nil {
			return err
		}
		if old != nil && old.chunked() {
			k.deleteChunks(scope, name, staleGeneration{Generation: old.Generation, Chunks: old.Chunks})
		}
		return nil
	}
	generation := 1
	if old != nil && old.Generation >= generation {
		generation = old.Generation + 1
	}
	k.sweepGeneration(scope, name, generation)
	chunks := splitChunks(base64.StdEncoding.EncodeToString([]byte(value)), itemLimit)
	for i, chunk := range chunks {
		if err := k.backend.Set(scope.Service(), chunkAccount(name, generation, i+1), chunk); err != nil {
			k.deleteChunks(scope, name, staleGeneration{Generation: generation, Chunks: i})
			return k.mapError(err, name)
		}
	}
	sum := sha256.Sum256([]byte(value))
	h = header{Version: 1, Generation: generation, Chunks: len(chunks), Length: len(value), SHA256: hex.EncodeToString(sum[:])}
	if old != nil && old.chunked() {
		h.Stale = []staleGeneration{{Generation: old.Generation, Chunks: old.Chunks}}
	}
	if err := k.writeHeader(scope, name, h); err != nil {
		k.deleteChunks(scope, name, staleGeneration{Generation: generation, Chunks: len(chunks)})
		return err
	}
	if len(h.Stale) == 0 {
		return nil
	}
	for _, stale := range h.Stale {
		if !k.deleteChunks(scope, name, stale) {
			return nil
		}
	}
	h.Stale = nil
	_ = k.writeHeader(scope, name, h)
	return nil
}

// Erase implements Store.
func (k *Keychain) Erase(scope Scope, name string, interactive bool) error {
	if err := k.ready(interactive); err != nil {
		return err
	}
	old, err := k.readHeader(scope, name)
	switch {
	case err == nil:
	case CodeOf(err) == CodeNotFound:
		return nil
	default:
		return err
	}
	if old.chunked() {
		k.deleteChunks(scope, name, staleGeneration{Generation: old.Generation, Chunks: old.Chunks})
	}
	for _, stale := range old.Stale {
		k.deleteChunks(scope, name, stale)
	}
	if err := k.backend.Delete(scope.Service(), name); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return k.mapError(err, name)
	}
	return nil
}

func (k *Keychain) ready(interactive bool) error {
	if k.probe == nil {
		return nil
	}
	return k.probe(interactive)
}

func (k *Keychain) readHeader(scope Scope, name string) (*header, error) {
	raw, err := k.backend.Get(scope.Service(), name)
	if err != nil {
		return nil, k.mapError(err, name)
	}
	var h header
	if err := json.Unmarshal([]byte(raw), &h); err != nil || h.Version != 1 || (h.Inline == nil && h.Chunks == 0) {
		return nil, incomplete(name)
	}
	return &h, nil
}

func (k *Keychain) writeHeader(scope Scope, name string, h header) error {
	encoded, err := json.Marshal(h)
	if err != nil {
		return err
	}
	if err := k.backend.Set(scope.Service(), name, string(encoded)); err != nil {
		return k.mapError(err, name)
	}
	return nil
}

func (k *Keychain) readChunks(scope Scope, name string, h *header) (string, error) {
	var encoded strings.Builder
	for i := 1; i <= h.Chunks; i++ {
		chunk, err := k.backend.Get(scope.Service(), chunkAccount(name, h.Generation, i))
		if err != nil {
			if errors.Is(err, keyring.ErrNotFound) {
				return "", incomplete(name)
			}
			return "", k.mapError(err, name)
		}
		encoded.WriteString(chunk)
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded.String())
	if err != nil || len(decoded) != h.Length {
		return "", incomplete(name)
	}
	sum := sha256.Sum256(decoded)
	if hex.EncodeToString(sum[:]) != h.SHA256 {
		return "", incomplete(name)
	}
	return string(decoded), nil
}

// maxChunks is the most chunk items one value can take.
var maxChunks = (base64.StdEncoding.EncodedLen(MaxValueBytes) + itemLimit - 1) / itemLimit

// sweepGeneration removes chunk items a replacement killed before its header
// left under the generation number about to be reused. Nothing records
// them, so it probes until the first account that does not exist.
func (k *Keychain) sweepGeneration(scope Scope, name string, generation int) {
	for i := 1; i <= maxChunks; i++ {
		if err := k.backend.Delete(scope.Service(), chunkAccount(name, generation, i)); err != nil {
			return
		}
	}
}

// deleteChunks removes a generation's chunk items and reports whether every
// one is gone.
func (k *Keychain) deleteChunks(scope Scope, name string, generation staleGeneration) bool {
	clean := true
	for i := 1; i <= generation.Chunks; i++ {
		if err := k.backend.Delete(scope.Service(), chunkAccount(name, generation.Generation, i)); err != nil && !errors.Is(err, keyring.ErrNotFound) {
			clean = false
		}
	}
	return clean
}

func incomplete(name string) error {
	return &StoreError{Code: CodeNotFound, Message: fmt.Sprintf("the value stored for %s is incomplete; set it again", name)}
}

func splitChunks(s string, size int) []string {
	var chunks []string
	for len(s) > size {
		chunks = append(chunks, s[:size])
		s = s[size:]
	}
	return append(chunks, s)
}

// mapError turns a keyring error into a store answer. The library returns
// the platform's own messages, so the states are told apart by their text.
func (k *Keychain) mapError(err error, name string) error {
	switch {
	case errors.Is(err, keyring.ErrNotFound):
		return notFound(name)
	case errors.Is(err, keyring.ErrSetDataTooBig):
		return &StoreError{Code: CodeTooLarge, Message: fmt.Sprintf("%s does not fit in the keychain", name), Err: err}
	case errors.Is(err, keyring.ErrUnsupportedPlatform):
		return &StoreError{Code: CodeUnavailable, Message: "no keychain on this platform", Err: err}
	}
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "user interaction is not allowed"),
		strings.Contains(text, "islocked"),
		strings.Contains(text, "is locked"),
		strings.Contains(text, "prompt dismissed"),
		strings.Contains(text, "user canceled"):
		return &StoreError{Code: CodeLocked, Message: "the keychain is locked", Err: err}
	case strings.Contains(text, "serviceunknown"),
		strings.Contains(text, "was not provided by any .service files"),
		strings.Contains(text, "cannot autolaunch d-bus"),
		strings.Contains(text, "no such logon session"),
		strings.Contains(text, "keychain could not be found"):
		return &StoreError{Code: CodeUnavailable, Message: "no keychain service is available", Err: err}
	}
	return &StoreError{Code: CodeUnavailable, Message: "the keychain could not be used: " + err.Error(), Err: err}
}
