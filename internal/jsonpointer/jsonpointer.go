// Package jsonpointer escapes, splits, and joins JSON pointers (RFC 6901).
package jsonpointer

import (
	"strconv"
	"strings"
)

// Escape escapes a reference token: ~ becomes ~0 and / becomes ~1.
func Escape(token string) string {
	return strings.ReplaceAll(strings.ReplaceAll(token, "~", "~0"), "/", "~1")
}

// Unescape reverses Escape.
func Unescape(token string) string {
	return strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
}

// Tokens returns the unescaped reference tokens of pointer, or nil for "",
// which names the whole document. A leading / is optional. A caller that
// must reject a pointer without one checks for it first.
func Tokens(pointer string) []string {
	if pointer == "" {
		return nil
	}
	tokens := strings.Split(strings.TrimPrefix(pointer, "/"), "/")
	for i, t := range tokens {
		tokens[i] = Unescape(t)
	}
	return tokens
}

// Format joins tokens into a pointer, escaping each.
func Format(tokens []string) string {
	var sb strings.Builder
	for _, t := range tokens {
		sb.WriteByte('/')
		sb.WriteString(Escape(t))
	}
	return sb.String()
}

// Index returns the array index a reference token names. ok is false for a
// token that is not a non-negative number or that has a leading zero.
func Index(token string) (index int, ok bool) {
	i, err := strconv.Atoi(token)
	if err != nil || i < 0 || (len(token) > 1 && token[0] == '0') {
		return 0, false
	}
	return i, true
}
