package output

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Printable strips control and formatting characters from text that arrived
// over the wire, so an adapter or server cannot rewrite the terminal with it.
func Printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
}
