// Package jcsutil provides JSON Canonicalization Scheme (JCS) per RFC 8785.
//
// JCS defines a deterministic serialization of JSON values, ensuring that
// semantically identical JSON documents produce byte-for-byte identical output.
// This is essential for cryptographic operations like signing and hashing.
//
// Key transformations performed:
//   - Object keys are sorted by UTF-16 code unit lexicographic order
//   - Numbers are formatted per ECMAScript rules (no trailing zeros, etc.)
//   - Whitespace is removed
//   - String escaping follows minimal JSON escaping rules
package jcsutil

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// MaxSafeInt is the maximum integer value that can be exactly represented
// in IEEE 754 double-precision floating point (2^53 - 1).
const MaxSafeInt int64 = (1 << 53) - 1

// NumberPolicy controls how numbers are validated and formatted during canonicalization.
type NumberPolicy int

const (
	// NumberPolicyFiniteIEEE accepts any finite IEEE 754 number (rejects NaN and Infinity).
	// This is the standard JCS behavior per RFC 8785.
	NumberPolicyFiniteIEEE NumberPolicy = iota

	// NumberPolicySafeIntNonNegative restricts numbers to non-negative integers
	// within JavaScript's safe integer range [0, 2^53-1]. Rejects negative numbers,
	// fractions, and values exceeding MaxSafeInt.
	NumberPolicySafeIntNonNegative
)

// Options configures JCS canonicalization behavior.
type Options struct {
	// RejectDuplicateKeys causes canonicalization to fail if the input JSON
	// contains duplicate object keys. By default (false), the last value wins
	// per standard JSON parsing behavior.
	RejectDuplicateKeys bool

	// NumberPolicy controls number validation and formatting.
	NumberPolicy NumberPolicy
}

// DefaultOptions returns the default canonicalization options:
// duplicate keys allowed, finite IEEE numbers accepted.
func DefaultOptions() Options {
	return Options{
		NumberPolicy: NumberPolicyFiniteIEEE,
	}
}

// Canonicalize transforms JSON into its canonical form per RFC 8785.
// It uses default options (duplicate keys allowed, finite IEEE numbers).
func Canonicalize(data []byte) ([]byte, error) {
	return CanonicalizeWithOptions(data, DefaultOptions())
}

// CanonicalizeWithOptions transforms JSON into its canonical form per RFC 8785
// using the specified options.
func CanonicalizeWithOptions(data []byte, opts Options) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	var v any
	if opts.RejectDuplicateKeys {
		if err := decodeNoDuplicateKeys(dec, &v); err != nil {
			return nil, err
		}
	} else {
		if err := dec.Decode(&v); err != nil {
			return nil, fmt.Errorf("jcsutil: invalid JSON: %w", err)
		}
		if dec.More() {
			return nil, errors.New("jcsutil: extra JSON input")
		}
	}

	if _, err := dec.Token(); err == nil {
		return nil, errors.New("jcsutil: extra JSON tokens after value")
	}

	var buf bytes.Buffer
	if err := writeCanonical(&buf, v, opts); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// CanonicalizeAndHash canonicalizes JSON and computes its SHA-256 hash.
// Returns the canonical form, the digest as "sha256:{hex}", and any error.
func CanonicalizeAndHash(data []byte) (canonical []byte, digest string, err error) {
	canonical, err = Canonicalize(data)
	if err != nil {
		return nil, "", err
	}
	h := sha256.Sum256(canonical)
	return canonical, "sha256:" + hex.EncodeToString(h[:]), nil
}

// CanonicalizeAndHashWithOptions canonicalizes JSON with the specified options
// and computes its SHA-256 hash. Returns the canonical form, the digest as
// "sha256:{hex}", and any error.
func CanonicalizeAndHashWithOptions(data []byte, opts Options) (canonical []byte, digest string, err error) {
	canonical, err = CanonicalizeWithOptions(data, opts)
	if err != nil {
		return nil, "", err
	}
	h := sha256.Sum256(canonical)
	return canonical, "sha256:" + hex.EncodeToString(h[:]), nil
}

// writeCanonical recursively writes a JSON value in canonical form.
func writeCanonical(w io.Writer, v any, opts Options) error {
	switch x := v.(type) {
	case nil:
		return writeLiteral(w, "null")
	case bool:
		return writeCanonicalBool(w, x)
	case string:
		return writeJCSString(w, x)
	case json.Number:
		return writeCanonicalNumber(w, x, opts.NumberPolicy)
	case float64:
		return writeCanonicalFloat(w, x, opts.NumberPolicy)
	case []any:
		return writeCanonicalArray(w, x, opts)
	case map[string]any:
		return writeCanonicalObject(w, x, opts)
	default:
		return fmt.Errorf("jcsutil: unsupported JSON type %T", v)
	}
}

// writeCanonicalObject writes a JSON object with keys sorted by UTF-16 code unit order.
func writeCanonicalObject(w io.Writer, obj map[string]any, opts Options) error {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return lessUTF16(keys[i], keys[j])
	})

	if _, err := io.WriteString(w, "{"); err != nil {
		return err
	}
	for i, k := range keys {
		if i > 0 {
			if _, err := io.WriteString(w, ","); err != nil {
				return err
			}
		}
		if err := writeJCSString(w, k); err != nil {
			return err
		}
		if _, err := io.WriteString(w, ":"); err != nil {
			return err
		}
		if err := writeCanonical(w, obj[k], opts); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, "}")
	return err
}

// writeJCSString writes a JSON string with JCS-compliant escaping.
// Only required characters are escaped; Unicode is written as UTF-8.
func writeJCSString(w io.Writer, s string) error {
	if _, err := io.WriteString(w, `"`); err != nil {
		return err
	}

	var tmp [utf8.UTFMax]byte
	for _, r := range s {
		if err := writeEscapedRune(w, r, tmp[:]); err != nil {
			return err
		}
	}

	_, err := io.WriteString(w, `"`)
	return err
}

// formatNumber formats a json.Number according to the specified policy.
func formatNumber(n json.Number, policy NumberPolicy) (string, error) {
	s := n.String()
	lower := strings.ToLower(s)
	if lower == "nan" || lower == "inf" || lower == "-inf" || lower == "+inf" ||
		lower == "infinity" || lower == "-infinity" || lower == "+infinity" {
		return "", fmt.Errorf("jcsutil: non-finite number %q", s)
	}

	switch policy {
	case NumberPolicySafeIntNonNegative:
		return formatSafeIntNonNegative(s)
	case NumberPolicyFiniteIEEE:
		f, err := n.Float64()
		if err != nil {
			return "", fmt.Errorf("jcsutil: invalid number %q: %w", s, err)
		}
		return formatFloatFiniteIEEE(f)
	default:
		return "", fmt.Errorf("jcsutil: unknown NumberPolicy %d", policy)
	}
}

// formatFloatNumber formats a float64 according to the specified policy.
func formatFloatNumber(f float64, policy NumberPolicy) (string, error) {
	switch policy {
	case NumberPolicySafeIntNonNegative:
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return "", fmt.Errorf("jcsutil: non-finite number %v", f)
		}
		if f < 0 {
			return "", fmt.Errorf("jcsutil: negative number %v", f)
		}
		if f > float64(MaxSafeInt) {
			return "", fmt.Errorf("jcsutil: number %v exceeds max safe integer", f)
		}
		if f != math.Trunc(f) {
			return "", fmt.Errorf("jcsutil: fractional number %v", f)
		}
		return strconv.FormatInt(int64(f), 10), nil
	case NumberPolicyFiniteIEEE:
		return formatFloatFiniteIEEE(f)
	default:
		return "", fmt.Errorf("jcsutil: unknown NumberPolicy %d", policy)
	}
}

// formatFloatFiniteIEEE formats a finite float64 per ECMAScript number-to-string rules.
// Returns an error for NaN or Infinity.
func formatFloatFiniteIEEE(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", fmt.Errorf("jcsutil: non-finite number %v", f)
	}
	if f == 0 {
		return "0", nil
	}
	s := strconv.FormatFloat(f, 'g', -1, 64)
	if len(s) > 0 && s[0] == '+' {
		s = s[1:]
	}
	return s, nil
}

// formatSafeIntNonNegative validates and formats a number string as a non-negative
// safe integer. Returns an error if the number is negative, fractional, or exceeds MaxSafeInt.
func formatSafeIntNonNegative(s string) (string, error) {
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		if i < 0 {
			return "", fmt.Errorf("jcsutil: negative integer %d", i)
		}
		if i > MaxSafeInt {
			return "", fmt.Errorf("jcsutil: integer %d exceeds max safe integer", i)
		}
		return strconv.FormatInt(i, 10), nil
	}

	if hasFractionalMantissa(s) {
		return "", fmt.Errorf("jcsutil: fractional number %q", s)
	}

	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return "", fmt.Errorf("jcsutil: invalid number %q: %w", s, err)
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", fmt.Errorf("jcsutil: non-finite number %q", s)
	}
	if f < 0 {
		return "", fmt.Errorf("jcsutil: negative number %v", f)
	}
	if f > float64(MaxSafeInt) {
		return "", fmt.Errorf("jcsutil: number %v exceeds max safe integer", f)
	}
	if f != math.Trunc(f) {
		return "", fmt.Errorf("jcsutil: fractional number %q", s)
	}
	return strconv.FormatInt(int64(f), 10), nil
}

// hasFractionalMantissa checks if a number string has non-zero digits after the decimal point.
func hasFractionalMantissa(s string) bool {
	expIdx := strings.IndexAny(s, "eE")
	mantissa := s
	if expIdx != -1 {
		mantissa = s[:expIdx]
	}
	dotIdx := strings.IndexByte(mantissa, '.')
	if dotIdx == -1 {
		return false
	}
	afterDot := mantissa[dotIdx+1:]
	for i := 0; i < len(afterDot); i++ {
		if afterDot[i] != '0' {
			return true
		}
	}
	return false
}

// lessUTF16 compares two strings by UTF-16 code unit lexicographic order,
// as required by JCS for object key sorting.
func lessUTF16(a, b string) bool {
	ai := utf16Iter{str: a}
	bi := utf16Iter{str: b}
	for {
		au, aok := ai.next()
		bu, bok := bi.next()
		if !aok && !bok {
			return false
		}
		if !aok {
			return true
		}
		if !bok {
			return false
		}
		if au < bu {
			return true
		}
		if au > bu {
			return false
		}
	}
}

// utf16Iter iterates over a UTF-8 string yielding UTF-16 code units.
// Characters outside the BMP are yielded as surrogate pairs.
type utf16Iter struct {
	str        string
	i          int
	pending    uint16
	hasPending bool
}

// next returns the next UTF-16 code unit from the string, or (0, false) if exhausted.
func (it *utf16Iter) next() (uint16, bool) {
	if it.hasPending {
		it.hasPending = false
		return it.pending, true
	}
	if it.i >= len(it.str) {
		return 0, false
	}

	r, size := utf8.DecodeRuneInString(it.str[it.i:])
	if r == utf8.RuneError && size == 1 {
		it.i++
		return uint16(utf8.RuneError), true
	}
	it.i += size

	if r <= 0xFFFF {
		return uint16(r), true
	}

	hi, lo := utf16.EncodeRune(r)
	it.pending = uint16(lo)
	it.hasPending = true
	return uint16(hi), true
}

// decodeNoDuplicateKeys recursively decodes JSON, returning an error if any
// object contains duplicate keys.
func decodeNoDuplicateKeys(dec *json.Decoder, out *any) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("jcsutil: invalid JSON: %w", err)
	}

	switch t := tok.(type) {
	case json.Delim:
		return decodeDelimitedNoDuplicates(dec, t, out)

	case string, bool, nil, json.Number, float64:
		*out = t
		return nil
	default:
		return fmt.Errorf("jcsutil: unexpected token type %T", tok)
	}
}

func writeLiteral(w io.Writer, s string) error {
	_, err := io.WriteString(w, s)
	return err
}

func writeCanonicalBool(w io.Writer, v bool) error {
	if v {
		return writeLiteral(w, "true")
	}
	return writeLiteral(w, "false")
}

func writeCanonicalNumber(w io.Writer, n json.Number, policy NumberPolicy) error {
	s, err := formatNumber(n, policy)
	if err != nil {
		return err
	}
	return writeLiteral(w, s)
}

func writeCanonicalFloat(w io.Writer, f float64, policy NumberPolicy) error {
	s, err := formatFloatNumber(f, policy)
	if err != nil {
		return err
	}
	return writeLiteral(w, s)
}

func writeCanonicalArray(w io.Writer, arr []any, opts Options) error {
	if err := writeLiteral(w, "["); err != nil {
		return err
	}
	for i := range arr {
		if i > 0 {
			if err := writeLiteral(w, ","); err != nil {
				return err
			}
		}
		if err := writeCanonical(w, arr[i], opts); err != nil {
			return err
		}
	}
	return writeLiteral(w, "]")
}

func writeEscapedRune(w io.Writer, r rune, scratch []byte) error {
	switch r {
	case '\\':
		return writeLiteral(w, `\\`)
	case '"':
		return writeLiteral(w, `\"`)
	case '\b':
		return writeLiteral(w, `\b`)
	case '\f':
		return writeLiteral(w, `\f`)
	case '\n':
		return writeLiteral(w, `\n`)
	case '\r':
		return writeLiteral(w, `\r`)
	case '\t':
		return writeLiteral(w, `\t`)
	default:
		if r >= 0 && r <= 0x1F {
			if err := writeLiteral(w, `\u00`); err != nil {
				return err
			}
			hex := "0123456789abcdef"
			b := byte(r)
			_, err := w.Write([]byte{hex[b>>4], hex[b&0x0F]})
			return err
		}
		n := utf8.EncodeRune(scratch, r)
		_, err := w.Write(scratch[:n])
		return err
	}
}

func decodeDelimitedNoDuplicates(dec *json.Decoder, d json.Delim, out *any) error {
	switch d {
	case '{':
		return decodeJSONObjectNoDuplicates(dec, out)
	case '[':
		return decodeJSONArrayNoDuplicates(dec, out)
	default:
		return fmt.Errorf("jcsutil: unexpected delimiter %q", d)
	}
}

func decodeJSONObjectNoDuplicates(dec *json.Decoder, out *any) error {
	obj := make(map[string]any)
	seen := make(map[string]struct{})
	for dec.More() {
		key, err := decodeObjectKey(dec)
		if err != nil {
			return err
		}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("jcsutil: duplicate object key %q", key)
		}
		seen[key] = struct{}{}

		var val any
		if err := decodeNoDuplicateKeys(dec, &val); err != nil {
			return err
		}
		obj[key] = val
	}
	if err := expectDelimiter(dec, '}'); err != nil {
		return err
	}
	*out = obj
	return nil
}

func decodeJSONArrayNoDuplicates(dec *json.Decoder, out *any) error {
	var arr []any
	for dec.More() {
		var val any
		if err := decodeNoDuplicateKeys(dec, &val); err != nil {
			return err
		}
		arr = append(arr, val)
	}
	if err := expectDelimiter(dec, ']'); err != nil {
		return err
	}
	*out = arr
	return nil
}

func decodeObjectKey(dec *json.Decoder) (string, error) {
	keyTok, err := dec.Token()
	if err != nil {
		return "", fmt.Errorf("jcsutil: invalid JSON: %w", err)
	}
	key, ok := keyTok.(string)
	if !ok {
		return "", errors.New("jcsutil: object key is not a string")
	}
	return key, nil
}

func expectDelimiter(dec *json.Decoder, expected json.Delim) error {
	endTok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("jcsutil: invalid JSON: %w", err)
	}
	if d, ok := endTok.(json.Delim); !ok || d != expected {
		return fmt.Errorf("jcsutil: expected %q", expected)
	}
	return nil
}
