package collectortest

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/aws/smithy-go/encoding/cbor"
)

// maxShortBlob is the length of the longest binary byte string that is never
// a token: its base64 is 40 characters, the longest run judgeRun passes.
const maxShortBlob = 30

// isCBOR reports whether a Content-Type names CBOR, such as the
// application/cbor that AWS services on the Smithy RPC v2 CBOR protocol
// answer with.
func isCBOR(contentType string) bool {
	mediaType, _, _ := strings.Cut(contentType, ";")
	mediaType = strings.ToLower(strings.TrimSpace(mediaType))
	return mediaType == "application/cbor" || strings.HasSuffix(mediaType, "+cbor")
}

// cborBody scrubs a CBOR body. It decodes the body, scrubs each text string,
// map key, and integer as the text rules scrub the same value in a JSON
// body, and encodes the result.
func (s *scrubber) cborBody(body []byte) ([]byte, error) {
	if len(body) == 0 {
		return body, nil
	}
	v, err := cbor.Decode(body)
	if err != nil {
		return nil, fmt.Errorf("it does not decode, so it cannot be scrubbed: %v", err)
	}
	scrubbed, err := s.cborValue(v, "")
	if err != nil {
		return nil, err
	}
	return encodeCBOR(scrubbed), nil
}

// cborValue scrubs v, which is the value of key in a map, or has no key. A
// credential field's string or byte string is redacted, as fields redacts a
// JSON member's.
func (s *scrubber) cborValue(v cbor.Value, key string) (cbor.Value, error) {
	switch v := v.(type) {
	case cbor.String:
		if credentialField(key) && v != "" && v != redacted {
			s.note("token", string(v))
			return cbor.String(redacted), nil
		}
		return cbor.String(s.text(string(v))), nil
	case cbor.Slice:
		if credentialField(key) && len(v) > 0 && string(v) != redacted {
			s.note("token", string(v))
			return cbor.Slice(redacted), nil
		}
		return cbor.Slice(s.blob(v)), nil
	case cbor.Uint:
		n, err := s.integer(uint64(v))
		return cbor.Uint(n), err
	case cbor.NegInt:
		n, err := s.integer(uint64(v))
		return cbor.NegInt(n), err
	case cbor.List:
		out := make(cbor.List, len(v))
		for i, item := range v {
			var err error
			if out[i], err = s.cborValue(item, ""); err != nil {
				return nil, err
			}
		}
		return out, nil
	case cbor.Map:
		out := make(cbor.Map, len(v))
		for _, k := range sortedKeys(v) {
			name := s.text(k)
			if _, ok := out[name]; ok {
				return nil, errors.New("scrubbing gave two keys of one map the same name; check the ScrubRules")
			}
			value, err := s.cborValue(v[k], name)
			if err != nil {
				return nil, err
			}
			out[name] = value
		}
		return out, nil
	case *cbor.Tag:
		value, err := s.cborValue(v.Value, key)
		if err != nil {
			return nil, err
		}
		return &cbor.Tag{ID: v.ID, Value: value}, nil
	}
	return v, nil
}

var errNumberToText = errors.New("scrubbing turned a number into text, which a CBOR integer cannot hold; check the ScrubRules")

// integer scrubs an integer's digits as the text rules scrub a number in a
// JSON body, such as an account ID.
func (s *scrubber) integer(n uint64) (uint64, error) {
	digits := strconv.FormatUint(n, 10)
	out := s.text(digits)
	if out == digits {
		return n, nil
	}
	scrubbed, err := strconv.ParseUint(out, 10, 64)
	if err != nil {
		return 0, errNumberToText
	}
	return scrubbed, nil
}

// blob scrubs a byte string as the text rules scrub base64 in a JSON body:
// text is scrubbed as text, a certificate or public key stays, and other
// bytes past maxShortBlob are a token.
func (s *scrubber) blob(b []byte) []byte {
	switch {
	case printable(b):
		return []byte(s.textAt(string(b), 1))
	case len(b) <= maxShortBlob || publicMaterial(b):
		return b
	}
	run := base64.StdEncoding.EncodeToString(b)
	if out := (scrubRuns{s}).token(run); out != run {
		return []byte(out)
	}
	return b
}

// scanCBOR runs the scrub check on a CBOR body's decoded values, as scan does
// on text.
func (c *scanner) scanCBOR(where string, body []byte) {
	c.where = where
	if len(body) == 0 {
		return
	}
	v, err := cbor.Decode(body)
	if err != nil {
		c.add("a CBOR body that does not decode, so the scrub check cannot read it")
		return
	}
	c.cborValue(v)
	// The decoder keeps the last of a map's repeated keys and ignores bytes
	// after the first item, so the raw bytes are checked too.
	c.marks(string(body))
}

func (c *scanner) cborValue(v cbor.Value) {
	switch v := v.(type) {
	case cbor.String:
		c.textAt(string(v), 0)
	case cbor.Slice:
		switch {
		case printable(v):
			c.textAt(string(v), 1)
		case len(v) > maxShortBlob && !publicMaterial(v):
			c.add("a long token")
		}
	case cbor.Uint:
		c.textAt(strconv.FormatUint(uint64(v), 10), 0)
	case cbor.NegInt:
		c.textAt(strconv.FormatUint(uint64(v), 10), 0)
	case cbor.List:
		for _, item := range v {
			c.cborValue(item)
		}
	case cbor.Map:
		for _, k := range sortedKeys(v) {
			c.textAt(k, 0)
			c.cborValue(v[k])
		}
	case *cbor.Tag:
		c.cborValue(v.Value)
	}
}

// mutateCBOR does to a CBOR body what mutateJSON does to JSON: it flips every
// boolean, empties every list, and adds one to every number, and reports
// whether anything changed. Strings and byte strings stay.
func mutateCBOR(body string) (string, bool) {
	v, err := cbor.Decode([]byte(body))
	if err != nil {
		return body, false
	}
	changed := false
	var walk func(v cbor.Value) cbor.Value
	walk = func(v cbor.Value) cbor.Value {
		switch node := v.(type) {
		case cbor.Map:
			out := make(cbor.Map, len(node))
			for key, child := range node {
				out[key] = walk(child)
			}
			return out
		case cbor.List:
			if len(node) > 0 {
				changed = true
			}
			return cbor.List{}
		case *cbor.Tag:
			return &cbor.Tag{ID: node.ID, Value: walk(node.Value)}
		case cbor.Bool:
			changed = true
			return !node
		case cbor.Uint:
			changed = true
			return node + 1
		case cbor.NegInt:
			changed = true
			// NegInt(n) is -n, so -1 plus one is zero, which only a Uint holds.
			if node == 1 {
				return cbor.Uint(0)
			}
			return node - 1
		case cbor.Float32:
			changed = true
			return node + 1
		case cbor.Float64:
			changed = true
			return node + 1
		}
		return v
	}
	v = walk(v)
	if !changed {
		return body, false
	}
	return string(encodeCBOR(v)), true
}

// encodeCBOR encodes v as cbor.Encode does, but with each map's keys in
// sorted order, so the same values always encode to the same bytes.
func encodeCBOR(v cbor.Value) []byte {
	switch v := v.(type) {
	case cbor.List:
		out := cborHead(4, uint64(len(v)))
		for _, item := range v {
			out = append(out, encodeCBOR(item)...)
		}
		return out
	case cbor.Map:
		out := cborHead(5, uint64(len(v)))
		for _, k := range sortedKeys(v) {
			out = append(out, cbor.Encode(cbor.String(k))...)
			out = append(out, encodeCBOR(v[k])...)
		}
		return out
	case *cbor.Tag:
		return append(cborHead(6, v.ID), encodeCBOR(v.Value)...)
	}
	return cbor.Encode(v)
}

// cborHead encodes the head of an item of the major type with argument n, in
// its shortest form.
func cborHead(major byte, n uint64) []byte {
	head := major << 5
	switch {
	case n < 24:
		return []byte{head | byte(n)}
	case n <= math.MaxUint8:
		return []byte{head | 24, byte(n)}
	case n <= math.MaxUint16:
		return binary.BigEndian.AppendUint16([]byte{head | 25}, uint16(n))
	case n <= math.MaxUint32:
		return binary.BigEndian.AppendUint32([]byte{head | 26}, uint32(n))
	}
	return binary.BigEndian.AppendUint64([]byte{head | 27}, n)
}
