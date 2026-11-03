package outputcheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/locktivity/epack/internal/jsonpointer"
)

// Prune returns raw, a JSON document, without the values AboveLevel reports
// as above level. Everything else stays as it is in raw, including the order
// of members. A document with nothing above level is returned unchanged.
func Prune(s *Schema, raw []byte, level string) ([]byte, error) {
	doc, err := Decode(raw)
	if err != nil {
		return nil, err
	}
	drop := map[string]bool{}
	for _, f := range AboveLevel(s, "", doc, level) {
		drop[f.Pointer] = true
	}
	switch {
	case len(drop) == 0:
		return raw, nil
	case drop[""]:
		return nil, fmt.Errorf("the whole document is above the %s level", level)
	}
	// within holds each container that a dropped value sits in. Containers
	// not in within are copied as they are.
	within := map[string]bool{}
	for p := range drop {
		for i := range len(p) {
			if p[i] == '/' {
				within[p[:i]] = true
			}
		}
	}
	var b bytes.Buffer
	if err := prune(&b, raw, "", drop, within); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// prune writes raw, the value at pointer at, to b without the values in
// drop.
func prune(b *bytes.Buffer, raw []byte, at string, drop, within map[string]bool) error {
	raw = bytes.TrimSpace(raw)
	if !within[at] {
		b.Write(raw)
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	open, err := dec.Token()
	if err != nil {
		return err
	}
	object := open == json.Delim('{')
	if !object && open != json.Delim('[') {
		return errors.New("a value above the level is inside a scalar")
	}
	b.WriteString(open.(json.Delim).String())
	wrote := false
	for i := 0; dec.More(); i++ {
		token := strconv.Itoa(i)
		var key []byte
		if object {
			name, err := dec.Token()
			if err != nil {
				return err
			}
			token = name.(string)
			if key, err = json.Marshal(token); err != nil {
				return err
			}
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return err
		}
		child := at + "/" + jsonpointer.Escape(token)
		if drop[child] {
			continue
		}
		if wrote {
			b.WriteByte(',')
		}
		wrote = true
		if object {
			b.Write(key)
			b.WriteByte(':')
		}
		if err := prune(b, value, child, drop, within); err != nil {
			return err
		}
	}
	if object {
		b.WriteByte('}')
	} else {
		b.WriteByte(']')
	}
	return nil
}
