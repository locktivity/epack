// Package safeyaml provides secure YAML parsing with mandatory pre-validation.
//
// # Quick Start
//
// For parsing config files:
//
//	var config Config
//	if err := safeyaml.Unmarshal(data, limits.ConfigFile, &config); err != nil {
//	    return err
//	}
//
// For strict parsing (rejects unknown fields):
//
//	if err := safeyaml.UnmarshalStrict(data, limits.ConfigFile, &config); err != nil {
//	    return err
//	}
//
// # Why Not gopkg.in/yaml.v3?
//
// This package wraps gopkg.in/yaml.v3 to ensure all YAML parsing goes through
// security validation BEFORE the actual parse. This prevents DoS attacks via:
//   - Large file parsing (memory exhaustion)
//   - YAML alias bombs (exponential expansion)
//
// All packages needing to parse YAML should import this package instead of
// gopkg.in/yaml.v3 directly. An import guard test enforces this boundary.
//
// # Serialization
//
// For marshaling (serialization), use gopkg.in/yaml.v3 directly - there are no
// security concerns with serialization. This package provides [NewEncoder] for
// convenience, but you can also use yaml.Marshal directly.
package safeyaml

import (
	"bytes"
	"fmt"
	"io"

	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/yamlpolicy"
	"gopkg.in/yaml.v3"
)

// Unmarshal parses YAML data into a Go value with mandatory security validation.
//
// SECURITY: This function validates size limits and checks for alias bombs
// BEFORE parsing. Use this instead of yaml.Unmarshal directly.
func Unmarshal(data []byte, limit limits.SizeLimit, v any) error {
	if err := yamlpolicy.ValidateBeforeParse(data, limit.Bytes()); err != nil {
		return err
	}
	if err := yaml.Unmarshal(data, v); err != nil {
		return fmt.Errorf("parsing YAML: %w", err)
	}
	return nil
}

// UnmarshalStrict is like Unmarshal but returns an error for unknown fields.
//
// Use this for configuration files where typos should be caught.
func UnmarshalStrict(data []byte, limit limits.SizeLimit, v any) error {
	if err := yamlpolicy.ValidateBeforeParse(data, limit.Bytes()); err != nil {
		return err
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(v); err != nil {
		return fmt.Errorf("parsing YAML: %w", err)
	}
	return nil
}

// DecodeNode parses YAML into a yaml.Node tree with security validation.
//
// SECURITY: Unlike Unmarshal to a Go type, DecodeNode preserves the node
// structure including anchors/aliases without expanding them. This is useful
// for inspection or transformation, but callers must be careful if they
// later convert nodes to Go types.
//
// The yamlpolicy validation still runs to enforce size limits and detect
// alias bombs before the parse.
func DecodeNode(data []byte, limit limits.SizeLimit) (*yaml.Node, error) {
	if err := yamlpolicy.ValidateBeforeParse(data, limit.Bytes()); err != nil {
		return nil, err
	}

	var node yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&node); err != nil {
		if err == io.EOF {
			// Empty document
			return &yaml.Node{Kind: yaml.DocumentNode}, nil
		}
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}
	return &node, nil
}

// Node re-exports yaml.Node for packages that need node-based operations
// without importing yaml.v3 directly.
type Node = yaml.Node

// NodeKind re-exports yaml.Kind constants.
const (
	DocumentNode = yaml.DocumentNode
	SequenceNode = yaml.SequenceNode
	MappingNode  = yaml.MappingNode
	ScalarNode   = yaml.ScalarNode
	AliasNode    = yaml.AliasNode
)

// Encoder wraps yaml.Encoder for streaming output.
// Use this for serialization when you need streaming writes.
type Encoder struct {
	enc *yaml.Encoder
}

// NewEncoder creates a new YAML encoder writing to w.
func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{enc: yaml.NewEncoder(w)}
}

// SetIndent sets the indentation level for the encoder.
func (e *Encoder) SetIndent(spaces int) {
	e.enc.SetIndent(spaces)
}

// Encode writes v to the encoder's output.
func (e *Encoder) Encode(v any) error {
	return e.enc.Encode(v)
}

// Close flushes and closes the encoder.
func (e *Encoder) Close() error {
	return e.enc.Close()
}

// Marshal serializes a Go value to YAML.
// This is a passthrough to yaml.Marshal - serialization has no security concerns.
// Provided for convenience so packages don't need to import yaml.v3 directly.
func Marshal(v any) ([]byte, error) {
	return yaml.Marshal(v)
}
