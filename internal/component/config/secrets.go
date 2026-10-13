package config

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/locktivity/epack/internal/safeyaml"
)

// SecretRef is one entry of a component's secrets list. A bare name is a
// variable the run must hold, so epack passes it through and the dry run
// reports it when unset. A mapping with optional: true is a variable the
// run may hold, such as a cloud profile name, so epack passes it through
// when set and the dry run does not require it.
type SecretRef struct {
	Name     string
	Optional bool
}

// secretMapping is the explicit form of an entry, {name: X, optional: true}.
type secretMapping struct {
	Name     string `yaml:"name" json:"name"`
	Optional bool   `yaml:"optional" json:"optional"`
}

// SecretList is a component's secrets list.
type SecretList []SecretRef

// Names returns every variable name, required or optional, in order.
func (l SecretList) Names() []string {
	names := make([]string, 0, len(l))
	for _, ref := range l {
		names = append(names, ref.Name)
	}
	return names
}

// SecretNames builds a list of required entries, for callers that have only
// names.
func SecretNames(names ...string) SecretList {
	list := make(SecretList, 0, len(names))
	for _, name := range names {
		list = append(list, SecretRef{Name: name})
	}
	return list
}

func (r SecretRef) validate() error {
	if r.Name == "" {
		return fmt.Errorf("secrets entry: name is required")
	}
	return nil
}

// UnmarshalYAML accepts a bare name or a mapping with name and optional.
// The mapping is checked by hand because node decoding does not enforce
// the strict parsing the rest of the config gets.
func (r *SecretRef) UnmarshalYAML(node *safeyaml.Node) error {
	switch node.Kind {
	case safeyaml.ScalarNode:
		var name string
		if err := node.Decode(&name); err != nil {
			return err
		}
		*r = SecretRef{Name: name}
		return nil
	case safeyaml.MappingNode:
		ref := SecretRef{}
		seen := map[string]bool{}
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if seen[key.Value] {
				return fmt.Errorf("secrets entry: duplicate key %q", key.Value)
			}
			seen[key.Value] = true
			switch key.Value {
			case "name":
				if err := value.Decode(&ref.Name); err != nil {
					return fmt.Errorf("secrets entry: name: %w", err)
				}
			case "optional":
				if err := value.Decode(&ref.Optional); err != nil {
					return fmt.Errorf("secrets entry: optional: %w", err)
				}
			default:
				return fmt.Errorf("secrets entry: unknown key %q (expected name and optional)", key.Value)
			}
		}
		if err := ref.validate(); err != nil {
			return err
		}
		*r = ref
		return nil
	default:
		return fmt.Errorf("secrets entry: expected a name or a mapping with name and optional")
	}
}

// MarshalYAML writes a required entry back as its bare name, so a config
// without optional entries round-trips unchanged.
func (r SecretRef) MarshalYAML() (any, error) {
	if !r.Optional {
		return r.Name, nil
	}
	return secretMapping(r), nil
}

// UnmarshalJSON mirrors UnmarshalYAML for JSON-encoded configs, with the
// same refusal of keys other than name and optional.
func (r *SecretRef) UnmarshalJSON(data []byte) error {
	var name string
	if err := json.Unmarshal(data, &name); err == nil {
		*r = SecretRef{Name: name}
		return nil
	}
	var mapping secretMapping
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&mapping); err != nil {
		return fmt.Errorf("secrets entry: expected a name or an object with name and optional: %w", err)
	}
	ref := SecretRef(mapping)
	if err := ref.validate(); err != nil {
		return err
	}
	*r = ref
	return nil
}

// MarshalJSON mirrors MarshalYAML.
func (r SecretRef) MarshalJSON() ([]byte, error) {
	if !r.Optional {
		return json.Marshal(r.Name)
	}
	return json.Marshal(secretMapping(r))
}
