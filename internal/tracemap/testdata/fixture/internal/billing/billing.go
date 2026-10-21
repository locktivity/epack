// Package billing declares part of the collector's output. The collector
// instantiates its generic wrapper again in its own package.
package billing

import "encoding/json"

// Account is the org's billing account.
type Account struct {
	Owner Optional[Owner] `json:"owner"`
}

// Owner is the account's owner.
type Owner struct {
	Name string `json:"name"`
}

// Optional encodes as its value alone.
type Optional[T any] struct{ Value *T }

// MarshalJSON writes the value, or null.
func (o Optional[T]) MarshalJSON() ([]byte, error) { return json.Marshal(o.Value) }
