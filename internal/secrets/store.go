package secrets

// MaxValueBytes is the largest value a store accepts. The keychain splits
// anything larger than one item across several, up to this size.
const MaxValueBytes = 16 * 1024

// Store keeps values by scope and name. Implementations answer with a
// StoreError when they have no value to give, so callers can tell a missing
// value from a locked or absent store.
type Store interface {
	// Kind is the short word the check shows: keychain, helper.
	Kind() string
	// Get returns the value under scope and name.
	Get(scope Scope, name string, interactive bool) (string, error)
	// Set stores value under scope and name, replacing any earlier value.
	Set(scope Scope, name, value string, interactive bool) error
	// Erase removes the value under scope and name. A name with no value is
	// not an error.
	Erase(scope Scope, name string, interactive bool) error
}
