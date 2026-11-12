package simulate

import (
	"crypto/sha256"
	"fmt"
	"maps"

	"github.com/locktivity/epack/componentsdk/collectortest/roster"
)

// UUID is a stable object ID for a roster key, shaped like a random UUID,
// as Microsoft's and many vendors' object IDs are. kind keeps the IDs of a
// user and a group with one key apart.
func UUID(kind, key string) string {
	sum := sha256.Sum256([]byte(kind + "/" + key))
	h := fmt.Sprintf("%x", sum[:16])
	return h[0:8] + "-" + h[8:12] + "-4" + h[13:16] + "-a" + h[17:20] + "-" + h[20:32]
}

const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// Base62 is a stable object ID for a roster key: prefix and then n letters
// and digits, as Okta's 00u IDs are.
func Base62(prefix string, n int, kind, key string) string {
	sum := sha256.Sum256([]byte(kind + "/" + key))
	out := []byte(prefix)
	for i := range n {
		out = append(out, base62[int(sum[i%len(sum)])%len(base62)])
	}
	return string(out)
}

// SetExtra sets a vendor extra on an entry, copying the map first so a
// clone's change leaves the original alone.
func SetExtra(e *roster.Extra, name string, value any) {
	*e = maps.Clone(*e)
	if *e == nil {
		*e = roster.Extra{}
	}
	(*e)[name] = []byte(JSON(value))
}

// Extra reads a vendor extra into v, which keeps its value when the extra
// is not set. A malformed extra is a roster bug, so it panics.
func Extra(e roster.Extra, name string, v any) {
	if _, err := e.Get(name, v); err != nil {
		panic(fmt.Sprintf("simulate: %v", err))
	}
}

// OnAccount changes the account with key.
func OnAccount(key string, change func(*roster.Account)) func(*roster.Roster) {
	return func(r *roster.Roster) {
		for i := range r.Accounts {
			if r.Accounts[i].Key == key {
				change(&r.Accounts[i])
			}
		}
	}
}

// OnPolicy changes the sign-in policy with key.
func OnPolicy(key string, change func(*roster.Policy)) func(*roster.Roster) {
	return func(r *roster.Roster) {
		for i := range r.Policies {
			if r.Policies[i].Key == key {
				change(&r.Policies[i])
			}
		}
	}
}

// OnGroup changes the group with key.
func OnGroup(key string, change func(*roster.Group)) func(*roster.Roster) {
	return func(r *roster.Roster) {
		for i := range r.Groups {
			if r.Groups[i].Key == key {
				change(&r.Groups[i])
			}
		}
	}
}

// OnApp changes the app with key.
func OnApp(key string, change func(*roster.App)) func(*roster.Roster) {
	return func(r *roster.Roster) {
		for i := range r.Apps {
			if r.Apps[i].Key == key {
				change(&r.Apps[i])
			}
		}
	}
}
