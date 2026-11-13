package roster

import "encoding/json"

// A domain is a part of a tenant that a roster describes under a top-level
// key of its own, such as a device manager's devices, and whose values go in
// a normalized schema of its own or add to another's. A roster file without
// the key leaves the domain out, and Derive gives none of its values. One
// with the key and no entries describes a tenant that has none.
type domain struct {
	// key is the domain's top-level key in a roster file.
	key string
	// parse reads the key's value into r.
	parse func(r *Roster, raw json.RawMessage) error
	// validate checks the domain's entries against r's terms. It is called
	// whether or not r has the domain.
	validate func(r *Roster) error
	// clone copies the domain's entries from r into c, so c's can change
	// without changing r's.
	clone func(c, r *Roster)
	// derive adds the values r's entries determine to out. It adds nothing
	// when r leaves the domain out.
	derive func(r *Roster, out Values) error
	// notDerived lists the fields of the domain's schema that Derive gives no
	// value for, by pointer with * for any index, each with the reason a
	// tenant doesn't determine it.
	notDerived map[string]map[string]string
}

// domains are the parts of a tenant beyond its identity side and the cloud
// side's network and storage, which Parse and Derive handle themselves.
var domains = []domain{endpointDomain, scanningDomain, vcsDomain, workspaceDomain, tlsDomain, mailDomain}

func domainKeys() []string {
	keys := make([]string, len(domains))
	for i, d := range domains {
		keys[i] = d.key
	}
	return keys
}
