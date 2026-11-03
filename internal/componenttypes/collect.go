package componenttypes

import "errors"

// CollectKey is the config key that lists the kinds of evidence a collector
// collects, such as [cloud-posture]. A kind is the name in a schema ID. A
// collector's own detailed file has no schema ID and goes by the
// collector's name.
const CollectKey = "collect"

// ErrCollectKey is the error for a collect key that is not a list of kinds.
var ErrCollectKey = errors.New("collect must be a list of kinds of evidence, such as [cloud-posture]")

// CollectOf returns the kinds a config's collect key lists. set is false when
// the key is absent. err is ErrCollectKey when the key holds anything but a
// list of non-empty strings.
func CollectOf(config map[string]any) (kinds []string, set bool, err error) {
	raw, ok := config[CollectKey]
	if !ok {
		return nil, false, nil
	}
	var list []any
	switch v := raw.(type) {
	case []any:
		list = v
	case []string:
		for _, s := range v {
			list = append(list, s)
		}
	default:
		return nil, true, ErrCollectKey
	}
	kinds = make([]string, 0, len(list))
	for _, item := range list {
		s, ok := item.(string)
		if !ok || s == "" {
			return nil, true, ErrCollectKey
		}
		kinds = append(kinds, s)
	}
	return kinds, true, nil
}

// KindOf returns the kind of an artifact with schema ID schemaID written by
// the collector named collector: the name in the schema ID, or the
// collector's name for an artifact with no schema ID.
func KindOf(schemaID, collector string) string {
	if kind, ok := SchemaKind(schemaID); ok {
		return kind
	}
	if schemaID != "" {
		return schemaID
	}
	return collector
}
