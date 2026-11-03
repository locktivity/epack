package collector

import (
	"encoding/json"

	"github.com/locktivity/epack/componentsdk"
)

// UnmatchedKinds returns the kinds a successful run's collect config key
// listed that the run never wrote or asked about, as its collector result
// records them. A kind there is usually a typo, or one the collector does
// not write. It returns nil for a failed run, a run with no result, or a
// result with no collect record.
func UnmatchedKinds(r RunResult) []string {
	if !r.Success || len(r.Output) == 0 {
		return nil
	}
	parsed, err := ParseCollectorOutput(r.Output)
	if err != nil {
		return nil
	}
	for _, a := range parsed.Artifacts {
		if a.Schema != componentsdk.ResultSchema {
			continue
		}
		var result struct {
			Collect *componentsdk.ResultCollect `json:"collect"`
		}
		if json.Unmarshal(a.RawData, &result) != nil || result.Collect == nil {
			return nil
		}
		return result.Collect.Unmatched
	}
	return nil
}
