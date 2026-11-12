package collectortest

import (
	"slices"
	"testing"
)

func TestCheckNamesListEveryCheckOnce(t *testing.T) {
	names := CheckNames()
	seen := map[string]bool{}
	for _, name := range names {
		if seen[name] {
			t.Errorf("%s is listed twice", name)
		}
		seen[name] = true
	}
	for _, want := range []string{"determinism", "coverage", "levels", "permissions", "redaction", "credentials", "faults", "responses", "guidance",
		"pages", "vocabulary", "order", "variants", "fields", "field_faults", "sensitivity", "tracemap", "population", "nulls", "rollups", "ratios"} {
		if !slices.Contains(names, want) {
			t.Errorf("CheckNames lacks %s", want)
		}
	}
}
