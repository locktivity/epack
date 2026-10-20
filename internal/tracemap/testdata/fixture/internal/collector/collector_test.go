package collector

import (
	"testing"

	"github.com/locktivity/epack/componentsdk/collectortest"
)

func TestCollectorKit(t *testing.T) {
	collectortest.Run(t, collectortest.Suite{
		Spec:    Spec(),
		Run:     Run,
		Secrets: map[string]string{"FIXTURE_TOKEN": "fixture-token-0123456789"},
		Scenarios: []collectortest.Scenario{{
			Name: "clean",
			Responses: []collectortest.Response{
				{URL: apiURL + "/org", Body: `{"name": "Fixture Org"}`},
				{URL: apiURL + "/people", Body: `[
					{"login": "a", "status": "ACTIVE", "factors": [{"status": "ACTIVE"}]},
					{"login": "b", "status": "SUSPENDED", "factors": []},
					{"login": "c", "status": "DEPROVISIONED", "factors": [{"status": "ACTIVE"}]}
				]`},
			},
		}},
		Required:    []string{opOrg},
		Insensitive: []string{opOrg},
		Operations:  []string{opOrg, opPeople},
	})
}
