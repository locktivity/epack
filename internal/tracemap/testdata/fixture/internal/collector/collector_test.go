package collector

import (
	"testing"
	"time"

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
		Required:   []string{opOrg},
		Operations: []string{opOrg, opPeople},
		Waivers: []collectortest.Waiver{
			{Check: collectortest.WaiveInsensitive, Subject: opOrg, Reason: "The org read signs the run in and feeds no value.", Expires: expires},
			// The fixture keeps the paths the map's tests name, one of them
			// outside artifacts/ on purpose.
			{Check: "paths", Reason: "The map's tests name these paths.", Expires: expires},
			{Check: "field_faults", Reason: "The fixture reads a dropped status as active, which the map's tests do not cover.", Expires: expires},
		},
	})
}

// expires keeps the fixture's waivers current, since it is a test fixture
// rather than a collector anyone runs.
var expires = time.Now().AddDate(0, 6, 0).Format("2006-01-02")
