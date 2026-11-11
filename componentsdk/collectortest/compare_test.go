package collectortest

import (
	"slices"
	"testing"
)

func TestCompareResponsesFindsDrift(t *testing.T) {
	const users = "https://graph.example.test/v1.0/users?$select=id,userType&$top=999"
	recorded := []Response{
		{URL: users, Body: `{"value": [{"id": "a", "userType": "Member", "signInActivity": {"lastSignInDateTime": "2026-11-01T00:00:00Z"}}],
			"@odata.nextLink": "https://graph.example.test/v1.0/users?$select=id,userType&$top=999&$skiptoken=X"}`},
		{URL: users + "&$skiptoken=X", Body: `{"value": [{"id": "b", "userType": "Guest", "signInActivity": {"lastSignInDateTime": null}}]}`},
		{URL: "https://graph.example.test/v1.0/policies", Body: `{"isEnabled": false}`},
		{URL: "https://graph.example.test/v1.0/reports", Status: 403, Body: `{"error": {"code": "Forbidden"}}`},
	}
	simulated := []Response{
		{URL: "https://graph.example.test/v1.0/users?$top=999&$select=id,userType", Body: `{"value": [
			{"id": "a", "userType": "Member", "signInActivity": null},
			{"id": "b", "userType": "guest", "invented": true},
			{"id": "c", "userType": "Member", "signInActivity": {"lastSignInDateTime": "2026-11-02T00:00:00Z"}}]}`},
		{URL: "https://graph.example.test/v1.0/policies?", Body: `{"isEnabled": "false"}`},
		{URL: "https://graph.example.test/v1.0/reports", Status: 200, Body: `{"value": []}`},
		{URL: "https://graph.example.test/v1.0/groups", Body: `{"value": []}`},
	}
	got := CompareResponses(recorded, simulated, CompareOptions{
		Items:      "value",
		Ignore:     []string{"@odata.nextLink"},
		Vocabulary: []string{"value[].userType"},
	})
	var lines []string
	for _, d := range got {
		lines = append(lines, d.String())
	}
	want := []string{
		"GET graph.example.test/v1.0/groups: only simulated (recorded nothing, simulated 200)",
		"GET graph.example.test/v1.0/policies isEnabled: type (recorded boolean, simulated string)",
		"GET graph.example.test/v1.0/reports: status (recorded 403, simulated 200)",
		"GET graph.example.test/v1.0/reports error: missing (recorded object, simulated nothing)",
		"GET graph.example.test/v1.0/reports value: extra (recorded nothing, simulated list)",
		"GET graph.example.test/v1.0/users?$select=id,userType&$top=999: count (recorded 2, simulated 3)",
		"GET graph.example.test/v1.0/users?$select=id,userType&$top=999 value[].invented: extra (recorded nothing, simulated boolean)",
		"GET graph.example.test/v1.0/users?$select=id,userType&$top=999 value[].signInActivity: type (recorded object, simulated null or object)",
		"GET graph.example.test/v1.0/users?$select=id,userType&$top=999 value[].signInActivity.lastSignInDateTime: type (recorded null or string, simulated string)",
		"GET graph.example.test/v1.0/users?$select=id,userType&$top=999 value[].userType: values (recorded Guest, simulated guest)",
	}
	if !slices.Equal(lines, want) {
		t.Errorf("differences:\n%s\nwant:\n%s", joinLines(lines), joinLines(want))
	}
}

func TestCompareResponsesAgreesWithItself(t *testing.T) {
	responses := []Response{
		{URL: "https://graph.example.test/v1.0/users", Body: `{"value": [{"id": "a", "tags": ["x", "y"]}]}`},
		{URL: "https://graph.example.test/v1.0/empty", Status: 204},
	}
	if got := CompareResponses(responses, responses, CompareOptions{Items: "value", Vocabulary: []string{"value[].tags[]"}}); len(got) != 0 {
		t.Errorf("CompareResponses() = %v, want nothing", got)
	}
}

func joinLines(lines []string) string {
	out := ""
	for _, l := range lines {
		out += "  " + l + "\n"
	}
	return out
}
