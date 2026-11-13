package collectortest

import (
	"strings"
	"testing"
)

func TestTheOrderCheckCatchesAValueThatDependsOnListOrder(t *testing.T) {
	report := checkDemo(t, demo{firstRow: true})
	expectViolation(t, report, "order", "reversing the lists in demo.users.list's answers changed artifacts/demo.json /mfa_enforced from true to false")

	if got := violationsOf(checkDemo(t, demo{}), "order"); len(got) != 0 {
		t.Errorf("rows in another order are the same values: %+v", got)
	}
	ordered := demoSuite(demo{firstRow: true})
	ordered.Waivers = append(ordered.Waivers, waive(WaiveOrdered, "demo.users.list"))
	if got := violationsOf(checkSuite(t, ordered), "order"); len(got) != 0 {
		t.Errorf("an operation waived as ordered keeps its order: %+v", got)
	}
}

func TestReverseXMLMovesEachElementWhole(t *testing.T) {
	body := `<?xml version="1.0" encoding="UTF-8"?>
<DescribeRegionsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <requestId>r-1</requestId>
  <regionInfo>
    <item><regionName>us-east-1</regionName><optInStatus>opt-in-not-required</optInStatus></item>
    <item><regionName>eu-west-1</regionName><tags><item>a</item><item>b</item></tags></item>
    <item><regionName>ap-south-1</regionName><empty/></item>
  </regionInfo>
</DescribeRegionsResponse>`
	want := `<?xml version="1.0" encoding="UTF-8"?>
<DescribeRegionsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <requestId>r-1</requestId>
  <regionInfo>
    <item><regionName>ap-south-1</regionName><empty/></item>
    <item><regionName>eu-west-1</regionName><tags><item>b</item><item>a</item></tags></item>
    <item><regionName>us-east-1</regionName><optInStatus>opt-in-not-required</optInStatus></item>
  </regionInfo>
</DescribeRegionsResponse>`
	got, ok := reverseXML(body)
	if !ok || got != want {
		t.Errorf("reverseXML = %v\n%s\nwant\n%s", ok, got, want)
	}
	if _, ok := reverseXML(`<GetUserResponse><User><UserName>a</UserName></User></GetUserResponse>`); ok {
		t.Error("a document with no repeated sibling has nothing to reverse")
	}
	if _, ok := reverseXML(`<a><b></a>`); ok {
		t.Error("a malformed document is left alone")
	}
}

func TestReverseJSONAndSortLists(t *testing.T) {
	got, ok := reverseJSON(`{"value":[{"id":1,"tags":["x","y"]},{"id":2}],"one":[7],"html":"<b>"}`)
	if !ok || got != `{"html":"<b>","one":[7],"value":[{"id":2},{"id":1,"tags":["y","x"]}]}` {
		t.Errorf("reverseJSON = %v %s", ok, got)
	}
	if _, ok := reverseJSON(`{"value":[1],"name":"x"}`); ok {
		t.Error("a document with no list of two or more has nothing to reverse")
	}
	a := sortLists(mustJSON(t, `{"rows":[{"b":2},{"a":1}],"ids":[3,1,2]}`))
	b := sortLists(mustJSON(t, `{"ids":[2,3,1],"rows":[{"a":1},{"b":2}]}`))
	if showLeaf(a) != showLeaf(b) || !strings.Contains(showLeaf(a), `"ids":[1,2,3]`) {
		t.Errorf("sortLists should make the same rows in another order equal: %s vs %s", showLeaf(a), showLeaf(b))
	}
}

func mustJSON(t *testing.T, s string) any {
	t.Helper()
	doc, ok := decodeJSON(s)
	if !ok {
		t.Fatalf("not JSON: %s", s)
	}
	return doc
}
