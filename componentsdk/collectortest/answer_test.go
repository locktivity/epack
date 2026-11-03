package collectortest

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestEachJSONGivesEachValueItsPlace(t *testing.T) {
	got := map[string]place{}
	eachJSON(mustJSON(t, `{"a/b":[{"id":"x"},"y"],"n":null}`), func(at place, _ any) { got[at.pointer] = at })
	want := map[string]place{
		"":           {},
		"/a~1b":      {key: "a/b", pattern: "/a~1b", pointer: "/a~1b"},
		"/a~1b/0":    {key: "a/b", pattern: "/a~1b/*", pointer: "/a~1b/0", item: true},
		"/a~1b/0/id": {key: "id", pattern: "/a~1b/*/id", pointer: "/a~1b/0/id"},
		"/a~1b/1":    {key: "a/b", pattern: "/a~1b/*", pointer: "/a~1b/1", item: true},
		"/n":         {key: "n", pattern: "/n", pointer: "/n"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("places = %+v\nwant %+v", got, want)
	}
}

func TestEditJSONReportsOnlyARealChange(t *testing.T) {
	if _, ok := editJSON(`not json`, json.Marshal, reverseArrays); ok {
		t.Error("a body that is not JSON has nothing to change")
	}
	if _, ok := editJSON(`{"a":[1]}`, json.Marshal, reverseArrays); ok {
		t.Error("an edit that changes nothing should report no change")
	}
	if got, ok := editJSON(`{"a":[1,2],"h":"<b>"}`, json.Marshal, reverseArrays); !ok || got != `{"a":[2,1],"h":"`+"\\u003cb\\u003e"+`"}` {
		t.Errorf("json.Marshal escapes HTML: %s, %v", got, ok)
	}
	if got, ok := editJSON(`{"a":[1,2],"h":"<b>"}`, marshalNoEscape, reverseArrays); !ok || got != `{"a":[2,1],"h":"<b>"}` {
		t.Errorf("marshalNoEscape keeps HTML as it is: %s, %v", got, ok)
	}
	bang := atPattern("/a/*/s", func(v any) (any, bool) {
		s, ok := v.(string)
		if !ok {
			return v, false
		}
		return s + "!", true
	})
	if got, ok := editJSON(`{"a":[{"s":"on"},{"s":null}],"s":"top"}`, json.Marshal, bang); !ok || got != `{"a":[{"s":"on!"},{"s":null}],"s":"top"}` {
		t.Errorf("a value left as it was should not undo an earlier change, and only the pattern changes: %s, %v", got, ok)
	}
}

func TestParseAnswerTellsFormatsApart(t *testing.T) {
	if _, ok := parseAnswer(" \n<a/>").(xmlDoc); !ok {
		t.Error("a body that starts with < is XML")
	}
	if _, ok := parseAnswer(`{"a":1}`).(jsonDoc); !ok {
		t.Error("a JSON body is JSON")
	}
	if _, ok := parseAnswer("plain text").(noAnswer); !ok {
		t.Error("a body that is neither has nothing in it")
	}
	if _, ok := readAnswer(`{"a":1}`, true).(xmlDoc); !ok {
		t.Error("readAnswer takes the format it is given")
	}
}

// TestXMLDocEachSeesOnlyPlainLeaves pins what the fields and guidance checks
// read from XML. xmlLeaf skips an element with a namespace prefix or an
// attribute, and keeps entities as they are. reverseXML sees every element.
func TestXMLDocEachSeesOnlyPlainLeaves(t *testing.T) {
	var got []string
	parseAnswer(`<r><Status>on</Status><ns:Status>off</ns:Status><Status a="1">x</Status><Name>a&amp;b</Name></r>`).each(func(at place, v any) {
		got = append(got, at.key+" "+at.pattern+" "+v.(string))
	})
	want := []string{"Status Status on", "Name Name a&amp;b"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("each = %q, want %q", got, want)
	}
}
