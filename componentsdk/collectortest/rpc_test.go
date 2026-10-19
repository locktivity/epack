package collectortest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk"
)

// rpcDemo reads three items with one JSON-RPC method, each call differing
// only in its body, and leaves out an item it could not read.
type rpcDemo struct {
	noSuccessClassify bool // leaves HTTPOptions.ClassifySuccess off, so a throttle inside a 200 is not retried
}

const (
	rpcURL      = "https://rpc.demo.test/rpc"
	rpcDemoPath = "artifacts/rpcdemo.json"
	rpcThrottle = `{"jsonrpc":"2.0","id":1,"error":{"code":-32003,"message":"Too many requests"}}`
)

// rpcThrottled reads the demo vendor's JSON-RPC rate limit error, which it
// sends inside a 200.
func rpcThrottled(_ *http.Response, body []byte) (componentsdk.Code, bool) {
	if bytes.Contains(body, []byte(`"code":-32003`)) {
		return componentsdk.CodeRateLimited, true
	}
	return "", false
}

func (d rpcDemo) run(ctx componentsdk.CollectorContext) error {
	client := componentsdk.NewHTTPClient(ctx, componentsdk.HTTPOptions{
		CredentialHosts:  []string{"rpc.demo.test"},
		ClassifyResponse: rpcThrottled,
		ClassifySuccess:  !d.noSuccessClassify,
	})
	get := func(id string) (map[string]any, error) {
		body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "items.get", "params": map[string]string{"id": id}})
		if err != nil {
			return nil, err
		}
		reqCtx := componentsdk.WithOperation(ctx.Context(), componentsdk.Operation{Name: "rpc.items.get", Safe: true})
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, rpcURL, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return nil, componentsdk.CodeError(componentsdk.ClassifyResponse(resp), &demoAPIError{status: resp.StatusCode})
		}
		var answer struct {
			Result *struct {
				Name   string `json:"name"`
				Active bool   `json:"active"`
			} `json:"result"`
			Error *struct {
				Code int `json:"code"`
			} `json:"error"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&answer); err != nil {
			return nil, err
		}
		switch {
		case answer.Error != nil && answer.Error.Code == -32003:
			return nil, componentsdk.CodeError(componentsdk.CodeRateLimited, fmt.Errorf("rpc error %d", answer.Error.Code))
		case answer.Error != nil || answer.Result == nil:
			return nil, componentsdk.CodeError(componentsdk.CodeInvalidResponse, errors.New("rpc answer has no result"))
		}
		return map[string]any{"name": answer.Result.Name, "active": answer.Result.Active}, nil
	}
	items := []any{}
	for i, id := range []string{"a", "b", "c"} {
		item, err := get(id)
		if err != nil {
			componentsdk.Records(ctx).NotCollected(componentsdk.Location{Path: rpcDemoPath, Pointer: fmt.Sprintf("/items/%d", i)}, err)
			items = append(items, nil)
			continue
		}
		items = append(items, item)
	}
	return ctx.Emit([]componentsdk.CollectedArtifact{{Data: map[string]any{"items": items}, Path: rpcDemoPath}})
}

// rpcAnswer answers the call for item id with name, matched by the
// request's body when byBody is set, and otherwise once, in order.
func rpcAnswer(id, name string, byBody bool) Response {
	r := Response{Operation: "rpc.items.get", Method: http.MethodPost, URL: rpcURL, Body: fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"result":{"name":%q,"active":true}}`, name)}
	if byBody {
		r.RequestBody = fmt.Sprintf(`{"method":"items.get","params":{"id":%q}}`, id)
	} else {
		r.Times = 1
	}
	return r
}

func rpcDemoSuite(d rpcDemo, byBody bool) Suite {
	return Suite{
		Spec: componentsdk.CollectorSpec{Name: "rpcdemo"},
		Run:  d.run,
		Scenarios: []Scenario{{Name: "clean", Responses: []Response{
			rpcAnswer("a", "alpha", byBody), rpcAnswer("b", "bravo", byBody), rpcAnswer("c", "charlie", byBody),
		}}},
		Operations: []string{"rpc.items.get"},
	}
}

func TestRequestBodiesKeepEachItemsAnswer(t *testing.T) {
	for _, v := range checkSuite(t, rpcDemoSuite(rpcDemo{}, true)).Violations {
		t.Errorf("%s/%s: %s", v.Check, v.Case, v.Message)
	}
	expectCase(t, checkSuite(t, rpcDemoSuite(rpcDemo{}, false)), "rpc.items.get/500/first",
		`artifacts/rpcdemo.json /items/1/name: value changed from "bravo" to "alpha"`)
}

func TestClassifySuccessClearsAThrottleInsideA200(t *testing.T) {
	throttleOnce := BodyFault("rpc-throttle-once", rpcThrottle, "")
	throttleOnce.Transient = true
	faults := []Fault{throttleOnce, BodyFault("rpc-throttle", rpcThrottle, componentsdk.CodeRateLimited)}

	s := rpcDemoSuite(rpcDemo{}, true)
	s.Faults = faults
	for _, v := range checkSuite(t, s).Violations {
		t.Errorf("%s/%s: %s", v.Check, v.Case, v.Message)
	}

	s = rpcDemoSuite(rpcDemo{noSuccessClassify: true}, true)
	s.Faults = faults
	expectViolation(t, checkSuite(t, s), "faults", "a fault that clears on retry left a gap at artifacts/rpcdemo.json /items/0 (rate_limited)")
}

func TestRequestBodyMatchesWhatItLists(t *testing.T) {
	rp, err := NewReplay(Scenario{Name: "bodies", Responses: []Response{
		{Method: http.MethodPost, URL: rpcURL, RequestBody: `{"method":"items.get","params":{"id":"a","page":1}}`, Body: "a"},
		{Method: http.MethodPost, URL: rpcURL, RequestBody: `{"ids":["a","b"]}`, Body: "ids"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		`{"jsonrpc":"2.0","method":"items.get","params":{"id":"a","page":1.0,"extra":true}}`: "a",
		`{"method":"items.get","params":{"id":"b","page":1}}`:                                "",
		`{"method":"items.get","params":["a"]}`:                                              "",
		`{"ids":["a","b"]}`:                                                                  "ids",
		`{"ids":["a","b","c"]}`:                                                              "",
		`method=items.get`:                                                                   "",
	}
	for body, want := range cases {
		req, err := http.NewRequest(http.MethodPost, rpcURL, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := rp.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(resp.Body)
		if want == "" && resp.StatusCode != http.StatusNotFound || want != "" && string(got) != want {
			t.Errorf("body %s: answered %d %q, want %q", body, resp.StatusCode, got, want)
		}
	}
	if _, err := NewReplay(Scenario{Name: "bad", Responses: []Response{{URL: rpcURL, RequestBody: `{"id":`}}}); err == nil {
		t.Error("a RequestBody that is not JSON should be rejected")
	}
}
