package componentsdk

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"testing/synctest"
	"time"
)

func TestTransportErrorsCarryTheirCall(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hang := func(req *http.Request) (*http.Response, error) {
			<-req.Context().Done()
			return nil, req.Context().Err()
		}
		script := newScript().on("api.example.com/me", respond(200, "{}", nil)).on("api.example.com/logs", hang)
		c := testContext(script)
		client := NewHTTPClient(c, HTTPOptions{AttemptTimeout: time.Second, MaxAttempts: 2, CredentialHosts: []string{"api.example.com"}})
		resp, err := get(t, client, WithOperation(context.Background(), Operation{Name: "me.get"}), "https://api.example.com/me")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		_, err = get(t, client, WithOperation(context.Background(), Operation{Name: "logs.list"}), "https://api.example.com/logs")
		var urlErr *url.Error
		if !errors.As(err, &urlErr) || !urlErr.Timeout() || Classify(err) != CodeTimeout {
			t.Fatalf("err = %v, want a *url.Error that reports a timeout", err)
		}
		req, _ := http.NewRequestWithContext(WithOperation(context.Background(), Operation{Name: "leak"}), http.MethodGet, "https://elsewhere.example.org/x", nil)
		req.Header.Set("Authorization", "Bearer x")
		_, refused := client.Do(req)

		rec := c.run.records
		rec.NotCollected(Location{Path: "a.json", Pointer: "/logs"}, err)
		rec.NotCollected(Location{Path: "a.json", Pointer: "/leak"}, refused)
		gaps := rec.Gaps()
		if gaps[0].Operation != "logs.list" || gaps[0].Call != 2 || gaps[0].Code != CodeTimeout {
			t.Errorf("gap = %+v, want logs.list as call 2 with a timeout", gaps[0])
		}
		if gaps[1].Operation != "leak" || gaps[1].Call != 3 {
			t.Errorf("gap = %+v, want the refused call", gaps[1])
		}
		rows, _, _ := c.run.calls.requests()
		if rows[len(rows)-1].Call != 3 || rows[len(rows)-1].Error != CodeInvalidResponse {
			t.Errorf("the refused call's row = %+v", rows[len(rows)-1])
		}
	})
}

func TestResponseErrorGivesAGapTheResponsesCall(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		script := newScript().
			on("api.example.com/me", respond(200, "{}", nil)).
			on("api.example.com/users", respond(200, `{"users": [`, nil)).
			on("api.example.com/logs", respond(403, `{"errorCode":"E0000006"}`, nil))
		c := testContext(script)
		client := NewHTTPClient(c, HTTPOptions{VendorCode: func(*http.Response, []byte) string { return "E0000006" }})
		call := func(op, path string) *http.Response {
			resp, err := get(t, client, WithOperation(context.Background(), Operation{Name: op}), "https://api.example.com"+path)
			if err != nil {
				t.Fatal(err)
			}
			return resp
		}
		_ = call("me.get", "/me").Body.Close()
		users := call("users.list", "/users")
		var decoded struct{ Users []string }
		decodeErr := ResponseError(users, json.NewDecoder(users.Body).Decode(&decoded))
		_ = users.Body.Close()
		logs := call("logs.list", "/logs")
		_ = logs.Body.Close()
		denied := ResponseError(logs, &apiErr{status: logs.StatusCode})

		rec := c.run.records
		rec.NotCollected(Location{Path: "a.json", Pointer: "/users"}, decodeErr)
		rec.NotCollected(Location{Path: "a.json", Pointer: "/logs"}, denied, MissingPermission("logs.read"))
		gaps := rec.Gaps()
		if gaps[0].Operation != "users.list" || gaps[0].Call != 2 || gaps[0].Code != CodeInvalidResponse {
			t.Errorf("decode gap = %+v, want the users call and invalid_response", gaps[0])
		}
		if gaps[1].Operation != "logs.list" || gaps[1].Call != 3 || gaps[1].VendorCode != "E0000006" || gaps[1].MissingPermission != "logs.read" || gaps[1].Code != CodePermissionDenied {
			t.Errorf("denied gap = %+v, want the logs call with its vendor code and the permission to grant", gaps[1])
		}

		foreign := &http.Response{StatusCode: 500, Request: mustRequest("https://api.example.com/x")}
		plain := errors.New("bad")
		if ResponseError(foreign, plain) != plain || ResponseError(nil, plain) != plain || ResponseError(users, nil) != nil {
			t.Error("ResponseError should return err unchanged for a response the SDK did not send, and nil for a nil error")
		}
	})
}
