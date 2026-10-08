package remote_test

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/remote"
)

func TestSigningKey_RoundTripsAPendingKeyWithItsApproval(t *testing.T) {
	data := `{"id":"key_123","name":"laptop","fingerprint":"9f14322e","algorithm":"ecdsa","status":"pending",` +
		`"registered_by":"dana@example.com","created_at":"2026-10-07T18:00:00Z","expires_at":"2027-10-07T18:00:00Z",` +
		`"machine":"dana-mbp","approval":{"code":"WDJB-MJHT","url":"https://app.example.com/approve","expires_at":"2026-10-07T18:15:00Z","interval":5}}`

	var key remote.SigningKey
	if err := json.Unmarshal([]byte(data), &key); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	want := remote.SigningKey{
		ID: "key_123", Name: "laptop", Fingerprint: "9f14322e", Algorithm: "ecdsa", Status: remote.KeyStatusPending,
		RegisteredBy: "dana@example.com", CreatedAt: "2026-10-07T18:00:00Z", ExpiresAt: "2027-10-07T18:00:00Z",
		Machine: "dana-mbp",
		Approval: &remote.KeyApproval{
			Code: "WDJB-MJHT", URL: "https://app.example.com/approve", ExpiresAt: "2026-10-07T18:15:00Z", Interval: 5,
		},
	}
	if !reflect.DeepEqual(key, want) {
		t.Fatalf("key = %+v\nwant %+v", key, want)
	}

	encoded, err := json.Marshal(key)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var again remote.SigningKey
	if err := json.Unmarshal(encoded, &again); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(again, want) {
		t.Fatalf("round trip = %+v\nwant %+v", again, want)
	}
}

func TestSigningKey_LeavesOutMachineAndApprovalWhenAbsent(t *testing.T) {
	encoded, err := json.Marshal(remote.SigningKey{ID: "key_123", Fingerprint: "9f14322e", Status: remote.KeyStatusUsable})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, field := range []string{`"machine"`, `"approval"`} {
		if strings.Contains(string(encoded), field) {
			t.Errorf("%s is set without a value: %s", field, encoded)
		}
	}

	encoded, err = json.Marshal(remote.KeyApproval{Code: "WDJB-MJHT", URL: "https://app.example.com/approve", ExpiresAt: "2026-10-07T18:15:00Z"})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(encoded) != `{"code":"WDJB-MJHT","url":"https://app.example.com/approve","expires_at":"2026-10-07T18:15:00Z"}` {
		t.Errorf("approval = %s", encoded)
	}
}

func TestExecutor_KeyRegisterReadsAPendingKeyAndKeyListReadsTheStatuses(t *testing.T) {
	script, dir := recordingAdapter(t, `{"ok":true,"type":"key.register.result","request_id":"req-1","created":true,"key":{"id":"key_123","fingerprint":"9f14322e","status":"pending","machine":"dana-mbp","approval":{"code":"WDJB-MJHT","url":"https://app.example.com/approve","expires_at":"2026-10-07T18:15:00Z","interval":5}}}`, 0)

	resp, err := remote.NewExecutor(script, "test").KeyRegister(context.Background(), &remote.KeyRegisterRequest{
		Config: "northwind-production", PublicKeyPEM: "-----BEGIN PUBLIC KEY-----\n", Name: "laptop", ExpiresInDays: 365,
	})
	if err != nil {
		t.Fatalf("KeyRegister: %v", err)
	}
	if !resp.Created || resp.Key.Status != remote.KeyStatusPending || resp.Key.Machine != "dana-mbp" || resp.Key.Approval == nil ||
		*resp.Key.Approval != (remote.KeyApproval{Code: "WDJB-MJHT", URL: "https://app.example.com/approve", ExpiresAt: "2026-10-07T18:15:00Z", Interval: 5}) {
		t.Fatalf("response = %+v (approval %+v)", resp, resp.Key.Approval)
	}
	if command, request := recordedRequest(t, dir); command != "key.register" || request["config"] != "northwind-production" || request["name"] != "laptop" {
		t.Errorf("command %q, request = %v", command, request)
	}

	script, _ = recordingAdapter(t, `{"ok":true,"type":"key.list.result","request_id":"req-2","keys":[{"id":"key_124","fingerprint":"0a0a0a0a","status":"lapsed"},{"id":"key_123","fingerprint":"9f14322e","status":"usable","machine":"dana-mbp","approved_at":"2026-10-07T18:05:00Z"}]}`, 0)
	list, err := remote.NewExecutor(script, "test").KeyList(context.Background(), "northwind-production")
	if err != nil {
		t.Fatalf("KeyList: %v", err)
	}
	if len(list.Keys) != 2 || list.Keys[0].Status != remote.KeyStatusLapsed || list.Keys[1].Status != remote.KeyStatusUsable ||
		list.Keys[1].Machine != "dana-mbp" || list.Keys[1].Approval != nil {
		t.Fatalf("keys = %+v", list.Keys)
	}
}

func TestExecutor_KeyRetireNamesTheKeyAndReadsItBackRetired(t *testing.T) {
	script, dir := recordingAdapter(t, `{"ok":true,"type":"key.retire.result","request_id":"req-3","key":{"id":"key_122","fingerprint":"0a0a0a0a","status":"retired","retired_at":"2026-10-07T18:05:00Z"}}`, 0)

	resp, err := remote.NewExecutor(script, "test").KeyRetire(context.Background(), "northwind-production", "key_122")
	if err != nil {
		t.Fatalf("KeyRetire: %v", err)
	}
	if resp.Key.Status != remote.KeyStatusRetired || resp.Key.RetiredAt != "2026-10-07T18:05:00Z" {
		t.Fatalf("key = %+v", resp.Key)
	}
	if command, request := recordedRequest(t, dir); command != "key.retire" || request["config"] != "northwind-production" || request["id"] != "key_122" {
		t.Errorf("command %q, request = %v", command, request)
	}
}
