package collectortest

import (
	"context"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func answer(req *http.Request, status int) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("{}")), Request: req}
}

// interleave sends two calls of one operation through the SDK's transport
// over base: call A to /a, whose first attempt must fail with a status the
// SDK retries, and call B to /b, which starts and finishes while A waits to
// retry. It returns the status each call ended with.
func interleave(t *testing.T, base http.RoundTripper) (a, b int) {
	t.Helper()
	waiting, resume := make(chan struct{}), make(chan struct{})
	handler := func(ctx componentsdk.CollectorContext) error {
		client := componentsdk.NewHTTPClient(ctx, componentsdk.HTTPOptions{MaxAttempts: 2})
		get := func(path string) int {
			req, err := http.NewRequestWithContext(componentsdk.WithOperation(ctx.Context(), componentsdk.Operation{Name: "demo.item.get"}),
				http.MethodGet, "https://api.example.com"+path, nil)
			if err != nil {
				return 0
			}
			resp, err := client.Do(req)
			if err != nil {
				return 0
			}
			_ = resp.Body.Close()
			return resp.StatusCode
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			a = get("/a")
		}()
		select {
		case <-waiting:
		case <-time.After(10 * time.Second):
			t.Error("call A never waited to retry")
			close(resume)
			<-done
			return nil
		}
		b = get("/b")
		close(resume)
		<-done
		return ctx.Emit([]componentsdk.CollectedArtifact{{Data: map[string]any{}, Path: "artifacts/demo.json"}})
	}
	res := componentsdk.RunInProcess(componentsdk.CollectorSpec{Name: "demo"}, handler, componentsdk.InProcessOptions{
		Transport: base,
		Sleep: func(ctx context.Context, _ time.Duration) error {
			close(waiting)
			<-resume
			return ctx.Err()
		},
	})
	if res.ExitCode != 0 {
		t.Fatalf("exit %d: %s", res.ExitCode, failureLabel(res))
	}
	return a, b
}

func TestARetryKeepsItsCallsFaultWhileAnotherCallRuns(t *testing.T) {
	ok := transportFunc(func(req *http.Request) (*http.Response, error) { return answer(req, http.StatusOK), nil })
	f := StatusFault("503", http.StatusServiceUnavailable, nil, `{}`, componentsdk.CodeVendorError, false)
	in := &injector{base: ok, op: "demo.item.get", fault: f, position: PositionFirst, total: 2}
	a, b := interleave(t, in)
	if a != http.StatusServiceUnavailable || b != http.StatusOK {
		t.Errorf("call A ended with %d and call B with %d, want the first call's fault to outlast its retry", a, b)
	}
	if hits, changed := in.hitCount(), in.changedCalls(); hits != 2 || !slices.Equal(changed, []int{1}) {
		t.Errorf("hits = %d, changed calls = %v, want both attempts of call 1", hits, changed)
	}
}

func TestARetrysAnswerReplacesItsOwnCalls(t *testing.T) {
	log := &answerLog{}
	var mu sync.Mutex
	tries := map[string]int{}
	base := transportFunc(func(req *http.Request) (*http.Response, error) {
		mu.Lock()
		tries[req.URL.Path]++
		n := tries[req.URL.Path]
		mu.Unlock()
		status := http.StatusOK
		switch {
		case req.URL.Path == "/a" && n == 1:
			status = http.StatusServiceUnavailable
		case req.URL.Path == "/b":
			status = http.StatusNotFound
		}
		resp := answer(req, status)
		log.note(req.Context(), componentsdk.ClassifyResponse(resp))
		return resp, nil
	})
	if a, b := interleave(t, base); a != http.StatusOK || b != http.StatusNotFound {
		t.Fatalf("call A ended with %d and call B with %d, want 200 and 404", a, b)
	}
	want := []componentsdk.Code{"", componentsdk.CodeInvalidResponse}
	if got := log.codes["demo.item.get"]; !slices.Equal(got, want) {
		t.Errorf("codes = %q, want %q: call A's retry answers call A", got, want)
	}
}
