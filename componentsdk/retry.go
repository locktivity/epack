package componentsdk

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	backoffBase  = 250 * time.Millisecond
	backoffCap   = 8 * time.Second
	drainLimit   = 64 << 10
	deadlineRoom = time.Second
)

// retries prepares req to be sent more than once when op allows it. It
// returns the request and the number of attempts it may take. A retry-safe
// request whose body can be sent again gets MaxAttempts, and any other
// request gets 1.
func (t *transport) retries(req *http.Request, op Operation) (*http.Request, int, error) {
	if op.Safe && req.GetBody == nil && req.Body != nil && req.Body != http.NoBody {
		var err error
		if req, err = replayable(req); err != nil {
			return nil, 0, err
		}
	}
	if (op.Safe || safeMethod(req.Method)) && (req.Body == nil || req.Body == http.NoBody || req.GetBody != nil) {
		return req, t.maxAttempts, nil
	}
	return req, 1, nil
}

// delay returns how long to wait before the next attempt. It uses the
// Retry-After value when the response has one. For a throttle with no
// Retry-After, it waits until the rate limit resets. Otherwise it uses
// exponential backoff. code is the code the ClassifyResponse hook returned
// for the response.
func (t *transport) delay(resp *http.Response, code Code, attempt int) time.Duration {
	if resp != nil {
		wait, ok := retryAfter(resp.Header.Get("Retry-After"))
		if !ok && rateLimited(resp, code) {
			wait, ok = rateLimitReset(resp.Header, t.run.now())
		}
		if ok {
			if wait > t.retryAfterCap {
				wait = t.retryAfterCap
			}
			return wait + t.run.jitter(min(time.Second, wait/10+1))
		}
	}
	backoff := backoffBase << (attempt - 1)
	if backoff > backoffCap || backoff <= 0 {
		backoff = backoffCap
	}
	return t.run.jitter(backoff)
}

// retryable reports whether an attempt's outcome is worth another try. code
// is the code the ClassifyResponse hook returned for the response, and it
// takes precedence over the status. A transport error is retried only when
// its own code shows that another try could succeed. A request that a guard
// in Base refused is therefore not sent again.
func retryable(ctx context.Context, resp *http.Response, err error, code Code) bool {
	if ctx.Err() != nil {
		return false
	}
	if err != nil {
		var slow *attemptTimeoutError
		if errors.As(err, &slow) {
			return true
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return false
		}
		if lostConnection(err) {
			return true
		}
		return transientCode(Classify(err))
	}
	if code != "" {
		return transientCode(code)
	}
	switch resp.StatusCode {
	case http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	case http.StatusForbidden:
		return throttled(resp.Header)
	default:
		return false
	}
}

// maxReplayBody is the largest request body the transport holds in memory
// so that a retry-safe request can be sent again.
const maxReplayBody = 1 << 20

// replayable returns a copy of req whose body can be sent again, when the
// body fits in maxReplayBody. Vendor SDKs such as AWS's build requests
// without GetBody. Without this copy, a safe POST from those SDKs could never
// be retried. A larger body is passed on whole, without GetBody.
func replayable(req *http.Request) (*http.Request, error) {
	held, err := holdBody(req)
	if err != nil {
		return nil, err
	}
	return withHeldBody(req, held), nil
}

// holdBody reads up to maxReplayBody+1 bytes of req's body. It closes the
// body when the read fails.
func holdBody(req *http.Request) ([]byte, error) {
	held, err := io.ReadAll(io.LimitReader(req.Body, maxReplayBody+1))
	if err != nil {
		_ = req.Body.Close()
		return nil, err
	}
	return held, nil
}

// withHeldBody returns a copy of req that sends held and then the rest of
// the body. held is what holdBody read. When held is the whole body, the
// copy can send it again.
func withHeldBody(req *http.Request, held []byte) *http.Request {
	out := req.Clone(req.Context())
	if len(held) > maxReplayBody {
		out.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(held), req.Body), req.Body}
		return out
	}
	_ = req.Body.Close()
	out.Body = io.NopCloser(bytes.NewReader(held))
	out.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(held)), nil }
	return out
}

// lostConnection reports whether a transport error shows that the
// connection closed before the full response arrived. This happens when a
// server drops an idle keep-alive connection, and a fresh connection fixes
// it. net/http retries some of these itself, but only for idempotent
// methods. It does not retry a POST marked Safe.
func lostConnection(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

// transientCode reports whether a failure with code can clear on its own.
func transientCode(code Code) bool {
	return code == CodeRateLimited || code == CodeVendorError || code == CodeTimeout
}

// retryAfter parses a Retry-After value in seconds or as an HTTP date.
func retryAfter(raw string) (time.Duration, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	if seconds, err := strconv.Atoi(raw); err == nil {
		if seconds < 0 {
			return 0, false
		}
		return time.Duration(seconds) * time.Second, true
	}
	when, err := http.ParseTime(raw)
	if err != nil {
		return 0, false
	}
	wait := time.Until(when)
	if wait < 0 {
		wait = 0
	}
	return wait, true
}

// rateLimited reports whether a response is a throttle. It uses the code the
// ClassifyResponse hook gave the response, if any. Otherwise it uses the
// status and headers.
func rateLimited(resp *http.Response, code Code) bool {
	if code != "" {
		return code == CodeRateLimited
	}
	return classifyStatus(resp.StatusCode, resp.Header) == CodeRateLimited
}

// rateLimitResetHeaders are the headers that give a vendor's rate limit
// reset time. In order, they are Okta's, GitHub's, GitLab's and the IETF
// draft's, and Sentry's.
var rateLimitResetHeaders = []string{"X-Rate-Limit-Reset", "X-RateLimit-Reset", "RateLimit-Reset", "X-Sentry-Rate-Limit-Reset"}

const (
	// epochReset separates the two forms of reset value. A value above it is
	// a time in epoch seconds, because no rate limit window lasts 30 years. A
	// smaller value is a number of seconds from now.
	epochReset = 1e9
	// maxReset is the largest reset value parsed, so that none overflows a
	// Duration.
	maxReset = 1e12
)

// rateLimitReset returns how long until the rate limit resets, measured on
// the run's clock. It uses the first reset header that parses.
func rateLimitReset(header http.Header, now time.Time) (time.Duration, bool) {
	for _, name := range rateLimitResetHeaders {
		seconds, err := strconv.ParseFloat(strings.TrimSpace(header.Get(name)), 64)
		// The range check is negated so that it also rejects NaN. ParseFloat
		// accepts NaN, and every comparison with NaN is false.
		if err != nil || !(seconds >= 0 && seconds < maxReset) {
			continue
		}
		if seconds <= epochReset {
			return time.Duration(seconds * float64(time.Second)), true
		}
		whole, frac := math.Modf(seconds)
		return max(time.Unix(int64(whole), int64(frac*1e9)).Sub(now), 0), true
	}
	return 0, false
}

func fitsDeadline(ctx context.Context, delay time.Duration) bool {
	deadline, ok := ctx.Deadline()
	if !ok {
		return true
	}
	return time.Until(deadline) > delay+deadlineRoom
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func drain(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, drainLimit))
	_ = resp.Body.Close()
}

func safeMethod(method string) bool {
	switch method {
	case "", http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}
