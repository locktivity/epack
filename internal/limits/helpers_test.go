package limits_test

import (
	"bytes"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/locktivity/epack/internal/limits"
)

func TestReadAllWithLimit(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		limit     int64
		wantData  string
		wantErr   bool
		errType   string
	}{
		{
			name:     "under limit",
			input:    "hello",
			limit:    10,
			wantData: "hello",
			wantErr:  false,
		},
		{
			name:     "exactly at limit",
			input:    "hello",
			limit:    5,
			wantData: "hello",
			wantErr:  false,
		},
		{
			name:    "over limit",
			input:   "hello world",
			limit:   5,
			wantErr: true,
			errType: "*limits.ErrSizeLimitExceeded",
		},
		{
			name:     "empty input",
			input:    "",
			limit:    10,
			wantData: "",
			wantErr:  false,
		},
		{
			name:    "one byte over",
			input:   "123456",
			limit:   5,
			wantErr: true,
			errType: "*limits.ErrSizeLimitExceeded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := strings.NewReader(tt.input)
			data, err := limits.ReadAllWithLimit(r, tt.limit)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
					return
				}
				if _, ok := err.(*limits.ErrSizeLimitExceeded); !ok {
					t.Errorf("expected ErrSizeLimitExceeded, got %T", err)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if string(data) != tt.wantData {
				t.Errorf("got data %q, want %q", string(data), tt.wantData)
			}
		})
	}
}

func TestReadAllWithLimitOp(t *testing.T) {
	r := strings.NewReader("too much data")
	_, err := limits.ReadAllWithLimitOp(r, 5, "test operation")

	if err == nil {
		t.Fatal("expected error")
	}

	sizeErr, ok := err.(*limits.ErrSizeLimitExceeded)
	if !ok {
		t.Fatalf("expected ErrSizeLimitExceeded, got %T", err)
	}

	if sizeErr.Op != "test operation" {
		t.Errorf("got Op %q, want %q", sizeErr.Op, "test operation")
	}

	if sizeErr.Limit != 5 {
		t.Errorf("got Limit %d, want 5", sizeErr.Limit)
	}

	// Check error message contains operation name
	errStr := sizeErr.Error()
	if !strings.Contains(errStr, "test operation") {
		t.Errorf("error message %q should contain operation name", errStr)
	}
}

func TestBudget_ReserveBytes(t *testing.T) {
	budget := limits.NewBudget(100, 10)

	// Should succeed
	if !budget.ReserveBytes(50) {
		t.Error("expected ReserveBytes(50) to succeed")
	}

	if budget.BytesUsed() != 50 {
		t.Errorf("expected BytesUsed() = 50, got %d", budget.BytesUsed())
	}

	if budget.BytesRemaining() != 50 {
		t.Errorf("expected BytesRemaining() = 50, got %d", budget.BytesRemaining())
	}

	// Should succeed - exactly at limit
	if !budget.ReserveBytes(50) {
		t.Error("expected ReserveBytes(50) to succeed at limit")
	}

	// Should fail - over limit
	if budget.ReserveBytes(1) {
		t.Error("expected ReserveBytes(1) to fail when over limit")
	}
}

func TestBudget_ReserveCount(t *testing.T) {
	budget := limits.NewBudget(1000, 3)

	// Reserve up to limit
	for i := 0; i < 3; i++ {
		if !budget.ReserveCount() {
			t.Errorf("expected ReserveCount() to succeed at iteration %d", i)
		}
	}

	// Should fail at limit
	if budget.ReserveCount() {
		t.Error("expected ReserveCount() to fail when at limit")
	}

	if budget.CountRemaining() != 0 {
		t.Errorf("expected CountRemaining() = 0, got %d", budget.CountRemaining())
	}
}

func TestBudget_NoLimit(t *testing.T) {
	// Budget with no limits (0 values)
	budget := limits.NewBudget(0, 0)

	// Should always succeed
	for i := 0; i < 1000; i++ {
		if !budget.ReserveBytes(1000000) {
			t.Error("expected unlimited budget to always succeed for bytes")
		}
		if !budget.ReserveCount() {
			t.Error("expected unlimited budget to always succeed for count")
		}
	}
}

func TestBudget_ReleaseBytes(t *testing.T) {
	budget := limits.NewBudget(100, 0)

	budget.ReserveBytes(80)
	if budget.BytesRemaining() != 20 {
		t.Errorf("expected 20 remaining, got %d", budget.BytesRemaining())
	}

	budget.ReleaseBytes(30)
	if budget.BytesRemaining() != 50 {
		t.Errorf("expected 50 remaining after release, got %d", budget.BytesRemaining())
	}
}

func TestBudget_ReserveBytesUpTo(t *testing.T) {
	budget := limits.NewBudget(100, 0)

	// Reserve most of the budget
	budget.ReserveBytes(80)

	// Try to reserve more than available
	reserved := budget.ReserveBytesUpTo(50)
	if reserved != 20 {
		t.Errorf("expected to reserve 20 bytes, got %d", reserved)
	}

	// Budget should be exhausted
	if budget.BytesRemaining() != 0 {
		t.Errorf("expected 0 remaining, got %d", budget.BytesRemaining())
	}

	// Further reservations should return 0
	reserved = budget.ReserveBytesUpTo(10)
	if reserved != 0 {
		t.Errorf("expected 0 reserved from exhausted budget, got %d", reserved)
	}
}

func TestBudget_Concurrent(t *testing.T) {
	budget := limits.NewBudget(1000, 100)

	var wg sync.WaitGroup
	successCount := make(chan int, 100)

	// Spawn 100 goroutines each trying to reserve 20 bytes
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if budget.ReserveBytes(20) {
				successCount <- 1
			}
		}()
	}

	wg.Wait()
	close(successCount)

	// Count successful reservations
	total := 0
	for range successCount {
		total++
	}

	// Exactly 50 should succeed (1000 bytes / 20 bytes each)
	if total != 50 {
		t.Errorf("expected 50 successful reservations, got %d", total)
	}

	if budget.BytesUsed() != 1000 {
		t.Errorf("expected 1000 bytes used, got %d", budget.BytesUsed())
	}
}

func TestNewBytesBudget(t *testing.T) {
	budget := limits.NewBytesBudget(100)

	// Bytes should be limited
	if !budget.ReserveBytes(100) {
		t.Error("expected bytes reservation to succeed")
	}
	if budget.ReserveBytes(1) {
		t.Error("expected bytes reservation to fail at limit")
	}

	// Count should be unlimited
	for i := 0; i < 1000; i++ {
		if !budget.ReserveCount() {
			t.Errorf("expected unlimited count reservations, failed at %d", i)
		}
	}
}

func TestRecursionGuard(t *testing.T) {
	guard := limits.NewRecursionGuard(5)

	// Should succeed up to limit
	for i := 0; i < 5; i++ {
		if err := guard.Enter(); err != nil {
			t.Errorf("expected Enter() to succeed at depth %d, got error: %v", i+1, err)
		}
		if guard.Depth() != i+1 {
			t.Errorf("expected depth %d, got %d", i+1, guard.Depth())
		}
	}

	// Should fail at limit
	err := guard.Enter()
	if err == nil {
		t.Error("expected Enter() to fail at max depth")
	}

	recErr, ok := err.(*limits.ErrRecursionLimitExceeded)
	if !ok {
		t.Fatalf("expected ErrRecursionLimitExceeded, got %T", err)
	}

	if recErr.Depth != 6 {
		t.Errorf("expected Depth 6, got %d", recErr.Depth)
	}
	if recErr.MaxDepth != 5 {
		t.Errorf("expected MaxDepth 5, got %d", recErr.MaxDepth)
	}

	// Depth should still be 5 since Enter() failed without incrementing
	if guard.Depth() != 5 {
		t.Errorf("expected depth 5 after failed Enter, got %d", guard.Depth())
	}

	// Leave should decrement
	guard.Leave()
	if guard.Depth() != 4 {
		t.Errorf("expected depth 4 after Leave, got %d", guard.Depth())
	}

	// Should succeed again after Leave
	if err := guard.Enter(); err != nil {
		t.Errorf("expected Enter() to succeed after Leave, got error: %v", err)
	}
	if guard.Depth() != 5 {
		t.Errorf("expected depth 5 after re-Enter, got %d", guard.Depth())
	}
}

func TestRecursionGuard_RecursivePattern(t *testing.T) {
	guard := limits.NewRecursionGuard(10)

	// Simulate recursive function pattern
	var recurse func(depth int) error
	recurse = func(depth int) error {
		if err := guard.Enter(); err != nil {
			return err
		}
		defer guard.Leave()

		if depth > 0 {
			return recurse(depth - 1)
		}
		return nil
	}

	// Should succeed within limit
	if err := recurse(9); err != nil {
		t.Errorf("expected recursion to depth 9 to succeed, got error: %v", err)
	}

	// Guard should be back to 0
	if guard.Depth() != 0 {
		t.Errorf("expected depth 0 after recursion, got %d", guard.Depth())
	}

	// Should fail exceeding limit
	err := recurse(15)
	if err == nil {
		t.Error("expected recursion to depth 15 to fail")
	}
}

func TestLimitedWriter(t *testing.T) {
	tests := []struct {
		name          string
		limit         int64
		writes        []string
		wantWritten   int64
		wantTruncated bool
		wantBuffer    string
	}{
		{
			name:          "under limit",
			limit:         100,
			writes:        []string{"hello", " ", "world"},
			wantWritten:   11,
			wantTruncated: false,
			wantBuffer:    "hello world",
		},
		{
			name:          "exactly at limit",
			limit:         5,
			writes:        []string{"hello"},
			wantWritten:   5,
			wantTruncated: true,
			wantBuffer:    "hello",
		},
		{
			name:          "truncated",
			limit:         5,
			writes:        []string{"hello", " world"},
			wantWritten:   5,
			wantTruncated: true,
			wantBuffer:    "hello",
		},
		{
			name:          "multiple writes truncated",
			limit:         10,
			writes:        []string{"12345", "67890", "extra"},
			wantWritten:   10,
			wantTruncated: true,
			wantBuffer:    "1234567890",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			lw := limits.NewLimitedWriter(&buf, tt.limit)

			for _, w := range tt.writes {
				n, err := lw.Write([]byte(w))
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				// LimitedWriter always reports full length to avoid breaking subprocesses
				if n != len(w) {
					t.Errorf("expected write to report %d, got %d", len(w), n)
				}
			}

			if lw.Written() != tt.wantWritten {
				t.Errorf("Written() = %d, want %d", lw.Written(), tt.wantWritten)
			}

			if lw.Truncated() != tt.wantTruncated {
				t.Errorf("Truncated() = %v, want %v", lw.Truncated(), tt.wantTruncated)
			}

			if buf.String() != tt.wantBuffer {
				t.Errorf("buffer = %q, want %q", buf.String(), tt.wantBuffer)
			}
		})
	}
}

func TestLimitedWriter_LargeWrite(t *testing.T) {
	var buf bytes.Buffer
	lw := limits.NewLimitedWriter(&buf, 10)

	// Write more than limit in single call
	data := make([]byte, 100)
	for i := range data {
		data[i] = 'x'
	}

	n, err := lw.Write(data)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Should report full write (to not break subprocess)
	if n != 100 {
		t.Errorf("expected n=100, got %d", n)
	}

	// But only 10 bytes should be in buffer
	if buf.Len() != 10 {
		t.Errorf("expected buffer len 10, got %d", buf.Len())
	}

	if lw.Written() != 10 {
		t.Errorf("expected Written() = 10, got %d", lw.Written())
	}

	if !lw.Truncated() {
		t.Error("expected Truncated() = true")
	}
}

func TestErrSizeLimitExceeded_Error(t *testing.T) {
	err := &limits.ErrSizeLimitExceeded{Limit: 100}
	if !strings.Contains(err.Error(), "100") {
		t.Errorf("error message should contain limit: %s", err.Error())
	}

	errWithOp := &limits.ErrSizeLimitExceeded{Limit: 100, Op: "reading file"}
	if !strings.Contains(errWithOp.Error(), "reading file") {
		t.Errorf("error message should contain operation: %s", errWithOp.Error())
	}
}

func TestErrBudgetExhausted_Error(t *testing.T) {
	err := &limits.ErrBudgetExhausted{Limit: 100, Used: 100}
	errStr := err.Error()
	if !strings.Contains(errStr, "100") {
		t.Errorf("error message should contain limit/used: %s", errStr)
	}
}

func TestErrRecursionLimitExceeded_Error(t *testing.T) {
	err := &limits.ErrRecursionLimitExceeded{Depth: 11, MaxDepth: 10}
	errStr := err.Error()
	if !strings.Contains(errStr, "11") || !strings.Contains(errStr, "10") {
		t.Errorf("error message should contain depth and max: %s", errStr)
	}
}

// TestReadAllWithLimit_ReaderError tests that reader errors are propagated
func TestReadAllWithLimit_ReaderError(t *testing.T) {
	r := &errorReader{err: io.ErrUnexpectedEOF}
	_, err := limits.ReadAllWithLimit(r, 100)
	if err != io.ErrUnexpectedEOF {
		t.Errorf("expected io.ErrUnexpectedEOF, got %v", err)
	}
}

type errorReader struct {
	err error
}

func (r *errorReader) Read(p []byte) (int, error) {
	return 0, r.err
}

// TestBudget_CountRemainingNoOverflow verifies that CountRemaining doesn't overflow
// on 32-bit systems when remaining count exceeds int32 range.
func TestBudget_CountRemainingNoOverflow(t *testing.T) {
	// Create budget with count larger than int32 max
	// On 64-bit systems this tests the bounds check; on 32-bit it prevents overflow
	largeCount := int(1<<31) + 100 // > int32 max on 64-bit systems
	if largeCount < 0 {
		// On 32-bit systems, this would overflow, so skip
		t.Skip("skipping on 32-bit system where int is too small")
	}

	budget := limits.NewBudget(0, largeCount)

	remaining := budget.CountRemaining()
	if remaining < 0 {
		t.Errorf("CountRemaining() returned negative value %d, expected positive", remaining)
	}
	if remaining == 0 {
		t.Errorf("CountRemaining() returned 0, expected positive value")
	}
}

// TestBudget_CountRemainingUnlimited verifies that unlimited count returns MaxInt.
func TestBudget_CountRemainingUnlimited(t *testing.T) {
	budget := limits.NewBudget(100, 0) // unlimited count

	remaining := budget.CountRemaining()
	if remaining <= 0 {
		t.Errorf("CountRemaining() for unlimited budget returned %d, expected large positive", remaining)
	}
}

func TestLimitedCopy(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		limit    int64
		wantN    int64
		wantData string
		wantErr  bool
	}{
		{
			name:     "under limit",
			input:    "hello",
			limit:    10,
			wantN:    5,
			wantData: "hello",
			wantErr:  false,
		},
		{
			name:     "exactly at limit",
			input:    "hello",
			limit:    5,
			wantN:    5,
			wantData: "hello",
			wantErr:  false,
		},
		{
			name:    "over limit",
			input:   "hello world",
			limit:   5,
			wantN:   6, // reads limit+1 to detect overflow
			wantErr: true,
		},
		{
			name:     "empty input",
			input:    "",
			limit:    10,
			wantN:    0,
			wantData: "",
			wantErr:  false,
		},
		{
			name:    "one byte over",
			input:   "123456",
			limit:   5,
			wantN:   6,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			r := strings.NewReader(tt.input)
			n, err := limits.LimitedCopy(&buf, r, tt.limit)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
					return
				}
				if _, ok := err.(*limits.ErrSizeLimitExceeded); !ok {
					t.Errorf("expected ErrSizeLimitExceeded, got %T: %v", err, err)
				}
				if n != tt.wantN {
					t.Errorf("got n=%d, want %d", n, tt.wantN)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if n != tt.wantN {
				t.Errorf("got n=%d, want %d", n, tt.wantN)
			}

			if buf.String() != tt.wantData {
				t.Errorf("got data %q, want %q", buf.String(), tt.wantData)
			}
		})
	}
}

func TestLimitedCopyOp(t *testing.T) {
	var buf bytes.Buffer
	r := strings.NewReader("too much data")
	_, err := limits.LimitedCopyOp(&buf, r, 5, "test operation")

	if err == nil {
		t.Fatal("expected error")
	}

	sizeErr, ok := err.(*limits.ErrSizeLimitExceeded)
	if !ok {
		t.Fatalf("expected ErrSizeLimitExceeded, got %T", err)
	}

	if sizeErr.Op != "test operation" {
		t.Errorf("got Op %q, want %q", sizeErr.Op, "test operation")
	}

	if sizeErr.Limit != 5 {
		t.Errorf("got Limit %d, want 5", sizeErr.Limit)
	}

	// Check error message contains operation name
	errStr := sizeErr.Error()
	if !strings.Contains(errStr, "test operation") {
		t.Errorf("error message %q should contain operation name", errStr)
	}
}

// TestLimitedCopy_WriterError verifies that writer errors are propagated
func TestLimitedCopy_WriterError(t *testing.T) {
	r := strings.NewReader("hello")
	w := &errorWriter{err: io.ErrShortWrite}
	_, err := limits.LimitedCopy(w, r, 100)
	if err != io.ErrShortWrite {
		t.Errorf("expected io.ErrShortWrite, got %v", err)
	}
}

type errorWriter struct {
	err error
}

func (w *errorWriter) Write(p []byte) (int, error) {
	return 0, w.err
}
