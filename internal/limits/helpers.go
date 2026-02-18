// Package limits provides helper functions for enforcing resource limits.
package limits

import (
	"fmt"
	"io"
	"math"
	"sync/atomic"
)

// ErrSizeLimitExceeded is returned when a read operation exceeds the size limit.
type ErrSizeLimitExceeded struct {
	Limit int64
	Op    string // optional: operation name for context
}

func (e *ErrSizeLimitExceeded) Error() string {
	if e.Op != "" {
		return fmt.Sprintf("%s: size limit exceeded (%d bytes)", e.Op, e.Limit)
	}
	return fmt.Sprintf("size limit exceeded (%d bytes)", e.Limit)
}

// ErrBudgetExhausted is returned when an operation's budget is exhausted.
type ErrBudgetExhausted struct {
	Limit int64
	Used  int64
}

func (e *ErrBudgetExhausted) Error() string {
	return fmt.Sprintf("budget exhausted: used %d of %d bytes", e.Used, e.Limit)
}

// ErrRecursionLimitExceeded is returned when recursion depth exceeds the limit.
type ErrRecursionLimitExceeded struct {
	Depth    int
	MaxDepth int
}

func (e *ErrRecursionLimitExceeded) Error() string {
	return fmt.Sprintf("recursion depth %d exceeds maximum %d", e.Depth, e.MaxDepth)
}

// ReadAllWithLimit reads at most limit bytes and returns ErrSizeLimitExceeded when input is larger.
func ReadAllWithLimit(r io.Reader, limit int64) ([]byte, error) {
	return ReadAllWithLimitOp(r, limit, "")
}

// ReadAllWithLimitOp reads all data from r up to limit bytes.
// The op parameter provides context for error messages.
func ReadAllWithLimitOp(r io.Reader, limit int64, op string) ([]byte, error) {
	limited := io.LimitReader(r, limit+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, &ErrSizeLimitExceeded{Limit: limit, Op: op}
	}
	return data, nil
}

// LimitedCopy copies from src to dst with a byte limit.
// Returns ErrSizeLimitExceeded if the source exceeds the limit.
// Unlike io.Copy with LimitReader alone, this explicitly errors rather than silently truncating.
func LimitedCopy(dst io.Writer, src io.Reader, limit int64) (int64, error) {
	return LimitedCopyOp(dst, src, limit, "")
}

// LimitedCopyOp is like LimitedCopy but includes an operation name in errors.
func LimitedCopyOp(dst io.Writer, src io.Reader, limit int64, op string) (int64, error) {
	n, err := io.Copy(dst, io.LimitReader(src, limit+1))
	if err != nil {
		return n, err
	}
	if n > limit {
		return n, &ErrSizeLimitExceeded{Limit: limit, Op: op}
	}
	return n, nil
}

// Budget tracks cumulative resource usage across operations.
// Budget is safe for concurrent use.
//
// Example usage:
//
//	budget := limits.NewBudget(limits.MaxPackSizeBytes, limits.MaxArtifactCount)
//	for _, file := range files {
//	    if !budget.ReserveBytes(file.Size) {
//	        return errors.New("pack size limit exceeded")
//	    }
//	    if !budget.ReserveCount() {
//	        return errors.New("artifact count limit exceeded")
//	    }
//	    // process file
//	}
type Budget struct {
	maxBytes  int64
	maxCount  int64
	bytesUsed atomic.Int64
	countUsed atomic.Int64
}

// NewBudget creates a budget with the specified byte and count limits.
// Pass 0 for a limit to disable that constraint.
func NewBudget(maxBytes int64, maxCount int) *Budget {
	return &Budget{
		maxBytes: maxBytes,
		maxCount: int64(maxCount),
	}
}

// NewBytesBudget creates a budget with only a byte limit.
func NewBytesBudget(maxBytes int64) *Budget {
	return &Budget{
		maxBytes: maxBytes,
		maxCount: 0, // no count limit
	}
}

// ReserveBytes attempts to atomically reserve n bytes from the budget.
// Returns true if reservation succeeded, false if budget would be exceeded.
//
// SECURITY: Uses compare-and-swap to prevent concurrent readers from overshooting.
func (b *Budget) ReserveBytes(n int64) bool {
	if b.maxBytes <= 0 {
		return true // no limit
	}
	for {
		current := b.bytesUsed.Load()
		if current+n > b.maxBytes {
			return false
		}
		if b.bytesUsed.CompareAndSwap(current, current+n) {
			return true
		}
		// CAS failed, another goroutine modified the counter; retry
	}
}

// ReserveBytesUpTo attempts to reserve up to n bytes, reserving as much as available.
// Returns the number of bytes actually reserved (may be less than n if near limit).
// Returns 0 if no budget is available.
func (b *Budget) ReserveBytesUpTo(n int64) int64 {
	if b.maxBytes <= 0 {
		return n // no limit
	}
	for {
		current := b.bytesUsed.Load()
		available := b.maxBytes - current
		if available <= 0 {
			return 0
		}
		toReserve := n
		if toReserve > available {
			toReserve = available
		}
		if b.bytesUsed.CompareAndSwap(current, current+toReserve) {
			return toReserve
		}
		// CAS failed, retry
	}
}

// ReleaseBytes releases previously reserved bytes back to the budget.
// This is useful when a reservation was made but the operation was cancelled.
func (b *Budget) ReleaseBytes(n int64) {
	b.bytesUsed.Add(-n)
}

// ReserveCount attempts to reserve one count from the budget.
// Returns true if reservation succeeded, false if count limit reached.
func (b *Budget) ReserveCount() bool {
	if b.maxCount <= 0 {
		return true // no limit
	}
	for {
		current := b.countUsed.Load()
		if current >= b.maxCount {
			return false
		}
		if b.countUsed.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

// BytesRemaining returns the remaining bytes in the budget.
func (b *Budget) BytesRemaining() int64 {
	if b.maxBytes <= 0 {
		return int64(^uint64(0) >> 1) // MaxInt64
	}
	remaining := b.maxBytes - b.bytesUsed.Load()
	if remaining < 0 {
		return 0
	}
	return remaining
}

// BytesUsed returns the number of bytes used from the budget.
func (b *Budget) BytesUsed() int64 {
	return b.bytesUsed.Load()
}

// CountRemaining returns the remaining count in the budget.
// Returns math.MaxInt if the budget is unlimited or remaining exceeds int range.
func (b *Budget) CountRemaining() int {
	if b.maxCount <= 0 {
		return math.MaxInt
	}
	remaining := b.maxCount - b.countUsed.Load()
	if remaining < 0 {
		return 0
	}
	// Prevent overflow on 32-bit systems where int is 32 bits
	if remaining > int64(math.MaxInt) {
		return math.MaxInt
	}
	return int(remaining)
}

// RecursionGuard prevents stack overflow from deep recursion.
// NOT safe for concurrent use - use one per goroutine.
//
// Example usage:
//
//	func traverse(node *Node, guard *limits.RecursionGuard) error {
//	    if err := guard.Enter(); err != nil {
//	        return err
//	    }
//	    defer guard.Leave()
//	    // process node and recurse...
//	}
type RecursionGuard struct {
	depth    int
	maxDepth int
}

// NewRecursionGuard creates a guard with the specified max depth.
func NewRecursionGuard(maxDepth int) *RecursionGuard {
	return &RecursionGuard{maxDepth: maxDepth}
}

// Enter increments depth and returns error if max exceeded.
// Must call Leave() after Enter() returns nil.
// If Enter() returns an error, depth is NOT incremented and Leave() should NOT be called.
func (g *RecursionGuard) Enter() error {
	if g.depth >= g.maxDepth {
		return &ErrRecursionLimitExceeded{Depth: g.depth + 1, MaxDepth: g.maxDepth}
	}
	g.depth++
	return nil
}

// Leave decrements depth. Must be called after Enter returns nil.
func (g *RecursionGuard) Leave() {
	if g.depth > 0 {
		g.depth--
	}
}

// Depth returns the current recursion depth.
func (g *RecursionGuard) Depth() int {
	return g.depth
}

// LimitedWriter forwards writes up to limit bytes and discards the remainder.
// It reports len(p) to avoid breaking subprocess pipes.
//
// LimitedWriter is safe for concurrent use.
type LimitedWriter struct {
	w       io.Writer
	limit   int64
	written atomic.Int64
}

// NewLimitedWriter creates a writer that accepts at most limit bytes.
// Excess bytes are silently discarded (returns original length to caller).
func NewLimitedWriter(w io.Writer, limit int64) *LimitedWriter {
	return &LimitedWriter{
		w:     w,
		limit: limit,
	}
}

// Write implements io.Writer. Bytes beyond the limit are silently discarded.
// Write is safe for concurrent use.
func (l *LimitedWriter) Write(p []byte) (n int, err error) {
	originalLen := len(p)

	// Use compare-and-swap loop to atomically reserve write space
	for {
		current := l.written.Load()
		if current >= l.limit {
			// Silently discard excess data to prevent breaking subprocesses
			return originalLen, nil
		}

		remaining := l.limit - current
		toWrite := int64(len(p))
		if toWrite > remaining {
			toWrite = remaining
		}

		// Try to reserve the space atomically
		if l.written.CompareAndSwap(current, current+toWrite) {
			// We reserved the space, now write
			if toWrite > 0 {
				_, err = l.w.Write(p[:toWrite])
			}
			return originalLen, err // Report full length written to avoid breaking the subprocess
		}
		// CAS failed, another goroutine wrote concurrently; retry
	}
}

// Written returns the number of bytes written (not discarded).
func (l *LimitedWriter) Written() int64 {
	return l.written.Load()
}

// Truncated reports whether writes hit the configured byte limit.
func (l *LimitedWriter) Truncated() bool {
	return l.written.Load() >= l.limit
}
