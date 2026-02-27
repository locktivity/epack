package collector

import (
	"runtime"
	"sync/atomic"
	"testing"
)

func TestEffectiveParallelism(t *testing.T) {
	tests := []struct {
		name           string
		configured     int
		collectorCount int
		wantMin        int
		wantMax        int
	}{
		{
			name:           "zero collectors returns 1",
			configured:     0,
			collectorCount: 0,
			wantMin:        1,
			wantMax:        1,
		},
		{
			name:           "one collector returns 1",
			configured:     0,
			collectorCount: 1,
			wantMin:        1,
			wantMax:        1,
		},
		{
			name:           "explicit sequential",
			configured:     1,
			collectorCount: 10,
			wantMin:        1,
			wantMax:        1,
		},
		{
			name:           "explicit parallel capped by collector count",
			configured:     10,
			collectorCount: 3,
			wantMin:        3,
			wantMax:        3,
		},
		{
			name:           "explicit parallel used when less than collector count",
			configured:     2,
			collectorCount: 10,
			wantMin:        2,
			wantMax:        2,
		},
		{
			name:           "auto mode caps at 8",
			configured:     0,
			collectorCount: 100,
			wantMin:        1,
			wantMax:        8,
		},
		{
			name:           "auto mode uses collector count if smaller",
			configured:     0,
			collectorCount: 3,
			wantMin:        1,
			wantMax:        3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := effectiveParallelism(tt.configured, tt.collectorCount)
			if got < tt.wantMin || got > tt.wantMax {
				t.Errorf("effectiveParallelism(%d, %d) = %d, want between %d and %d",
					tt.configured, tt.collectorCount, got, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestEffectiveParallelism_AutoConsidersNumCPU(t *testing.T) {
	numCPU := runtime.NumCPU()
	got := effectiveParallelism(0, 100)

	// Auto should be at most min(numCPU, 8)
	expectedMax := numCPU
	if expectedMax > 8 {
		expectedMax = 8
	}
	if got > expectedMax {
		t.Errorf("effectiveParallelism(0, 100) = %d, want at most %d (NumCPU=%d)",
			got, expectedMax, numCPU)
	}
}

func TestParallelResults(t *testing.T) {
	t.Run("set and get results", func(t *testing.T) {
		pr := newParallelResults(3)

		pr.set(0, RunResult{Collector: "a", Success: true})
		pr.set(1, RunResult{Collector: "b", Success: false, Error: errTest})
		pr.set(2, RunResult{Collector: "c", Success: true})

		if pr.results[0].Collector != "a" {
			t.Errorf("expected collector 'a' at index 0")
		}
		if pr.results[1].Collector != "b" {
			t.Errorf("expected collector 'b' at index 1")
		}
		if pr.results[2].Collector != "c" {
			t.Errorf("expected collector 'c' at index 2")
		}

		if got := pr.getFailures(); got != 1 {
			t.Errorf("getFailures() = %d, want 1", got)
		}
	})

	t.Run("concurrent set is safe", func(t *testing.T) {
		const n = 100
		pr := newParallelResults(n)
		var done int64

		// Simulate concurrent writes from multiple goroutines
		for i := 0; i < n; i++ {
			go func(idx int) {
				success := idx%2 == 0
				pr.set(idx, RunResult{
					Collector: string(rune('a' + idx%26)),
					Success:   success,
				})
				atomic.AddInt64(&done, 1)
			}(i)
		}

		// Wait for all goroutines
		for atomic.LoadInt64(&done) < n {
			runtime.Gosched()
		}

		// Verify all slots are filled
		for i := 0; i < n; i++ {
			if pr.results[i].Collector == "" {
				t.Errorf("slot %d not filled", i)
			}
		}

		// Verify failure count (half should fail)
		expectedFailures := n / 2
		if got := pr.getFailures(); got != expectedFailures {
			t.Errorf("getFailures() = %d, want %d", got, expectedFailures)
		}
	})
}

var errTest = error(nil)

func init() {
	errTest = &testError{}
}

type testError struct{}

func (e *testError) Error() string { return "test error" }
