package output

import (
	"bytes"
	"context"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	w := New(stdout, stderr, Options{})

	if w == nil {
		t.Fatal("New returned nil")
	}
	if w.stdout != stdout {
		t.Error("stdout not set correctly")
	}
	if w.stderr != stderr {
		t.Error("stderr not set correctly")
	}
	if w.palette == nil {
		t.Error("palette is nil")
	}
}

func TestWriter_Flags(t *testing.T) {
	tests := []struct {
		name    string
		opts    Options
		quiet   bool
		json    bool
		verbose bool
	}{
		{"defaults", Options{}, false, false, false},
		{"quiet", Options{Quiet: true}, true, false, false},
		{"json", Options{JSON: true}, false, true, false},
		{"verbose", Options{Verbose: true}, false, false, true},
		{"all", Options{Quiet: true, JSON: true, Verbose: true}, true, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := New(&bytes.Buffer{}, &bytes.Buffer{}, tt.opts)
			if w.IsQuiet() != tt.quiet {
				t.Errorf("IsQuiet() = %v, want %v", w.IsQuiet(), tt.quiet)
			}
			if w.IsJSON() != tt.json {
				t.Errorf("IsJSON() = %v, want %v", w.IsJSON(), tt.json)
			}
			if w.IsVerbose() != tt.verbose {
				t.Errorf("IsVerbose() = %v, want %v", w.IsVerbose(), tt.verbose)
			}
		})
	}
}

func TestWriter_Print(t *testing.T) {
	stdout := &bytes.Buffer{}
	w := New(stdout, &bytes.Buffer{}, Options{})

	w.Print("hello %s", "world")
	if got := stdout.String(); got != "hello world" {
		t.Errorf("Print() = %q, want %q", got, "hello world")
	}
}

func TestWriter_Print_Quiet(t *testing.T) {
	stdout := &bytes.Buffer{}
	w := New(stdout, &bytes.Buffer{}, Options{Quiet: true})

	w.Print("hello %s", "world")
	if got := stdout.String(); got != "" {
		t.Errorf("Print() in quiet mode = %q, want empty", got)
	}
}

func TestWriter_Println(t *testing.T) {
	stdout := &bytes.Buffer{}
	w := New(stdout, &bytes.Buffer{}, Options{})

	w.Println("hello", "world")
	if got := stdout.String(); got != "hello world\n" {
		t.Errorf("Println() = %q, want %q", got, "hello world\n")
	}
}

func TestWriter_Println_Quiet(t *testing.T) {
	stdout := &bytes.Buffer{}
	w := New(stdout, &bytes.Buffer{}, Options{Quiet: true})

	w.Println("hello")
	if got := stdout.String(); got != "" {
		t.Errorf("Println() in quiet mode = %q, want empty", got)
	}
}

func TestWriter_PrintAlways(t *testing.T) {
	stdout := &bytes.Buffer{}
	w := New(stdout, &bytes.Buffer{}, Options{Quiet: true})

	w.PrintAlways("important: %s", "message")
	if got := stdout.String(); got != "important: message" {
		t.Errorf("PrintAlways() = %q, want %q", got, "important: message")
	}
}

func TestWriter_Verbose(t *testing.T) {
	tests := []struct {
		name   string
		opts   Options
		expect string
	}{
		{"verbose enabled", Options{Verbose: true}, "debug info"},
		{"verbose disabled", Options{Verbose: false}, ""},
		{"verbose but quiet", Options{Verbose: true, Quiet: true}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout := &bytes.Buffer{}
			w := New(stdout, &bytes.Buffer{}, tt.opts)
			w.Verbose("debug info")
			if got := stdout.String(); got != tt.expect {
				t.Errorf("Verbose() = %q, want %q", got, tt.expect)
			}
		})
	}
}

func TestWriter_Error(t *testing.T) {
	stderr := &bytes.Buffer{}
	w := New(&bytes.Buffer{}, stderr, Options{})

	w.Error("error: %s", "something failed")
	if got := stderr.String(); got != "error: something failed" {
		t.Errorf("Error() = %q, want %q", got, "error: something failed")
	}
}

func TestWriter_Error_IgnoresQuiet(t *testing.T) {
	stderr := &bytes.Buffer{}
	w := New(&bytes.Buffer{}, stderr, Options{Quiet: true})

	w.Error("error message")
	if got := stderr.String(); got != "error message" {
		t.Errorf("Error() should ignore quiet mode, got %q", got)
	}
}

func TestWriter_JSON(t *testing.T) {
	stdout := &bytes.Buffer{}
	w := New(stdout, &bytes.Buffer{}, Options{})

	data := map[string]string{"key": "value"}
	if err := w.JSON(data); err != nil {
		t.Fatalf("JSON() error: %v", err)
	}

	// Verify it's valid JSON with indentation
	got := stdout.String()
	if !strings.Contains(got, "  ") {
		t.Error("JSON() should produce indented output")
	}

	var decoded map[string]string
	if err := json.Unmarshal([]byte(got), &decoded); err != nil {
		t.Fatalf("JSON() produced invalid JSON: %v", err)
	}
	if decoded["key"] != "value" {
		t.Errorf("decoded key = %q, want %q", decoded["key"], "value")
	}
}

func TestWriter_JSONCompact(t *testing.T) {
	stdout := &bytes.Buffer{}
	w := New(stdout, &bytes.Buffer{}, Options{})

	data := map[string]string{"key": "value"}
	if err := w.JSONCompact(data); err != nil {
		t.Fatalf("JSONCompact() error: %v", err)
	}

	got := strings.TrimSpace(stdout.String())
	if got != `{"key":"value"}` {
		t.Errorf("JSONCompact() = %q, want %q", got, `{"key":"value"}`)
	}
}

func TestTableWriter(t *testing.T) {
	stdout := &bytes.Buffer{}
	w := New(stdout, &bytes.Buffer{}, Options{NoColor: true})

	table := w.Table()
	table.Header("NAME", "VALUE")
	table.Row("foo", "bar")
	table.Row("baz", "qux")
	_ = table.Flush()

	got := stdout.String()
	if !strings.Contains(got, "NAME") {
		t.Error("Table output missing header NAME")
	}
	if !strings.Contains(got, "foo") {
		t.Error("Table output missing row foo")
	}
	if !strings.Contains(got, "baz") {
		t.Error("Table output missing row baz")
	}
}

func TestWriter_Section(t *testing.T) {
	stdout := &bytes.Buffer{}
	w := New(stdout, &bytes.Buffer{}, Options{NoColor: true})

	w.Section("Test Section")
	got := stdout.String()
	if !strings.Contains(got, "Test Section") {
		t.Errorf("Section() = %q, missing title", got)
	}
}

func TestWriter_Section_Quiet(t *testing.T) {
	stdout := &bytes.Buffer{}
	w := New(stdout, &bytes.Buffer{}, Options{Quiet: true})

	w.Section("Test Section")
	if got := stdout.String(); got != "" {
		t.Errorf("Section() in quiet mode = %q, want empty", got)
	}
}

func TestWriter_KeyValue(t *testing.T) {
	stdout := &bytes.Buffer{}
	w := New(stdout, &bytes.Buffer{}, Options{NoColor: true})

	w.KeyValue("Name", "test")
	got := stdout.String()
	if !strings.Contains(got, "Name:") {
		t.Errorf("KeyValue() = %q, missing key", got)
	}
	if !strings.Contains(got, "test") {
		t.Errorf("KeyValue() = %q, missing value", got)
	}
}

func TestWriter_KeyValue_Quiet(t *testing.T) {
	stdout := &bytes.Buffer{}
	w := New(stdout, &bytes.Buffer{}, Options{Quiet: true})

	w.KeyValue("Name", "test")
	if got := stdout.String(); got != "" {
		t.Errorf("KeyValue() in quiet mode = %q, want empty", got)
	}
}

func TestWriter_Success(t *testing.T) {
	stdout := &bytes.Buffer{}
	w := New(stdout, &bytes.Buffer{}, Options{NoColor: true})

	w.Success("operation completed")
	got := stdout.String()
	if !strings.Contains(got, "operation completed") {
		t.Errorf("Success() = %q, missing message", got)
	}
}

func TestWriter_Success_Quiet(t *testing.T) {
	stdout := &bytes.Buffer{}
	w := New(stdout, &bytes.Buffer{}, Options{Quiet: true})

	w.Success("operation completed")
	if got := stdout.String(); got != "" {
		t.Errorf("Success() in quiet mode = %q, want empty", got)
	}
}

func TestWriter_Warning(t *testing.T) {
	stderr := &bytes.Buffer{}
	w := New(&bytes.Buffer{}, stderr, Options{NoColor: true})

	w.Warning("something %s", "happened")
	got := stderr.String()
	if !strings.Contains(got, "Warning:") {
		t.Errorf("Warning() = %q, missing prefix", got)
	}
	if !strings.Contains(got, "something happened") {
		t.Errorf("Warning() = %q, missing message", got)
	}
}

func TestWriter_Palette(t *testing.T) {
	w := New(&bytes.Buffer{}, &bytes.Buffer{}, Options{})
	if w.Palette() == nil {
		t.Error("Palette() returned nil")
	}
}

func TestWriter_IsTTY_NonFile(t *testing.T) {
	// bytes.Buffer is not a file, so IsTTY should be false
	w := New(&bytes.Buffer{}, &bytes.Buffer{}, Options{})
	if w.IsTTY() {
		t.Error("IsTTY() should be false for non-file writer")
	}
}

func TestSpinner_NonTTY_Success(t *testing.T) {
	stdout := &bytes.Buffer{}
	w := New(stdout, &bytes.Buffer{}, Options{NoColor: true})

	spinner := w.StartSpinner("Processing")
	spinner.Success("Done")

	got := stdout.String()
	if !strings.Contains(got, "Processing") {
		t.Errorf("Spinner output missing initial message, got %q", got)
	}
	if !strings.Contains(got, "Done") {
		t.Errorf("Spinner output missing success message, got %q", got)
	}
}

func TestSpinner_NonTTY_Fail(t *testing.T) {
	stdout := &bytes.Buffer{}
	w := New(stdout, &bytes.Buffer{}, Options{NoColor: true})

	spinner := w.StartSpinner("Processing")
	spinner.Fail("Error occurred")

	got := stdout.String()
	if !strings.Contains(got, "Processing") {
		t.Errorf("Spinner output missing initial message, got %q", got)
	}
	if !strings.Contains(got, "Error occurred") {
		t.Errorf("Spinner output missing failure message, got %q", got)
	}
}

func TestSpinner_Quiet(t *testing.T) {
	stdout := &bytes.Buffer{}
	w := New(stdout, &bytes.Buffer{}, Options{Quiet: true})

	spinner := w.StartSpinner("Processing")
	spinner.Success("Done")

	if got := stdout.String(); got != "" {
		t.Errorf("Spinner in quiet mode = %q, want empty", got)
	}
}

func TestSpinner_JSON(t *testing.T) {
	stdout := &bytes.Buffer{}
	w := New(stdout, &bytes.Buffer{}, Options{JSON: true})

	spinner := w.StartSpinner("Processing")
	spinner.Success("Done")

	if got := stdout.String(); got != "" {
		t.Errorf("Spinner in JSON mode = %q, want empty", got)
	}
}

func TestSpinner_Stop(t *testing.T) {
	stdout := &bytes.Buffer{}
	w := New(stdout, &bytes.Buffer{}, Options{NoColor: true})

	spinner := w.StartSpinner("Processing")
	spinner.Stop()

	// Should have printed the initial message but nothing else
	got := stdout.String()
	if !strings.Contains(got, "Processing") {
		t.Errorf("Spinner output missing initial message, got %q", got)
	}
}

func TestSpinner_DoubleStop(t *testing.T) {
	stdout := &bytes.Buffer{}
	w := New(stdout, &bytes.Buffer{}, Options{NoColor: true})

	spinner := w.StartSpinner("Processing")
	spinner.Stop()
	// Second stop should not panic
	spinner.Stop()
}

func TestSpinner_SuccessAfterStop(t *testing.T) {
	stdout := &bytes.Buffer{}
	w := New(stdout, &bytes.Buffer{}, Options{NoColor: true})

	spinner := w.StartSpinner("Processing")
	spinner.Stop()
	// Calling Success after Stop should still print the success message
	spinner.Success("Done anyway")

	got := stdout.String()
	if !strings.Contains(got, "Done anyway") {
		t.Errorf("Spinner success after stop missing message, got %q", got)
	}
}

func TestSpinner_WithContext_Cancellation(t *testing.T) {
	stdout := &bytes.Buffer{}
	w := New(stdout, &bytes.Buffer{}, Options{NoColor: true})
	// Force TTY mode to test the goroutine path
	w.isTTY = true

	ctx, cancel := context.WithCancel(context.Background())

	// Count goroutines before
	goroutinesBefore := runtime.NumGoroutine()

	spinner := w.StartSpinnerWithContext(ctx, "Processing")

	// Give the goroutine time to start
	time.Sleep(50 * time.Millisecond)

	// Cancel the context
	cancel()

	// Give the goroutine time to stop
	time.Sleep(150 * time.Millisecond)

	// Check spinner is stopped
	spinner.mu.Lock()
	stopped := spinner.stopped
	spinner.mu.Unlock()

	if !stopped {
		t.Error("Spinner should be stopped after context cancellation")
	}

	// Check goroutine count returns to normal (with some tolerance for GC)
	goroutinesAfter := runtime.NumGoroutine()
	if goroutinesAfter > goroutinesBefore+1 {
		t.Errorf("Possible goroutine leak: before=%d, after=%d", goroutinesBefore, goroutinesAfter)
	}
}

func TestSpinner_WithContext_NoLeak(t *testing.T) {
	stdout := &bytes.Buffer{}
	w := New(stdout, &bytes.Buffer{}, Options{NoColor: true})
	// Force TTY mode to test the goroutine path
	w.isTTY = true

	goroutinesBefore := runtime.NumGoroutine()

	// Start and stop multiple spinners with context
	for i := 0; i < 5; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		spinner := w.StartSpinnerWithContext(ctx, "Processing")
		time.Sleep(20 * time.Millisecond)
		cancel()
		// Also explicitly stop to test both paths
		spinner.Stop()
		time.Sleep(20 * time.Millisecond)
	}

	// Allow time for goroutines to clean up
	time.Sleep(100 * time.Millisecond)

	goroutinesAfter := runtime.NumGoroutine()
	// Allow for some variance due to runtime goroutines
	if goroutinesAfter > goroutinesBefore+2 {
		t.Errorf("Goroutine leak detected: before=%d, after=%d", goroutinesBefore, goroutinesAfter)
	}
}
