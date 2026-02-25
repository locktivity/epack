// Package output provides formatted output for the epack CLI.
//
// It handles human-readable vs JSON output, TTY detection, and NO_COLOR support.
package output

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/locktivity/epack/internal/redact"
	"golang.org/x/term"
)

// Options configures the output writer.
type Options struct {
	Quiet   bool // Suppress non-essential output
	JSON    bool // Output in JSON format
	NoColor bool // Disable colored output
	Verbose bool // Enable verbose output
	CI      bool // CI mode: disable spinners, add timestamps
}

// Writer handles formatted output for the CLI.
type Writer struct {
	stdout  io.Writer
	stderr  io.Writer
	opts    Options
	isTTY   bool
	palette *Palette
}

// New creates a new output writer.
func New(stdout, stderr io.Writer, opts Options) *Writer {
	isTTY := false
	if f, ok := stdout.(*os.File); ok {
		isTTY = term.IsTerminal(int(f.Fd()))
	}

	return &Writer{
		stdout:  stdout,
		stderr:  stderr,
		opts:    opts,
		isTTY:   isTTY,
		palette: NewPalette(!opts.NoColor && isTTY),
	}
}

// IsQuiet returns true if quiet mode is enabled.
func (w *Writer) IsQuiet() bool {
	return w.opts.Quiet
}

// IsJSON returns true if JSON output is enabled.
func (w *Writer) IsJSON() bool {
	return w.opts.JSON
}

// IsVerbose returns true if verbose output is enabled.
func (w *Writer) IsVerbose() bool {
	return w.opts.Verbose
}

// IsCI returns true if CI mode is enabled.
func (w *Writer) IsCI() bool {
	return w.opts.CI
}

// IsTTY returns true if stdout is a terminal.
func (w *Writer) IsTTY() bool {
	return w.isTTY
}

// Palette returns the color palette.
func (w *Writer) Palette() *Palette {
	return w.palette
}

// Print writes to stdout (respects quiet mode).
func (w *Writer) Print(format string, args ...interface{}) {
	if !w.opts.Quiet {
		_, _ = fmt.Fprintf(w.stdout, format, args...)
	}
}

// Println writes a line to stdout (respects quiet mode).
func (w *Writer) Println(args ...interface{}) {
	if !w.opts.Quiet {
		_, _ = fmt.Fprintln(w.stdout, args...)
	}
}

// PrintAlways writes to stdout even in quiet mode.
func (w *Writer) PrintAlways(format string, args ...interface{}) {
	_, _ = fmt.Fprintf(w.stdout, format, args...)
}

// Verbose writes to stdout only in verbose mode.
func (w *Writer) Verbose(format string, args ...interface{}) {
	if w.opts.Verbose && !w.opts.Quiet {
		_, _ = fmt.Fprintf(w.stdout, format, args...)
	}
}

// Error writes to stderr. File paths are redacted when redaction is enabled.
func (w *Writer) Error(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	_, _ = fmt.Fprint(w.stderr, redact.Error(msg))
}

// JSON writes a value as JSON to stdout.
func (w *Writer) JSON(v interface{}) error {
	enc := json.NewEncoder(w.stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// JSONCompact writes a value as compact JSON to stdout.
func (w *Writer) JSONCompact(v interface{}) error {
	return json.NewEncoder(w.stdout).Encode(v)
}

// Table creates a new table writer for tabular output.
func (w *Writer) Table() *TableWriter {
	return &TableWriter{
		tw:      tabwriter.NewWriter(w.stdout, 0, 0, 2, ' ', 0),
		palette: w.palette,
	}
}

// TableWriter handles tabular output.
type TableWriter struct {
	tw      *tabwriter.Writer
	palette *Palette
}

// Header writes a table header row.
func (t *TableWriter) Header(cols ...string) {
	for i, col := range cols {
		cols[i] = t.palette.Bold(col)
	}
	_, _ = fmt.Fprintln(t.tw, strings.Join(cols, "\t"))
}

// Row writes a table row.
func (t *TableWriter) Row(cols ...string) {
	_, _ = fmt.Fprintln(t.tw, strings.Join(cols, "\t"))
}

// Flush flushes the table output and returns any error encountered.
func (t *TableWriter) Flush() error {
	return t.tw.Flush()
}

// Section prints a section header.
func (w *Writer) Section(title string) {
	if w.opts.Quiet {
		return
	}
	_, _ = fmt.Fprintln(w.stdout)
	_, _ = fmt.Fprintln(w.stdout, w.palette.Bold(title))
}

// KeyValue prints a key-value pair with consistent formatting.
func (w *Writer) KeyValue(key, value string) {
	if w.opts.Quiet {
		return
	}
	_, _ = fmt.Fprintf(w.stdout, "  %-14s %s\n", w.palette.Dim(key+":"), value)
}

// Success prints a success message.
func (w *Writer) Success(format string, args ...interface{}) {
	if w.opts.Quiet {
		return
	}
	msg := fmt.Sprintf(format, args...)
	_, _ = fmt.Fprintln(w.stdout, w.palette.Green(msg))
}

// Warning prints a warning message. File paths are redacted when redaction is enabled.
func (w *Writer) Warning(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	msg = redact.Error(msg)
	_, _ = fmt.Fprintln(w.stderr, w.palette.Yellow("Warning: "+msg))
}

// Spinner provides animated progress indication for long-running operations.
// It displays a spinning animation in TTY mode, or falls back to simple
// status messages in non-TTY mode.
type Spinner struct {
	w         *Writer
	message   string
	done      chan struct{}
	stopped   bool
	mu        sync.Mutex
	closeOnce sync.Once       // prevents double-close panic on done channel
	ctx       context.Context // optional context for automatic cancellation
}

// spinnerFrames are the animation frames for the spinner.
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// StartSpinner begins a spinner with the given message.
// The spinner animates in TTY mode or prints a static message otherwise.
// Call Success(), Fail(), or Stop() to end the spinner.
// For automatic cleanup on context cancellation, use StartSpinnerWithContext.
func (w *Writer) StartSpinner(message string) *Spinner {
	return w.StartSpinnerWithContext(context.Background(), message)
}

// StartSpinnerWithContext begins a spinner that automatically stops when the context is cancelled.
// This prevents goroutine leaks if the caller panics or forgets to call Stop().
// The spinner animates in TTY mode or prints a static message otherwise.
// In CI mode, spinners are disabled and timestamps are added.
// Call Success(), Fail(), or Stop() to end the spinner, or let the context cancel it.
func (w *Writer) StartSpinnerWithContext(ctx context.Context, message string) *Spinner {
	if w.opts.Quiet || w.opts.JSON {
		return &Spinner{w: w, message: message, stopped: true, ctx: ctx}
	}

	s := &Spinner{
		w:       w,
		message: message,
		done:    make(chan struct{}),
		ctx:     ctx,
	}

	if w.isTTY && !w.opts.CI {
		go s.animate()
	} else {
		// Non-TTY or CI mode: print the message once with optional timestamp
		if w.opts.CI {
			_, _ = fmt.Fprintf(w.stdout, "[%s] %s...\n", time.Now().Format("15:04:05"), message)
		} else {
			_, _ = fmt.Fprintf(w.stdout, "%s...\n", message)
		}
	}

	return s
}

// animate runs the spinner animation in a goroutine.
func (s *Spinner) animate() {
	ticker := time.NewTicker(80 * time.Millisecond)
	defer ticker.Stop()

	// Get context done channel (nil if no context, which is fine for select)
	var ctxDone <-chan struct{}
	if s.ctx != nil {
		ctxDone = s.ctx.Done()
	}

	frame := 0
	for {
		select {
		case <-s.done:
			return
		case <-ctxDone:
			// Context cancelled - stop the spinner cleanly
			s.mu.Lock()
			if !s.stopped {
				s.stopped = true
				if s.w.isTTY {
					_, _ = fmt.Fprint(s.w.stdout, "\r\033[K")
				}
			}
			s.mu.Unlock()
			return
		case <-ticker.C:
			s.mu.Lock()
			if !s.stopped {
				// Clear line and print spinner frame
				_, _ = fmt.Fprintf(s.w.stdout, "\r%s %s", s.w.palette.Cyan(spinnerFrames[frame]), s.message)
				frame = (frame + 1) % len(spinnerFrames)
			}
			s.mu.Unlock()
		}
	}
}

// Success stops the spinner and shows a success message.
func (s *Spinner) Success(message string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.stopped {
		if !s.w.opts.Quiet && !s.w.opts.JSON {
			s.printResult(s.w.palette.Success(""), message)
		}
		return
	}
	s.stopped = true
	s.closeOnce.Do(func() { close(s.done) })

	if s.w.isTTY && !s.w.opts.CI {
		// Clear the spinner line and print success
		_, _ = fmt.Fprintf(s.w.stdout, "\r%s %s\n", s.w.palette.Success(""), message)
	} else {
		s.printResult(s.w.palette.Success(""), message)
	}
}

// printResult prints a result message with optional CI timestamp.
func (s *Spinner) printResult(indicator, message string) {
	if s.w.opts.CI {
		_, _ = fmt.Fprintf(s.w.stdout, "[%s] %s %s\n", time.Now().Format("15:04:05"), indicator, message)
	} else {
		_, _ = fmt.Fprintf(s.w.stdout, "%s %s\n", indicator, message)
	}
}

// Fail stops the spinner and shows a failure message.
func (s *Spinner) Fail(message string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.stopped {
		if !s.w.opts.Quiet && !s.w.opts.JSON {
			s.printResult(s.w.palette.Failure(""), message)
		}
		return
	}
	s.stopped = true
	s.closeOnce.Do(func() { close(s.done) })

	if s.w.isTTY && !s.w.opts.CI {
		// Clear the spinner line and print failure
		_, _ = fmt.Fprintf(s.w.stdout, "\r%s %s\n", s.w.palette.Failure(""), message)
	} else {
		s.printResult(s.w.palette.Failure(""), message)
	}
}

// Stop stops the spinner without showing a completion message.
func (s *Spinner) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.stopped {
		return
	}
	s.stopped = true
	s.closeOnce.Do(func() { close(s.done) })

	if s.w.isTTY {
		// Clear the spinner line
		_, _ = fmt.Fprint(s.w.stdout, "\r\033[K")
	}
}

// ProgressBar provides a progress indication for operations with known size.
// It displays a progress bar with percentage in TTY mode, or periodic
// percentage updates in non-TTY mode.
type ProgressBar struct {
	w            *Writer
	message      string
	total        int64
	current      int64
	lastPct      int
	mu           sync.Mutex
	stopped      bool
	barWidth     int
	lastUpdate   time.Time
	updatePeriod time.Duration // minimum time between non-TTY updates
}

// StartProgress begins a progress bar with the given message and total size.
// In TTY mode, it displays an animated bar. In non-TTY/CI mode, it prints
// periodic percentage updates.
func (w *Writer) StartProgress(message string, total int64) *ProgressBar {
	if w.opts.Quiet || w.opts.JSON {
		return &ProgressBar{w: w, stopped: true}
	}

	p := &ProgressBar{
		w:            w,
		message:      message,
		total:        total,
		barWidth:     30,
		updatePeriod: 5 * time.Second, // Update every 5s in non-TTY mode
	}

	// Print initial message
	if w.isTTY && !w.opts.CI {
		p.render()
	} else {
		if w.opts.CI {
			_, _ = fmt.Fprintf(w.stdout, "[%s] %s (0%%)\n", time.Now().Format("15:04:05"), message)
		} else {
			_, _ = fmt.Fprintf(w.stdout, "%s (0%%)\n", message)
		}
		p.lastUpdate = time.Now()
	}

	return p
}

// Update sets the current progress. Thread-safe.
func (p *ProgressBar) Update(current int64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.stopped {
		return
	}

	p.current = current
	pct := p.percent()

	if p.w.isTTY && !p.w.opts.CI {
		// TTY mode: update immediately
		p.render()
	} else {
		// Non-TTY mode: update periodically or at significant milestones
		shouldUpdate := pct != p.lastPct && (pct%25 == 0 || time.Since(p.lastUpdate) >= p.updatePeriod)
		if shouldUpdate {
			if p.w.opts.CI {
				_, _ = fmt.Fprintf(p.w.stdout, "[%s] %s (%d%%)\n", time.Now().Format("15:04:05"), p.message, pct)
			} else {
				_, _ = fmt.Fprintf(p.w.stdout, "%s (%d%%)\n", p.message, pct)
			}
			p.lastUpdate = time.Now()
			p.lastPct = pct
		}
	}
}

// Done completes the progress bar with a success message.
func (p *ProgressBar) Done(message string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.stopped {
		return
	}
	p.stopped = true

	if p.w.isTTY && !p.w.opts.CI {
		// Clear the progress bar line and print success
		_, _ = fmt.Fprintf(p.w.stdout, "\r\033[K%s %s\n", p.w.palette.Success(""), message)
	} else {
		if p.w.opts.CI {
			_, _ = fmt.Fprintf(p.w.stdout, "[%s] %s %s\n", time.Now().Format("15:04:05"), p.w.palette.Success(""), message)
		} else {
			_, _ = fmt.Fprintf(p.w.stdout, "%s %s\n", p.w.palette.Success(""), message)
		}
	}
}

// Fail stops the progress bar and shows a failure message.
func (p *ProgressBar) Fail(message string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.stopped {
		return
	}
	p.stopped = true

	if p.w.isTTY && !p.w.opts.CI {
		// Clear the progress bar line and print failure
		_, _ = fmt.Fprintf(p.w.stdout, "\r\033[K%s %s\n", p.w.palette.Failure(""), message)
	} else {
		if p.w.opts.CI {
			_, _ = fmt.Fprintf(p.w.stdout, "[%s] %s %s\n", time.Now().Format("15:04:05"), p.w.palette.Failure(""), message)
		} else {
			_, _ = fmt.Fprintf(p.w.stdout, "%s %s\n", p.w.palette.Failure(""), message)
		}
	}
}

// percent returns the current percentage (0-100).
func (p *ProgressBar) percent() int {
	if p.total <= 0 {
		return 0
	}
	pct := int(p.current * 100 / p.total)
	if pct > 100 {
		pct = 100
	}
	return pct
}

// render draws the progress bar (TTY only, must hold mutex).
func (p *ProgressBar) render() {
	pct := p.percent()
	filled := pct * p.barWidth / 100
	empty := p.barWidth - filled

	bar := strings.Repeat("█", filled) + strings.Repeat("░", empty)
	sizeStr := fmt.Sprintf("%s / %s", FormatBytes(p.current), FormatBytes(p.total))

	// \r moves to start of line, then print bar
	_, _ = fmt.Fprintf(p.w.stdout, "\r%s %s %3d%% %s",
		p.w.palette.Cyan(p.message),
		p.w.palette.Dim("["+bar+"]"),
		pct,
		p.w.palette.Dim(sizeStr))
}

// ProgressReader wraps an io.Reader to report progress to a ProgressBar.
type ProgressReader struct {
	reader io.Reader
	bar    *ProgressBar
	read   int64
}

// NewProgressReader creates a reader that updates the progress bar as data is read.
func NewProgressReader(r io.Reader, bar *ProgressBar) *ProgressReader {
	return &ProgressReader{reader: r, bar: bar}
}

// Read implements io.Reader and updates progress.
func (pr *ProgressReader) Read(p []byte) (int, error) {
	n, err := pr.reader.Read(p)
	if n > 0 {
		pr.read += int64(n)
		pr.bar.Update(pr.read)
	}
	return n, err
}

// Prompt reads a line of text from stdin, displaying the given prompt.
// Returns the trimmed input and any error. If stdin is not a TTY, returns
// ErrNotInteractive.
func (w *Writer) Prompt(prompt string) (string, error) {
	if !w.isTTY {
		return "", ErrNotInteractive
	}

	_, _ = fmt.Fprint(w.stdout, prompt)

	// Read from stdin
	var input string
	_, err := fmt.Scanln(&input)
	if err != nil && err.Error() == "unexpected newline" {
		// Empty input is OK
		return "", nil
	}
	return strings.TrimSpace(input), err
}

// PromptWithDefault reads input with a default value shown in brackets.
// If user enters empty input, returns the default.
func (w *Writer) PromptWithDefault(prompt, defaultVal string) (string, error) {
	if !w.isTTY {
		return "", ErrNotInteractive
	}

	fullPrompt := fmt.Sprintf("%s [%s]: ", prompt, defaultVal)
	_, _ = fmt.Fprint(w.stdout, fullPrompt)

	var input string
	_, err := fmt.Scanln(&input)
	if err != nil && err.Error() == "unexpected newline" {
		// Empty input - use default
		return defaultVal, nil
	}
	if err != nil {
		return defaultVal, err
	}

	input = strings.TrimSpace(input)
	if input == "" {
		return defaultVal, nil
	}
	return input, nil
}

// PromptRequired keeps prompting until non-empty input is provided.
// Returns ErrNotInteractive if stdin is not a TTY.
func (w *Writer) PromptRequired(prompt string) (string, error) {
	if !w.isTTY {
		return "", ErrNotInteractive
	}

	for {
		_, _ = fmt.Fprint(w.stdout, prompt)

		var input string
		_, err := fmt.Scanln(&input)
		if err != nil && err.Error() != "unexpected newline" {
			return "", err
		}

		input = strings.TrimSpace(input)
		if input != "" {
			return input, nil
		}

		_, _ = fmt.Fprintln(w.stdout, w.palette.Red("This field is required."))
	}
}

// ErrNotInteractive is returned when prompts are attempted in non-TTY mode.
var ErrNotInteractive = fmt.Errorf("cannot prompt: not running in interactive terminal")

// PromptConfirm asks a yes/no question and returns true if the user confirms.
// Default is yes (pressing Enter confirms). Returns false in non-TTY mode.
func (w *Writer) PromptConfirm(format string, args ...interface{}) bool {
	if !w.isTTY {
		return false
	}

	message := fmt.Sprintf(format, args...)
	_, _ = fmt.Fprintf(w.stdout, "%s [Y/n]: ", message)

	var input string
	_, err := fmt.Scanln(&input)
	if err != nil && err.Error() == "unexpected newline" {
		// Empty input = yes (default)
		return true
	}
	if err != nil {
		return false
	}

	input = strings.TrimSpace(strings.ToLower(input))
	return input == "" || input == "y" || input == "yes"
}

// StepTracker provides multi-step progress tracking for complex operations.
// It shows completed steps with checkmarks and the current step with a spinner.
type StepTracker struct {
	w       *Writer
	steps   []string
	current int
	spinner *Spinner
	mu      sync.Mutex
}

// StartSteps begins a multi-step operation with the given step names.
// Each step should be a short description (e.g., "Verifying pack integrity").
func (w *Writer) StartSteps(steps []string) *StepTracker {
	if w.opts.Quiet || w.opts.JSON {
		return &StepTracker{w: w, steps: steps}
	}

	return &StepTracker{
		w:       w,
		steps:   steps,
		current: -1,
	}
}

// Next advances to the next step. Returns false if all steps are complete.
// The previous step is marked as complete with a checkmark.
func (st *StepTracker) Next() bool {
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.w.opts.Quiet || st.w.opts.JSON {
		st.current++
		return st.current < len(st.steps)
	}

	// Complete the current step's spinner
	if st.spinner != nil {
		st.spinner.Success(st.steps[st.current])
	}

	st.current++
	if st.current >= len(st.steps) {
		return false
	}

	// Start spinner for next step
	st.spinner = st.w.StartSpinnerWithContext(context.Background(), st.steps[st.current])
	return true
}

// Current returns the current step index (0-based).
func (st *StepTracker) Current() int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.current
}

// CurrentStep returns the name of the current step.
func (st *StepTracker) CurrentStep() string {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.current < 0 || st.current >= len(st.steps) {
		return ""
	}
	return st.steps[st.current]
}

// Fail marks the current step as failed and stops tracking.
func (st *StepTracker) Fail(message string) {
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.spinner != nil {
		st.spinner.Fail(message)
		st.spinner = nil
	}
}

// Complete marks the final step as complete.
func (st *StepTracker) Complete() {
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.spinner != nil {
		if st.current >= 0 && st.current < len(st.steps) {
			st.spinner.Success(st.steps[st.current])
		}
		st.spinner = nil
	}
}
