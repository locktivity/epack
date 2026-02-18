// Package progress provides progress tracking for I/O operations.
package progress

import "io"

// Callback is called with current bytes processed and total size.
// For uploads, current is bytes written. For downloads, current is bytes read.
type Callback func(current, total int64)

// Reader wraps an io.Reader to report read progress.
// This is useful for tracking download progress.
type Reader struct {
	R        io.Reader
	Total    int64
	OnUpdate Callback
	read     int64
}

// NewReader creates a progress reader wrapping the given reader.
// total is the expected total bytes (use -1 if unknown).
// onUpdate is called after each Read with current and total bytes.
func NewReader(r io.Reader, total int64, onUpdate Callback) *Reader {
	return &Reader{
		R:        r,
		Total:    total,
		OnUpdate: onUpdate,
	}
}

// Read implements io.Reader, tracking bytes read and calling the progress callback.
func (pr *Reader) Read(p []byte) (int, error) {
	n, err := pr.R.Read(p)
	if n > 0 {
		pr.read += int64(n)
		if pr.OnUpdate != nil {
			pr.OnUpdate(pr.read, pr.Total)
		}
	}
	return n, err
}

// BytesRead returns the total bytes read so far.
func (pr *Reader) BytesRead() int64 {
	return pr.read
}

// Writer wraps an io.Writer to report write progress.
// This is useful for tracking upload progress.
type Writer struct {
	W        io.Writer
	Total    int64
	OnUpdate Callback
	written  int64
}

// NewWriter creates a progress writer wrapping the given writer.
// total is the expected total bytes (use -1 if unknown).
// onUpdate is called after each Write with current and total bytes.
func NewWriter(w io.Writer, total int64, onUpdate Callback) *Writer {
	return &Writer{
		W:        w,
		Total:    total,
		OnUpdate: onUpdate,
	}
}

// Write implements io.Writer, tracking bytes written and calling the progress callback.
func (pw *Writer) Write(p []byte) (int, error) {
	n, err := pw.W.Write(p)
	if n > 0 {
		pw.written += int64(n)
		if pw.OnUpdate != nil {
			pw.OnUpdate(pw.written, pw.Total)
		}
	}
	return n, err
}

// BytesWritten returns the total bytes written so far.
func (pw *Writer) BytesWritten() int64 {
	return pw.written
}
