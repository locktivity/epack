package boundedio

import (
	"fmt"
	"io"
	"os"

	"github.com/locktivity/epack/internal/limits"
)

// BoundedReadError is returned when size limits are exceeded.
type BoundedReadError struct {
	Path   string // File path or identifier
	Limit  int64  // Maximum allowed size
	Actual int64  // Actual size encountered
	Phase  string // "stat" or "read" - when the limit was hit
}

func (e *BoundedReadError) Error() string {
	return fmt.Sprintf("%s exceeds size limit (%d > %d bytes) at %s phase",
		e.Path, e.Actual, e.Limit, e.Phase)
}

// IsBoundedReadError returns true if err is a BoundedReadError.
func IsBoundedReadError(err error) bool {
	_, ok := err.(*BoundedReadError)
	return ok
}

// ReadFileWithLimit reads a file with TOCTOU-safe size checking.
//
// Security properties:
//  1. Size checked via Fstat on open fd (not separate Stat call)
//  2. LimitReader(+1) as defense-in-depth against file growth
//  3. Final length check catches growth during read
//
// This does NOT check for symlinks - use safefile.ReadFile for that.
func ReadFileWithLimit(path string, limit limits.SizeLimit) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	return ReadWithLimit(f, path, limit)
}

// ReadWithLimit reads from an open file with size limits.
// Uses Fstat on the fd to prevent TOCTOU races.
//
// The name parameter is used for error messages only.
func ReadWithLimit(f *os.File, name string, limit limits.SizeLimit) ([]byte, error) {
	maxBytes := limit.Bytes()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > maxBytes {
		return nil, &BoundedReadError{
			Path:   name,
			Limit:  maxBytes,
			Actual: info.Size(),
			Phase:  "stat",
		}
	}

	// +1 to detect growth during read
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, &BoundedReadError{
			Path:   name,
			Limit:  maxBytes,
			Actual: int64(len(data)),
			Phase:  "read",
		}
	}
	return data, nil
}

// ReadReaderWithLimit reads from any io.Reader with a size limit.
// No Stat phase (reader may not be a file).
//
// The name parameter is used for error messages only.
func ReadReaderWithLimit(r io.Reader, name string, limit limits.SizeLimit) ([]byte, error) {
	maxBytes := limit.Bytes()
	data, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, &BoundedReadError{
			Path:   name,
			Limit:  maxBytes,
			Actual: int64(len(data)),
			Phase:  "read",
		}
	}
	return data, nil
}

// MustReadWithLimit is like ReadWithLimit but panics on error.
// Only use this in tests or initialization code where errors are fatal.
func MustReadWithLimit(f *os.File, name string, limit limits.SizeLimit) []byte {
	data, err := ReadWithLimit(f, name, limit)
	if err != nil {
		panic(fmt.Sprintf("MustReadWithLimit(%s): %v", name, err))
	}
	return data
}
