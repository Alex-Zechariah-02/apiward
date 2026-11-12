// The logical end of an audit file. A zero-filled active file (fill.go)
// carries zero bytes after its records; its content ends at the first zero
// byte after its last newline. JSON text never holds a zero byte (RFC 8259
// §7 requires control characters in strings to be escaped), so a file
// written by appending ends where it always did.

package audit

import (
	"bytes"
	"errors"
	"io"
	"os"
)

// Content returns the content of data, the bytes of an audit file: up to the
// first zero byte after its last newline, or all of data.
func Content(data []byte) []byte {
	line := bytes.LastIndexByte(data, '\n') + 1
	if i := bytes.IndexByte(data[line:], 0); i >= 0 {
		return data[:line+i]
	}
	return data
}

// End returns the logical end of file, the length of its Content. It reads
// backwards past the zero tail, then the last record's bytes before it.
func End(file *os.File) (int64, error) {
	info, err := file.Stat()
	if err != nil {
		return 0, err
	}
	end := info.Size()
	window := make([]byte, min(end, MaxRecordBytes))
	for end > 0 {
		base := max(end-int64(len(window)), 0)
		chunk := window[:end-base]
		if _, err := file.ReadAt(chunk, base); err != nil && !errors.Is(err, io.EOF) {
			return 0, err
		}
		if kept := len(bytes.TrimRight(chunk, "\x00")); kept > 0 {
			end = base + int64(kept)
			break
		}
		end = base
	}
	// A record is at most MaxRecordBytes, so the last newline is in reach.
	base := max(end-int64(len(window)), 0)
	tail := window[:end-base]
	if _, err := file.ReadAt(tail, base); err != nil && !errors.Is(err, io.EOF) {
		return 0, err
	}
	return base + int64(len(Content(tail))), nil
}
