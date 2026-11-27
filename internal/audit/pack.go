// Compressing a rotated file: one pass describes it (size, SHA-256 and the
// times of its first and last records), a second writes it gzip-compressed
// in blocks (blocks.go; RFC 1952, Go's default level, as Caddy's rotated
// logs) to a temporary
// name, syncs it, renames it and syncs the folder, so a crash leaves either
// no compressed file or a complete one. The description goes in the gzip
// header's comment, so eviction and verification read it without
// decompressing the file.

package audit

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/fault"
	"github.com/Alex-Zechariah-02/apiward/internal/filecheck"
)

// describe reads a rotated file once: its size, SHA-256 and the times of its
// first and last records, as an event of kind.
func describe(name, kind string) (Event, error) {
	file, err := OpenShared(name)
	if err != nil {
		return Event{}, err
	}
	defer file.Close()
	sum := sha256.New()
	reader := bufio.NewReaderSize(io.TeeReader(file, sum), MaxRecordBytes)
	e := Event{Kind: kind, File: filepath.Base(name)}
	for {
		line, err := reader.ReadSlice('\n')
		e.Bytes += int64(len(line))
		if len(line) > 0 && err == nil {
			if at, ok := recordTime(line); ok {
				if e.First.IsZero() {
					e.First = at
				}
				e.Last = at
			}
		}
		if err == io.EOF {
			break
		}
		// A line longer than the buffer is no record; its bytes still count.
		if err != nil && !errors.Is(err, bufio.ErrBufferFull) {
			return Event{}, err
		}
	}
	e.Digest = hex.EncodeToString(sum.Sum(nil))
	return e, nil
}

// recordTime reads a record's time without decoding the rest of it.
func recordTime(line []byte) (time.Time, bool) {
	_, rest, found := bytes.Cut(line, []byte(`"time":"`))
	if !found {
		return time.Time{}, false
	}
	text, _, found := bytes.Cut(rest, []byte(`"`))
	if !found {
		return time.Time{}, false
	}
	at, err := time.Parse(time.RFC3339Nano, string(text))
	return at, err == nil
}

// pack compresses the plain rotated file src into dir as <name>.gz and
// returns its description with Bytes, the stored size, in Archived. An
// earlier attempt's temporary file is replaced.
func pack(src, dir string) (Event, error) {
	e, err := describe(src, "audit.archived")
	if err != nil {
		return Event{}, err
	}
	target := filepath.Join(dir, filepath.Base(src)+packedSuffix)
	temporary := target + ".tmp"
	if err := os.Remove(temporary); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Event{}, err
	}
	stored, err := writePacked(src, temporary, e)
	if err != nil {
		return Event{}, errors.Join(err, os.Remove(temporary))
	}
	fault.CrashPoint("audit-pack-before-rename")
	if err := os.Rename(temporary, target); err != nil {
		return Event{}, errors.Join(err, os.Remove(temporary))
	}
	if err := filecheck.SyncDir(dir); err != nil {
		return Event{}, err
	}
	e.Archived = stored
	return e, nil
}

// writePacked writes src compressed to temporary, with e's description in
// the header, syncs it and returns its size.
func writePacked(src, temporary string, e Event) (int64, error) {
	in, err := OpenShared(src)
	if err != nil {
		return 0, err
	}
	defer in.Close()
	// 0600 keeps an archived file readable only by the gateway's user.
	out, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	stored, err := writeBlocks(out, in, gzip.Header{Name: filepath.Base(src), Comment: headerComment(e), ModTime: e.Last})
	if err == nil {
		err = out.Sync()
	}
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return 0, err
	}
	return stored, nil
}

// headerComment is the description a compressed file carries.
func headerComment(e Event) string {
	return fmt.Sprintf("first=%s last=%s sha256=%s bytes=%d", e.First.Format(time.RFC3339Nano), e.Last.Format(time.RFC3339Nano), e.Digest, e.Bytes)
}

// Packed is the description in a compressed file's header.
type Packed struct {
	First, Last time.Time
	Digest      string // SHA-256 of the uncompressed content
	Bytes       int64  // uncompressed size
}

// ReadPacked reads the description in the header of the compressed file path.
func ReadPacked(path string) (Packed, error) {
	file, err := OpenShared(path)
	if err != nil {
		return Packed{}, err
	}
	defer file.Close()
	zr, err := gzip.NewReader(file)
	if err != nil {
		return Packed{}, err
	}
	defer zr.Close()
	return readPackedHeader(filepath.Base(path), zr)
}

func readPackedHeader(name string, zr *gzip.Reader) (Packed, error) {
	var p Packed
	for field := range strings.FieldsSeq(zr.Comment) {
		key, value, _ := strings.Cut(field, "=")
		switch key {
		case "first":
			at, err := time.Parse(time.RFC3339Nano, value)
			if err != nil {
				return Packed{}, fmt.Errorf("%s: invalid first time in its gzip header", name)
			}
			p.First = at
		case "last":
			at, err := time.Parse(time.RFC3339Nano, value)
			if err != nil {
				return Packed{}, fmt.Errorf("%s: invalid last time in its gzip header", name)
			}
			p.Last = at
		case "sha256":
			p.Digest = value
		case "bytes":
			size, err := strconv.ParseInt(value, 10, 64)
			if err != nil || size < 0 || size > MaxAuditBytes {
				return Packed{}, fmt.Errorf("%s: the size in its gzip header is not 0 to %d bytes", name, MaxAuditBytes)
			}
			p.Bytes = size
		}
	}
	if p.Digest == "" {
		return Packed{}, fmt.Errorf("%s: no description in its gzip header", name)
	}
	return p, nil
}

// OpenRecords opens a log file for reading its records: a compressed file
// through a gzip reader. Closing the result closes the file.
func OpenRecords(path string) (io.ReadCloser, error) {
	file, err := OpenShared(path)
	if err != nil || !strings.HasSuffix(path, packedSuffix) {
		return file, err
	}
	zr, err := gzip.NewReader(file)
	if err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return packedReader{Reader: zr, file: file}, nil
}

// packedReader closes the gzip reader and its file together.
type packedReader struct {
	*gzip.Reader
	file *os.File
}

func (r packedReader) Close() error { return errors.Join(r.Reader.Close(), r.file.Close()) }
