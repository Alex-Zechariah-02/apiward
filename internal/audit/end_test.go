// The logical end of an audit file, and the zero-filled active file: zeros
// ahead of the writer while it runs, none in a rotated or closed file.

package audit

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLogicalEnd(t *testing.T) {
	zeros := strings.Repeat("\x00", 3*MaxRecordBytes)
	for _, tc := range []struct {
		name, data string
		want       int64
	}{
		{"empty", "", 0},
		{"appended", "{}\n{}\n", 6},
		{"zero tail", "{}\n" + zeros, 3},
		{"incomplete record", "{}\n{\"a\":" + zeros, 8},
		{"only zeros", zeros, 0},
		{"zeros inside the last line", "{}\n{\x00\x00}\n" + zeros, 8},
		{"zeros after the last newline", "{}\n{\x00}" + zeros, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.log")
			if err := os.WriteFile(path, []byte(tc.data), 0o600); err != nil {
				t.Fatal(err)
			}
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			end, err := End(file)
			if err != nil || end != tc.want || len(Content([]byte(tc.data))) != int(tc.want) {
				t.Fatalf("End %d (%v), Content %d, want %d", end, err, len(Content([]byte(tc.data))), tc.want)
			}
		})
	}
}

func TestZeroFilledLog(t *testing.T) {
	for _, appends := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "audit.log")
		a := OpenAudit(path, Settings{MaxBytes: 4 << 10, MaxFiles: 4, Append: appends})
		if commitN(a, 3) != 3 {
			t.Fatal("a commit was refused")
		}
		info, err := os.Stat(path)
		active, _, _, _ := a.Usage()
		filled := runtime.GOOS == "linux" && !appends
		if err != nil || (info.Size() > active) != filled {
			t.Fatalf("append %v: file %d bytes, content %d (%v)", appends, info.Size(), active, err)
		}
		commitUntil(t, a, func() bool { return len(rotated(t, path)) > 0 })
		if err := a.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		for _, name := range append(rotated(t, path), path) {
			data, err := os.ReadFile(name)
			if err != nil || len(data) == 0 || data[len(data)-1] != '\n' || bytes.IndexByte(data, 0) >= 0 {
				t.Fatalf("append %v: %s is not newline-terminated records without zeros (%v)", appends, name, err)
			}
		}
	}
}

type readerFunc func([]byte, int64) (int, error)

func (fn readerFunc) ReadAt(p []byte, off int64) (int, error) {
	return fn(p, off)
}

func TestTailReadsRejectShortRead(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		actual   string
		staleEnd int64
	}{
		{name: "truncated to empty", actual: "", staleEnd: 64},
		{name: "truncated mid-file", actual: "{\"kind\":\"audit.closed\"}\n", staleEnd: 64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "audit.log")
			if err := os.WriteFile(path, []byte(tc.actual), 0o600); err != nil {
				t.Fatal(err)
			}
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			if end, err := endAt(file, tc.staleEnd); end != 0 || !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Errorf("endAt(stale=%d) = (%d, %v), want (0, %v)", tc.staleEnd, end, err, io.ErrUnexpectedEOF)
			}
			if off, err := incompleteRecord(file, tc.staleEnd); off != -1 || !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Errorf("incompleteRecord(stale=%d) = (%d, %v), want (-1, %v)", tc.staleEnd, off, err, io.ErrUnexpectedEOF)
			}
			if closed, err := closedTail(file, tc.staleEnd); closed || !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Errorf("closedTail(stale=%d) = (%v, %v), want (false, %v)", tc.staleEnd, closed, err, io.ErrUnexpectedEOF)
			}
		})
	}

	t.Run("endAt rejects short second tail read", func(t *testing.T) {
		t.Parallel()
		reads := 0
		r := readerFunc(func(p []byte, _ int64) (int, error) {
			reads++
			if reads == 1 {
				copy(p, []byte("{}\n"))
				return len(p), nil
			}
			return 0, io.EOF
		})
		if end, err := endAt(r, 16); end != 0 || !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("endAt(short tail) = (%d, %v), want (0, %v)", end, err, io.ErrUnexpectedEOF)
		}
	})

	t.Run("exact EOF reads succeed", func(t *testing.T) {
		t.Parallel()
		content := []byte("{\"kind\":\"audit.closed\"}\n")
		r := readerFunc(func(p []byte, off int64) (int, error) {
			return copy(p, content[off:]), io.EOF
		})
		if end, err := endAt(r, int64(len(content))); err != nil || end != int64(len(content)) {
			t.Fatalf("endAt(exact EOF) = (%d, %v), want (%d, nil)", end, err, len(content))
		}
		if off, err := incompleteRecord(r, int64(len(content))); err != nil || off != -1 {
			t.Fatalf("incompleteRecord(exact EOF) = (%d, %v), want (-1, nil)", off, err)
		}
		if closed, err := closedTail(r, int64(len(content))); err != nil || !closed {
			t.Fatalf("closedTail(exact EOF) = (%v, %v), want (true, nil)", closed, err)
		}
	})

	t.Run("non-EOF error propagates", func(t *testing.T) {
		t.Parallel()
		wantErr := errors.New("disk read failed")
		r := readerFunc(func(p []byte, _ int64) (int, error) {
			return len(p), wantErr
		})
		if end, err := endAt(r, 16); end != 0 || !errors.Is(err, wantErr) {
			t.Errorf("endAt(io err) = (%d, %v), want (0, %v)", end, err, wantErr)
		}
		if off, err := incompleteRecord(r, 16); off != -1 || !errors.Is(err, wantErr) {
			t.Errorf("incompleteRecord(io err) = (%d, %v), want (-1, %v)", off, err, wantErr)
		}
		if closed, err := closedTail(r, 16); closed || !errors.Is(err, wantErr) {
			t.Errorf("closedTail(io err) = (%v, %v), want (false, %v)", closed, err, wantErr)
		}
	})
}
