// The logical end of an audit file, and the zero-filled active file: zeros
// ahead of the writer while it runs, none in a rotated or closed file.

package audit

import (
	"bytes"
	"context"
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
		commitN(a, 3)
		info, err := os.Stat(path)
		active, _, _, _ := a.Usage()
		filled := runtime.GOOS == "linux" && !appends
		if err != nil || (info.Size() > active) != filled {
			t.Fatalf("append %v: file %d bytes, content %d (%v)", appends, info.Size(), active, err)
		}
		for !fileExists(path + ".1") {
			commitN(a, 1)
		}
		if err := a.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{path + ".1", path} {
			data, err := os.ReadFile(name)
			if err != nil || len(data) == 0 || data[len(data)-1] != '\n' || bytes.IndexByte(data, 0) >= 0 {
				t.Fatalf("append %v: %s is not newline-terminated records without zeros (%v)", appends, name, err)
			}
		}
	}
}
