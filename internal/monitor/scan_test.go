// Backward log scanning rejects short reads instead of scanning stale buffer bytes.

package monitor

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func writeMultiWindowLines(t *testing.T, path string) (prefixBytes int64, firstLine, lastLine string) {
	t.Helper()
	var buf bytes.Buffer
	firstLine = "line-first-00000000"
	buf.WriteString(firstLine + "\n")
	buf.WriteString("line-second-0000000\n")
	// Fill past one securityLogWindow so backward scanning reads two windows
	// and reuses its buffer for the earlier prefix.
	target := securityLogWindow + 256
	for i := 0; buf.Len() < target; i++ {
		fmt.Fprintf(&buf, "filler-%08d-%048d\n", i, i)
	}
	lastLine = "line-last-99999999"
	buf.WriteString(lastLine + "\n")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	prefixBytes = int64(buf.Len()) - securityLogWindow
	return prefixBytes, firstLine, lastLine
}

func TestScanLinesBackwardRejectsShortRead(t *testing.T) {
	t.Parallel()
	t.Run("complete multi-window file", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "audit.log")
		_, firstLine, lastLine := writeMultiWindowLines(t, path)
		budget := int64(securityLogWindow * 4)
		var firstSeen, lastSeen string
		var count int
		_, stopped, err := scanLinesBackward(t.Context(), path, -1, 0, &budget, func(line []byte, _ int64) bool {
			if count == 0 {
				firstSeen = string(line)
			}
			lastSeen = string(line)
			count++
			return false
		})
		if err != nil || stopped {
			t.Fatalf("complete scan: stopped=%v err=%v", stopped, err)
		}
		if firstSeen != lastLine || lastSeen != firstLine {
			t.Fatalf("visited endpoints %q .. %q, want %q .. %q", firstSeen, lastSeen, lastLine, firstLine)
		}
	})

	for _, tc := range []struct {
		name  string
		ratio int64
	}{
		{name: "truncated to empty", ratio: 0},
		{name: "truncated mid-prefix", ratio: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "audit.log")
			prefixBytes, _, lastLine := writeMultiWindowLines(t, path)
			budget := int64(securityLogWindow * 4)
			truncated := false
			var extraLines []string
			_, _, err := scanLinesBackward(t.Context(), path, -1, 0, &budget, func(line []byte, lineStart int64) bool {
				if !truncated {
					if string(line) != lastLine {
						t.Errorf("first visited line %q, want %q", string(line), lastLine)
					}
					var target int64
					if tc.ratio > 0 {
						target = prefixBytes / tc.ratio
					}
					if err := os.Truncate(path, target); err != nil {
						t.Fatalf("truncate: %v", err)
					}
					truncated = true
					return false
				}
				if lineStart < prefixBytes {
					extraLines = append(extraLines, string(line))
				}
				return false
			})
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("short read error = %v, want %v (extra prefix lines visited: %d)", err, io.ErrUnexpectedEOF, len(extraLines))
			}
			if len(extraLines) != 0 {
				t.Fatalf("visited %d lines from short-read prefix: %v", len(extraLines), extraLines)
			}
		})
	}
}
