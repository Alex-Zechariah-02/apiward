// Fuzzing of the Security Log cursor a client sends back, and of a search
// over an arbitrary audit file from an arbitrary cursor.

package monitor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzCursor checks that an accepted cursor names a plain file and survives
// a round trip, and that nothing a client sends makes decoding panic.
func FuzzCursor(f *testing.F) {
	for _, seed := range []string{
		EncodeCursor(Cursor{File: "audit.log", First: "e-1", Offset: 10}),
		EncodeCursor(Cursor{File: "../audit.log", First: "e-1", Offset: 0}),
		EncodeCursor(Cursor{File: "audit.log", Offset: -2}),
		"", "e30", "!!", "eyJmIjoiYSIsImYiOiJiIn0",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		c := DecodeCursor(text)
		if c == nil {
			return
		}
		if c.File == "" || strings.ContainsAny(c.File, `/\`) || filepath.Base(c.File) != c.File || c.Offset < -1 {
			t.Fatalf("accepted cursor %+v", *c)
		}
		again := DecodeCursor(EncodeCursor(*c))
		if again == nil || *again != *c {
			t.Fatalf("cursor %+v reads back as %+v", *c, again)
		}
	})
}

// FuzzSearch searches an arbitrary file from an arbitrary position: no
// content or cursor may panic, return more than the limit, or hand back a
// cursor the decoder refuses.
func FuzzSearch(f *testing.F) {
	record := `{"event_id":"e-1","time":"2026-11-02T09:00:01Z","kind":"request.forwarded","request_id":"01","decision":"forwarded","status":200,"method":"GET","path":"/a"}` + "\n"
	f.Add([]byte(record+record), "e-1", int64(0), "")
	f.Add([]byte(record+`{"event_id":"e-2","kind":"request.rejected"`), "e-1", int64(-1), "01")
	f.Add([]byte("\n\n{}\n"), "", int64(1<<40), "")
	f.Add([]byte(record), "x", int64(-1), "")
	f.Fuzz(func(t *testing.T, content []byte, first string, offset int64, ref string) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "audit.log"), content, 0o600); err != nil {
			t.Fatal(err)
		}
		query, bad := ParseQuery(map[string][]string{"ref": {ref}})
		if bad != "" {
			return
		}
		var start *Cursor
		if offset >= -1 {
			start = &Cursor{File: "audit.log", First: first, Offset: offset}
		}
		result, err := Search(dir, []string{"audit.log"}, start, query, 3, 1<<20)
		if err != nil {
			return
		}
		if len(result.Items) > 3 {
			t.Fatalf("returned %d items for a limit of 3", len(result.Items))
		}
		if result.Next != nil && DecodeCursor(EncodeCursor(*result.Next)) == nil {
			t.Fatalf("returned cursor %+v that the decoder refuses", *result.Next)
		}
	})
}
