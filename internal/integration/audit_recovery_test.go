// Audit records recovered after a crash or a torn write.

package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

// An interrupted append leaves an incomplete last record. The writer
// replaces the file at once: the suspect file keeps its
// complete records and the incomplete one after them, and the new file's
// audit.recovered names the suspect file and where its synced records end.
// After a restart without the fault, admission works again.
func TestIncompleteRecordIsRecovered(t *testing.T) {
	t.Parallel()
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	if code, _ := e.Get("/a/x"); code != http.StatusOK {
		t.Fatal(code)
	}
	e.EventsWhen(func(events []map[string]any) bool { return gatewaytest.CountKind(events, "request.forwarded") == 1 })
	e.Stop()
	complete := readAudit(t, e.AuditLog)

	e.Start(gatewaytest.Binaries.Fault, "GATEWAY_FAULT=audit-partial")
	e.Status() // signs the harness in while the log still works
	if code, _ := e.Get("/a/x"); code != http.StatusServiceUnavailable {
		t.Fatalf("admission with a partial write: %d", code)
	}
	var marker map[string]any
	gatewaytest.WaitFor(t, time.Now().Add(5*time.Second), "the replacement record", func() bool {
		for _, ev := range e.AuditEvents() {
			if ev["kind"] == "audit.recovered" && ev["reason"] == "sync_failed" {
				marker = ev
			}
		}
		return marker != nil
	})
	e.Stop()
	var suspect []byte
	for _, file := range gatewaytest.RotatedAudit(t, e.AuditLog) {
		if strings.TrimSuffix(filepath.Base(file), ".gz") == marker["file"] {
			// Read raw: the incomplete record follows the last newline.
			raw, err := audit.OpenRecords(file)
			if err != nil {
				t.Fatal(err)
			}
			suspect, _ = io.ReadAll(raw)
			raw.Close()
		}
	}
	offset, _ := marker["offset"].(float64)
	if !bytes.HasPrefix(suspect, complete) || int(offset) >= len(suspect) || suspect[int(offset)-1] != '\n' || suspect[len(suspect)-1] == '\n' || json.Valid(suspect[int(offset):]) {
		t.Fatalf("suspect file %v: %d bytes, synced end %v, after %d complete bytes", marker["file"], len(suspect), offset, len(complete))
	}

	e.Start(gatewaytest.Binaries.Plain)
	if code, _ := e.Get("/a/x"); code != http.StatusOK {
		t.Fatalf("after recovery: %d", code)
	}
	e.AssertReceipts(2, 0, 0)
}

// A crash in the middle of a write leaves part of a record and, on a
// zero-filled file, the zero tail. The next start removes the tail and keeps
// the part as the one incomplete record, named by audit.recovered; every
// complete record before it is unchanged.
func TestTornWriteRecovered(t *testing.T) {
	t.Parallel()
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Fault, "GATEWAY_FAULT=audit-torn-crash")
	req, _ := http.NewRequest(http.MethodGet, "http://"+e.DataAddr+"/a/x", http.NoBody)
	if resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req); err == nil {
		resp.Body.Close()
		t.Fatalf("request answered %d by a process that should have stopped", resp.StatusCode)
	}
	if code := e.WaitExit(); code != crashExit {
		t.Fatalf("exit code %d", code)
	}
	raw, err := os.ReadFile(e.AuditLog)
	if err != nil {
		t.Fatal(err)
	}
	torn := audit.Content(raw)
	if runtime.GOOS == "linux" && len(raw) == len(torn) {
		t.Fatal("the crashed zero-filled file has no zero tail")
	}
	offset := bytes.LastIndexByte(torn, '\n') + 1
	if offset == len(torn) {
		t.Fatal("the crash left no incomplete record")
	}

	e.Start(gatewaytest.Binaries.Plain)
	if code, _ := e.Get("/a/x"); code != http.StatusOK {
		t.Fatalf("after recovery: %d", code)
	}
	events := e.EventsWhen(func(events []map[string]any) bool { return gatewaytest.CountKind(events, "audit.recovered") == 1 })
	marker := events[slices.IndexFunc(events, func(ev map[string]any) bool { return ev["kind"] == "audit.recovered" })]
	if marker["offset"] != float64(offset) {
		t.Fatalf("recovery event %v, want offset %d", marker, offset)
	}
	data, _ := os.ReadFile(e.AuditLog)
	data = audit.Content(data)
	if !bytes.HasPrefix(data, torn) || data[len(torn)] != '\n' || bytes.IndexByte(data, 0) >= 0 {
		t.Fatal("recovery changed the complete records, left the record unterminated or kept zeros inside the content")
	}
	e.AssertReceipts(1, 0, 0)
}

// readAudit reads an audit file up to its logical end.
func readAudit(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return audit.Content(data)
}
