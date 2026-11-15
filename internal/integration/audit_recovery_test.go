// Audit records recovered after a crash or a torn write.

package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

// An interrupted append leaves an incomplete last record. After a restart it
// is kept, terminated, and named by an audit.recovered event; complete
// records are unchanged and admission works again.
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
	if !e.Status().AuditFailed {
		t.Fatal("partial write not reported")
	}
	e.Stop()
	partial := readAudit(t, e.AuditLog)
	if !bytes.HasPrefix(partial, complete) || len(partial) == len(complete) || partial[len(partial)-1] == '\n' {
		t.Fatalf("expected an incomplete record after %d complete bytes; file has %d bytes", len(complete), len(partial))
	}
	offset := bytes.LastIndexByte(partial, '\n') + 1

	e.Start(gatewaytest.Binaries.Plain)
	if code, _ := e.Get("/a/x"); code != http.StatusOK {
		t.Fatalf("after recovery: %d", code)
	}
	// The shared readers refuse any invalid line, so this one parses the file
	// itself and checks below that the interrupted record is the only one.
	var data []byte
	var marker map[string]any
	for deadline := time.Now().Add(5 * time.Second); marker == nil && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		data = readAudit(t, e.AuditLog)
		for line := range bytes.SplitSeq(data, []byte("\n")) {
			var ev map[string]any
			if json.Unmarshal(line, &ev) == nil && ev["kind"] == "audit.recovered" {
				marker = ev
			}
		}
	}
	if !bytes.HasPrefix(data, partial) {
		t.Fatal("recovery rewrote existing records")
	}
	if marker == nil || marker["offset"] != float64(offset) || marker["file"] != filepath.Base(e.AuditLog) {
		t.Fatalf("recovery event %v, want offset %d", marker, offset)
	}
	// The incomplete record is on its own line and is the only invalid one.
	invalid := 0
	for line := range bytes.SplitSeq(bytes.TrimSuffix(data, []byte("\n")), []byte("\n")) {
		if !json.Valid(line) {
			invalid++
			if !bytes.Equal(line, partial[offset:]) {
				t.Fatalf("invalid line %q is not the interrupted record", line)
			}
		}
	}
	if invalid != 1 {
		t.Fatalf("%d invalid lines, want 1", invalid)
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
