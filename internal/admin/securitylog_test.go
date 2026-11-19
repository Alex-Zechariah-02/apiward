// Security log export.

package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
)

// Client-chosen values cannot run as spreadsheet formulas in an export, and
// the last column says the path was cut.
func TestSecurityLogCSV(t *testing.T) {
	subject := "=HYPERLINK(1)"
	w := httptest.NewRecorder()
	writeSecurityLogCSV(w, monitor.Result{Items: []monitor.RequestView{{RequestID: "r", Method: "-2+3", Path: "+1", Subject: &subject, Roles: []string{"-A"}, Truncated: true}}, Searched: []string{"audit.log"}}, nil, []string{})
	body := w.Body.String()
	if !strings.Contains(body, "'-2+3") || !strings.Contains(body, "'+1") || !strings.Contains(body, "'=HYPERLINK(1)") || !strings.Contains(body, "'-A") || w.Header().Get("X-Security-Log-Complete") != "true" {
		t.Errorf("csv: %s %v", body, w.Header())
	}
	if lines := strings.Split(strings.TrimSpace(body), "\n"); !strings.HasSuffix(lines[0], ",path_truncated") || !strings.HasSuffix(lines[1], ",true") {
		t.Errorf("csv path_truncated column: %s", body)
	}
}

// A query that does not parse is refused, not answered with unfiltered rows.
func TestSecurityLogMalformedQuery(t *testing.T) {
	s := testServer(openController(t))
	w := httptest.NewRecorder()
	s.handleSecurityLog(w, httptest.NewRequest(http.MethodGet, "/admin/security-log?ref=%zz&decision=refused", nil), caller{})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"field":"query"`) {
		t.Fatalf("malformed query: %d %s", w.Code, w.Body)
	}
}

// Security log scans run one at a time; a second is refused at once with
// 503 busy and Retry-After instead of waiting.
func TestLogScansQueue(t *testing.T) {
	s := &Server{scans: make(chan struct{}, maxLogScans)}
	if !s.scanLog(httptest.NewRecorder()) {
		t.Fatal("the first scan did not start")
	}
	second := httptest.NewRecorder()
	if s.scanLog(second) {
		t.Fatal("a second scan ran beside the first")
	}
	if second.Code != http.StatusServiceUnavailable || second.Header().Get("Retry-After") != "1" || !strings.Contains(second.Body.String(), "busy") {
		t.Fatalf("second scan answered %d %v %s", second.Code, second.Header(), second.Body)
	}
	s.scanDone()
	if !s.scanLog(httptest.NewRecorder()) {
		t.Fatal("no scan started after the first ended")
	}
}
