// Security log export.

package admin

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
)

// Client-chosen values cannot run as spreadsheet formulas in an export.
func TestSecurityLogCSV(t *testing.T) {
	subject := "=HYPERLINK(1)"
	w := httptest.NewRecorder()
	writeSecurityLogCSV(w, monitor.Result{Items: []monitor.RequestView{{RequestID: "r", Path: "+1", Subject: &subject, Roles: []string{"-A"}}}, Searched: []string{"audit.log"}}, nil, []string{})
	body := w.Body.String()
	if !strings.Contains(body, "'+1") || !strings.Contains(body, "'=HYPERLINK(1)") || !strings.Contains(body, "'-A") || w.Header().Get("X-Security-Log-Complete") != "true" {
		t.Errorf("csv: %s %v", body, w.Header())
	}
}
