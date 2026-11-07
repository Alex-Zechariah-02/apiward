// Security log export and endpoint tests.

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

// The endpoint needs the history permission, reads the real audit files and
// says what it searched.
func TestAdminSecurityLog(t *testing.T) {
	e := newEnv(t)
	seed(t, e.database, e.protectedPolicy(), seedOptions{})
	e.start(binaries.plain)
	admin := e.mustLogin(harnessAdmin, harnessPassword)
	resp, _ := e.exchange("GET", "/a/x", "", "", "Authorization", "Bearer "+issuer.TokenFor(t, "bob"))
	ref := resp.Header.Get("X-Request-Id")
	e.get("/a/x")
	var page struct {
		Items         []map[string]any `json:"items"`
		Complete      bool             `json:"complete"`
		FilesSearched []string         `json:"files_searched"`
		FilesMissing  []string         `json:"files_missing"`
	}
	var code int
	var body string
	// The audit writer is asynchronous: wait for the record.
	for range 50 {
		code, body, _ = e.as(admin, "GET", "/admin/security-log?ref="+ref, "")
		if code == 200 && json.Unmarshal([]byte(body), &page) == nil && len(page.Items) == 1 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(page.Items) != 1 || page.Items[0]["subject"] != "bob" || page.Items[0]["decision"] != "allowed" || !page.Complete || len(page.FilesSearched) == 0 || page.FilesMissing == nil {
		t.Fatalf("search by ref: %d %s", code, body)
	}
	if strings.Contains(body, "Bearer") {
		t.Fatalf("credential in the results: %s", body)
	}
	// The refused request's record is written asynchronously too.
	var csvBody string
	var header http.Header
	for range 50 {
		code, csvBody, header = e.as(admin, "GET", "/admin/security-log?decision=refused&format=csv", "")
		if code == 200 && strings.Contains(csvBody, ",refused,401,") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if code != 200 || !strings.HasPrefix(header.Get("Content-Type"), "text/csv") || !strings.HasPrefix(csvBody, "time,request_id,decision") || !strings.Contains(csvBody, ",refused,401,") {
		t.Errorf("csv export: %d %s", code, csvBody)
	}
	for _, query := range []string{"limit=0", "limit=101", "decision=maybe", "from=yesterday", "after=!!", "format=xml"} {
		if code, body, _ := e.as(admin, "GET", "/admin/security-log?"+query, ""); code != 400 {
			t.Errorf("%s: %d %s", query, code, body)
		}
	}
	reader, _ := e.addAdmin(binaries.plain, "viewer", "read")
	if code, body, _ := e.as(reader, "GET", "/admin/security-log", ""); code != 403 {
		t.Errorf("without the history permission: %d %s", code, body)
	}
}
