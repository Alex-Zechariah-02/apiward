// Security log export and endpoint tests.

package integration

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

// The endpoint needs the history permission, reads the real audit files and
// says what it searched.
func TestAdminSecurityLog(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	admin := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
	resp, _ := e.Exchange("GET", "/a/x", "", "", "Authorization", "Bearer "+gatewaytest.Issuer.TokenFor(t, "bob"))
	ref := resp.Header.Get("X-Request-Id")
	e.Get("/a/x")
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
		code, body, _ = e.As(admin, "GET", "/admin/security-log?ref="+ref, "")
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
		code, csvBody, header = e.As(admin, "GET", "/admin/security-log?decision=refused&format=csv", "")
		if code == 200 && strings.Contains(csvBody, ",refused,401,") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if code != 200 || !strings.HasPrefix(header.Get("Content-Type"), "text/csv") || !strings.HasPrefix(csvBody, "time,request_id,decision") || !strings.Contains(csvBody, ",refused,401,") {
		t.Errorf("csv export: %d %s", code, csvBody)
	}
	for _, query := range []string{"limit=0", "limit=101", "decision=maybe", "from=yesterday", "after=!!", "format=xml"} {
		if code, body, _ := e.As(admin, "GET", "/admin/security-log?"+query, ""); code != 400 {
			t.Errorf("%s: %d %s", query, code, body)
		}
	}
	reader, _ := addAdmin(e, gatewaytest.Binaries.Plain, "viewer", "read")
	if code, body, _ := e.As(reader, "GET", "/admin/security-log", ""); code != 403 {
		t.Errorf("without the history permission: %d %s", code, body)
	}
}
