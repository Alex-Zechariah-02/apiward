// Dashboard files on the admin listener: where they come from (the admin_ui
// directory, the build embedded in a release binary, or none), and the page
// and flat assets served with a strict content policy, and nothing else.

package gateway

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

// writeDashboard creates a directory of built dashboard files, plus files the
// admin listener must never serve.
func writeDashboard(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"index.html":           "<!doctype html><title>dashboard</title>",
		"assets/app.js":        "console.log('app')",
		"assets/app.css":       "body{}",
		"assets/logo.svg":      "<svg xmlns=\"http://www.w3.org/2000/svg\"/>",
		"assets/app.js.map":    "{}",
		"assets/nested/x.js":   "nested",
		"secret.txt":           "not for the browser",
		"assets/.hidden.js":    "hidden",
		"assets/readme.txt":    "text",
		"assets/index.html":    "<!doctype html><title>other</title>",
		"assets/upper.JS.html": "<p>",
	}
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// The admin listener serves the dashboard's page and flat assets with a strict
// content policy, and nothing else: no listing, no fallback page, no other
// file, and the Admin API keeps its own answers.
func TestDashboardFiles(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
	e.WriteConfig(gatewaytest.ConfigOptions{Admin: map[string]any{"admin_ui": writeDashboard(t)}})
	e.Start(gatewaytest.Binaries.Plain)

	served := []struct{ path, contentType, body string }{
		{"/", "text/html; charset=utf-8", "<!doctype html><title>dashboard</title>"},
		{"/assets/app.js", "text/javascript; charset=utf-8", "console.log('app')"},
		{"/assets/app.css", "text/css; charset=utf-8", "body{}"},
		{"/assets/logo.svg", "image/svg+xml", "<svg xmlns=\"http://www.w3.org/2000/svg\"/>"},
	}
	for _, f := range served {
		code, body, header := e.AdminSend(http.MethodGet, f.path, "")
		if code != http.StatusOK || body != f.body || header.Get("Content-Type") != f.contentType {
			t.Errorf("GET %s: %d %q %q", f.path, code, header.Get("Content-Type"), body)
			continue
		}
		for name, want := range map[string]string{
			"Content-Security-Policy": uiPolicy,
			"X-Frame-Options":         "DENY",
			"Referrer-Policy":         "no-referrer",
			"Cache-Control":           "no-store",
			"X-Content-Type-Options":  "nosniff",
		} {
			if got := header.Get(name); got != want {
				t.Errorf("GET %s: %s = %q, want %q", f.path, name, got, want)
			}
		}
		if header.Get("Access-Control-Allow-Origin") != "" || header.Get("Set-Cookie") != "" {
			t.Errorf("GET %s: unexpected CORS or cookie header %v", f.path, header)
		}
	}
	if code, body, _ := e.AdminSend(http.MethodHead, "/", ""); code != http.StatusOK || body != "" {
		t.Errorf("HEAD /: %d %q", code, body)
	}

	notServed := []string{
		"/index.html", "/secret.txt", "/assets/", "/assets", "/assets/app.js.map",
		"/assets/nested/x.js", "/assets/nested", "/assets/readme.txt", "/assets/upper.JS.html", "/assets/index.html",
		"/assets/..%2fsecret.txt", "/assets/%2e%2e%2fsecret.txt", "/assets/missing.js",
		"/admin", "/admin/", "/admin/unknown", "/admin/status/extra", "/demo/", "/orders",
	}
	for _, p := range notServed {
		code, body, header := e.AdminSend(http.MethodGet, p, "")
		if code == http.StatusOK || strings.Contains(body, "<") || strings.Contains(header.Get("Content-Type"), "html") {
			t.Errorf("GET %s: %d %q %q", p, code, header.Get("Content-Type"), body)
		}
	}

	// The page is not a way around the API's own checks.
	if code, body, _ := e.AdminSend(http.MethodGet, "/admin/status", ""); code != http.StatusUnauthorized || !strings.Contains(body, `"unauthenticated"`) {
		t.Errorf("unauthenticated status: %d %s", code, body)
	}
	if code, _, _ := e.AdminSend(http.MethodGet, "/", "", "Host", "localhost:"+gatewaytest.Port(e.Admin)); code != http.StatusBadRequest {
		t.Errorf("page with another Host: %d", code)
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions} {
		if code, _, header := e.AdminSend(method, "/", "", "Origin", e.AdminOrigin()); code != http.StatusMethodNotAllowed || header.Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("%s /: %d %v", method, code, header)
		}
	}
	if code, _ := e.Get("/"); code == http.StatusOK {
		t.Errorf("data plane serves the dashboard: %d", code)
	}
}

// TestEmbeddedUI: the operator's admin_ui directory wins over an embedded
// build, an embedded build is served when no directory is set, a binary with
// neither serves no dashboard, and an embedded build without its page is
// refused at start.
func TestEmbeddedUI(t *testing.T) {
	dir := writeDashboard(t)
	embedded := fstest.MapFS{"index.html": {Data: []byte("embedded page")}}
	files, source, err := dashboardFiles(dir, embedded)
	if err != nil || source != uiDirectory {
		t.Fatalf("directory and embedded: %q %v", source, err)
	}
	if page, _ := fs.ReadFile(files, "index.html"); string(page) == "embedded page" {
		t.Error("the embedded build overrode the operator's directory")
	}
	files, source, err = dashboardFiles("", embedded)
	if err != nil || source != uiEmbedded {
		t.Fatalf("embedded only: %q %v", source, err)
	}
	w := httptest.NewRecorder()
	dashboard(files).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusOK || w.Body.String() != "embedded page" || w.Header().Get("Content-Security-Policy") != uiPolicy {
		t.Errorf("embedded page: %d %q %v", w.Code, w.Body, w.Header())
	}
	if files, source, err = dashboardFiles("", nil); files != nil || source != uiNone || err != nil {
		t.Errorf("neither: %v %q %v", files, source, err)
	}
	if _, _, err = dashboardFiles("", fstest.MapFS{"assets/app.js": {}}); err == nil {
		t.Error("an embedded build without index.html was accepted")
	}
}
