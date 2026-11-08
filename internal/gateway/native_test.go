// The website the native gateway serves, matched on the exact target.

package gateway

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

// The native data plane serves the Client website itself: the page
// at the approved Fetch routes and flat assets directory, with its security headers,
// matched on the exact target. Every other request, including every other
// spelling of a website path, goes to enforcement, and no request reaches a
// file outside the website or the admin dashboard. Without the setting there
// is no website.
func TestNativeWebsite(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
	site := writeDashboard(t)
	settings := e.NativeSettings()
	gatewaytest.Section(settings, "data")["website"] = site
	e.WriteNative(settings)
	e.Start(gatewaytest.Binaries.Plain)

	headers := map[string]string{
		"Content-Security-Policy": uiPolicy,
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
		"Cache-Control":           "no-store",
		"X-Content-Type-Options":  "nosniff",
	}
	for _, f := range []struct{ path, contentType, body string }{
		{"/", "text/html; charset=utf-8", "<!doctype html><title>dashboard</title>"},
		{"/my-orders/ORD-1001?from=link", "text/html; charset=utf-8", "<!doctype html><title>dashboard</title>"},
		{"/assets/app.js", "text/javascript", "console.log('app')"},
		{"/assets/app.css", "text/css", "body{}"},
		{"/assets/logo.svg", "image/svg+xml", "<svg xmlns=\"http://www.w3.org/2000/svg\"/>"},
	} {
		resp, body := e.Exchange(http.MethodGet, f.path, "", "")
		if resp.StatusCode != http.StatusOK || body != f.body || resp.Header.Get("Content-Type") != f.contentType {
			t.Errorf("GET %s: %d %q %q", f.path, resp.StatusCode, resp.Header.Get("Content-Type"), body)
			continue
		}
		for name, want := range headers {
			if got := resp.Header.Get(name); got != want {
				t.Errorf("GET %s: %s = %q, want %q", f.path, name, got, want)
			}
		}
	}
	if resp, body := e.Exchange(http.MethodHead, "/", "", ""); resp.StatusCode != http.StatusOK || body != "" {
		t.Errorf("HEAD /: %d %q", resp.StatusCode, body)
	}
	if code, body := e.Get("/assets/missing.js"); code != http.StatusNotFound || strings.Contains(body, "request_id") {
		t.Errorf("missing asset: %d %q", code, body)
	}
	// A Windows device name is no file of the website: os.DirFS refuses it,
	// so the request is answered 404 at once instead of opening the device.
	if code, body := e.Get("/assets/CON.js"); code != http.StatusNotFound || strings.Contains(body, "request_id") {
		t.Errorf("device name as an asset: %d %q", code, body)
	}

	// Everything else is the policy's: refused here by enforcement, with an
	// event, and never answered with a file.
	files := []string{"dashboard", "console.log", "body{}", "<svg", "not for the browser", "nested", "hidden", "other", "SQLite"}
	for _, probe := range []struct{ method, target string }{
		{http.MethodGet, "/demo"}, {http.MethodGet, "/demo/"}, {http.MethodGet, "/index.html"}, {http.MethodGet, "/assets/"},
		{http.MethodGet, "/assets/app.js.map"}, {http.MethodGet, "/assets/nested/x.js"}, {http.MethodGet, "/assets/readme.txt"},
		{http.MethodGet, "/assets/upper.JS.html"}, {http.MethodGet, "/secret.txt"}, {http.MethodGet, "/%61ssets/app.js"},
		{http.MethodGet, "/assets/..%2fsecret.txt"}, {http.MethodGet, "/assets/%2e%2e%2fsecret.txt"},
		{http.MethodGet, "/assets/../../secret.txt"}, {http.MethodGet, "/assets/..\\secret.txt"},
		{http.MethodGet, "/food//"}, {http.MethodGet, "//food"}, {http.MethodGet, "/FOOD"}, {http.MethodGet, "/food/%2e"},
		{http.MethodGet, "/assets/" + filepath.Base(e.Database)}, {http.MethodGet, "/demo/assets/app.js"},
		{http.MethodGet, "/orders"}, {http.MethodGet, "/orders/ORD-1001"}, {http.MethodGet, "/support/tickets"},
		{http.MethodPost, "/"}, {http.MethodPut, "/assets/app.js"}, {http.MethodOptions, "/"},
	} {
		resp, body := e.RawResponse(probe.method + " " + probe.target + " HTTP/1.1\r\nHost: gw\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		_, id := gatewaytest.RequestID(resp, body)
		events := e.RequestEvents(id, 1)
		if resp.StatusCode == http.StatusOK || id == "" || len(events) != 1 || resp.Header.Get("Content-Security-Policy") != "" {
			t.Errorf("%s %s: %d %q, events %v", probe.method, probe.target, resp.StatusCode, body, events)
		}
		for _, content := range files {
			if strings.Contains(body, content) {
				t.Errorf("%s %s answered with file content %q", probe.method, probe.target, body)
			}
		}
	}
	if code, body, _ := e.AdminSend(http.MethodGet, "/demo/", ""); code != http.StatusNotFound || strings.Contains(body, "dashboard") {
		t.Errorf("the admin listener serves the website: %d %q", code, body)
	}
	e.AssertReceipts(0, 0, 0)

	e.Stop()
	e.WriteNative(e.NativeSettings())
	e.Start(gatewaytest.Binaries.Plain)
	resp, body := e.Exchange(http.MethodGet, "/", "", "")
	if _, id := gatewaytest.RequestID(resp, body); resp.StatusCode != http.StatusNotFound || id == "" {
		t.Errorf("/ without a website: %d %q", resp.StatusCode, body)
	}
}
