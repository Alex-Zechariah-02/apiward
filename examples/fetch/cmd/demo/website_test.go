// The Fetch website server: the targets it answers and the headers it sets.

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

// Catch accidental SPA fallback over an API or acceptance of a decoded target.
func TestFetchWebsiteTargets(t *testing.T) {
	pages := []string{
		"/", "/food", "/mart", "/store/MER-001", "/item/ITM-001", "/cart", "/checkout",
		"/my-orders", "/my-orders/ORD-1001", "/help", "/help/TKT-1001", "/signin",
		"/merchant", "/rider", "/support", "/ops", "/lab", "/account",
	}
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		for _, target := range pages {
			t.Run(method+target, func(t *testing.T) {
				r := httptest.NewRequest(method, target+"?from=link", nil)
				name, contentType, ok := websiteFile(r)
				if !ok || name != "index.html" || contentType != "text/html; charset=utf-8" {
					t.Fatalf("page target returned %q %q %t", name, contentType, ok)
				}
			})
		}
		for file, contentType := range map[string]string{
			"app-1.js": "text/javascript", "app.css": "text/css", "logo.svg": "image/svg+xml", "MER-001.webp": "image/webp",
		} {
			name, gotType, ok := websiteFile(httptest.NewRequest(method, "/assets/"+file, nil))
			if !ok || name != "assets/"+file || gotType != contentType {
				t.Errorf("asset %s: %q %q %t", file, name, gotType, ok)
			}
		}
	}
	for _, target := range []string{
		"/orders", "/orders/ORD-1001", "/orders/mine", "/orders/quote", "/support/tickets", "/internal/stock",
		"/inventory/search", "/accounts/login", "/admin/status", "/demo/", "/demo/assets/app.js",
		"/food/", "/store", "/store/", "/store/a/b", "/my-orders/", "/help/a/b", "/signin/extra",
		"/assets/", "/assets/app.js.map", "/assets/x.png", "/assets/x.jpg", "/assets/x.JS", "/assets/../app.js",
		"/assets/sub/app.js", "/assets/%61pp.js", "/assets/%2e%2e%2fapp.js", "/%66ood", "/store/%2f",
		"/store/.", "/item/..", "//food", "/food//", "/assets/..\\app.js",
	} {
		if _, _, ok := websiteFile(httptest.NewRequest(http.MethodGet, target, nil)); ok {
			t.Errorf("unapproved target served as website: %s", target)
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions} {
		for _, target := range []string{"/", "/food", "/assets/app.js"} {
			if _, _, ok := websiteFile(httptest.NewRequest(method, target, nil)); ok {
				t.Errorf("unapproved method served as website: %s %s", method, target)
			}
		}
	}
}

// A page and an asset carry the content policy and nosniff; a missing asset
// and any other target are 404.
func TestFetchWebsiteResponseHeaders(t *testing.T) {
	files := fstest.MapFS{
		"index.html":          {Data: []byte("test page")},
		"assets/MER-001.webp": {Data: []byte("test image")},
	}
	handler := website(files)
	for _, target := range []string{"/", "/food", "/assets/MER-001.webp", "/assets/missing.js", "/orders/mine"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
		if strings.Contains(target, "missing") || strings.HasPrefix(target, "/orders") {
			if w.Code != http.StatusNotFound {
				t.Errorf("%s: %d, want 404", target, w.Code)
			}
			continue
		}
		if w.Code != http.StatusOK || w.Header().Get("Content-Security-Policy") != sitePolicy || w.Header().Get("X-Content-Type-Options") != "nosniff" ||
			w.Header().Get("X-Frame-Options") != "DENY" || w.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: status %d headers %v", target, w.Code, w.Header())
		}
	}
}
