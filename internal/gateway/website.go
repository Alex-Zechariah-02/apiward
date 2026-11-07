// The Fetch website served beside enforcement on the data plane.

package gateway

import (
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
)

// dataPlane is the data-plane server's handler: enforcement for every request,
// except the website's exact routes when a website is configured. No router
// cleans or redirects a path before enforcement sees it.
func dataPlane(enforcement http.Handler, website fs.FS) http.Handler {
	if website == nil {
		return enforcement
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name, contentType, ok := websiteFile(r)
		if !ok {
			enforcement.ServeHTTP(w, r)
			return
		}
		pipeline.StripUntrusted(r.Header)
		w.Header().Set("X-Request-Id", audit.NewRequestID())
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		serveFrontendFile(w, r, website, name, contentType)
	})
}

// websiteFile names the Fetch page at an approved client route, or a file
// of the flat assets directory at /assets/<name>. The
// request target is compared as received, before any decoding, and an asset
// name may hold only letters, digits, '.', '-' and '_', so no target reaches
// any other file. Every other request is not the website's.
func websiteFile(r *http.Request) (name, contentType string, ok bool) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return "", "", false
	}
	target, _, _ := strings.Cut(r.RequestURI, "?")
	if isWebsitePage(target) {
		return "index.html", "text/html; charset=utf-8", true
	}
	asset, found := strings.CutPrefix(target, "/assets/")
	switch path.Ext(asset) {
	case ".js":
		contentType = "text/javascript"
	case ".css":
		contentType = "text/css"
	case ".svg":
		contentType = "image/svg+xml"
	case ".webp":
		contentType = "image/webp"
	}
	if !found || contentType == "" || !isAssetName(asset) {
		return "", "", false
	}
	return "assets/" + asset, contentType, true
}

func isWebsitePage(target string) bool {
	switch target {
	case "/", "/food", "/mart", "/cart", "/checkout", "/my-orders", "/help", "/signin",
		"/merchant", "/rider", "/support", "/ops", "/lab", "/account":
		return true
	}
	if !compile.IsCanonical(target) {
		return false
	}
	for _, prefix := range []string{"/store/", "/item/", "/my-orders/", "/help/"} {
		if id, found := strings.CutPrefix(target, prefix); found && id != "" && !strings.Contains(id, "/") {
			return true
		}
	}
	return false
}

func isAssetName(name string) bool {
	for _, c := range name {
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '.', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}
