// The Fetch website server: the built shop on its own loopback upstream,
// reached only through the gateway's public website operations. It answers
// only the shop's client routes and its flat assets directory; everything
// else is 404.

package main

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"path"
	"slices"
	"strings"
	"time"
)

// sitePolicy lets the shop load only its own scripts, styles and images and
// call only its own origin, and forbids framing, so injected markup cannot
// run script or send data elsewhere.
const sitePolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; " +
	"base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// assetTypes are the only asset types served, each with a fixed content type
// rather than one guessed from the host's registry.
var assetTypes = map[string]string{
	".js":   "text/javascript",
	".css":  "text/css",
	".svg":  "image/svg+xml",
	".webp": "image/webp",
}

// sitePages are the shop's exact client routes, and sitePrefixes those that
// take one more path segment (an ID or a name); every one returns the page.
var (
	sitePages = []string{"/", "/food", "/mart", "/cart", "/checkout", "/my-orders", "/help", "/signin",
		"/merchant", "/rider", "/support", "/ops", "/lab", "/account"}
	sitePrefixes = []string{"/store/", "/item/", "/my-orders/", "/help/"}
)

// website serves the built shop in files.
func website(files fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name, contentType, ok := websiteFile(r)
		if !ok {
			http.NotFound(w, r)
			return
		}
		data, err := fs.ReadFile(files, name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Security-Policy", sitePolicy)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(data)
	})
}

// websiteFile names the page at an approved client route, or a file of the
// flat assets directory at /assets/<name>. The target is compared as
// received, before any decoding, and an asset name may hold only letters,
// digits, '.', '-' and '_', so no target reaches any other file.
func websiteFile(r *http.Request) (name, contentType string, ok bool) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return "", "", false
	}
	target, _, _ := strings.Cut(r.RequestURI, "?")
	if isWebsitePage(target) {
		return "index.html", "text/html; charset=utf-8", true
	}
	asset, found := strings.CutPrefix(target, "/assets/")
	contentType = assetTypes[path.Ext(asset)]
	if !found || contentType == "" || !isPlainName(asset) {
		return "", "", false
	}
	return "assets/" + asset, contentType, true
}

// isWebsitePage reports whether target is an exact client route, or a
// prefixed route with one segment of visible ASCII other than '\' and '%'
// that is not a dot segment.
func isWebsitePage(target string) bool {
	if slices.Contains(sitePages, target) {
		return true
	}
	for _, prefix := range sitePrefixes {
		if id, found := strings.CutPrefix(target, prefix); found && isSegment(id) {
			return true
		}
	}
	return false
}

func isSegment(id string) bool {
	if id == "" || id == "." || id == ".." {
		return false
	}
	for i := 0; i < len(id); i++ {
		if c := id[i]; c < 0x21 || c > 0x7e || c == '/' || c == '\\' || c == '%' {
			return false
		}
	}
	return true
}

// isPlainName accepts a nonempty name of letters, digits, '.', '-' and '_'.
func isPlainName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '.', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// serveWebsite serves files on listener until ctx ends, then stops within
// the bound and reports why the server ended, nil for a requested stop.
func serveWebsite(ctx context.Context, listener net.Listener, files fs.FS) error {
	server := &http.Server{Handler: website(files), ReadHeaderTimeout: 5 * time.Second}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdown)
	}()
	err := server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		<-stopped
		return nil
	}
	return err
}
