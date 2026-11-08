// The built dashboard, served on the Admin API listener under a content
// policy of its own origin only, and the check of its files.

package gateway

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path"
)

// assetTypes are the only asset types served, each with a fixed content type
// rather than one guessed from the host's registry. The only page is the
// index.
var assetTypes = map[string]string{
	".js":  "text/javascript; charset=utf-8",
	".css": "text/css; charset=utf-8",
	".svg": "image/svg+xml",
}

// uiPolicy lets the dashboard load only its own
// scripts and styles and call only its own origin, and forbids framing, so
// injected markup cannot run script or exfiltrate data.
const uiPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; " +
	"base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// dashboard serves the dashboard's page and assets from files, for the Admin
// API to mount at "GET /{$}" and "GET /assets/{file}". The files hold no data,
// so no session is needed; everything the dashboard shows comes from the
// Admin API.
func dashboard(files fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name, contentType := "index.html", "text/html; charset=utf-8"
		if file := r.PathValue("file"); file != "" {
			name, contentType = "assets/"+file, assetTypes[path.Ext(file)]
		}
		if contentType == "" || !fs.ValidPath(name) {
			http.NotFound(w, r)
			return
		}
		serveFrontendFile(w, r, files, name, contentType)
	})
}

// serveFrontendFile answers with one file of a built frontend under the
// frontends' content policy, or 404 when it cannot be read.
func serveFrontendFile(w http.ResponseWriter, r *http.Request, files fs.FS, name, contentType string) {
	data, err := fs.ReadFile(files, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Security-Policy", uiPolicy)
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Write(data)
}

// Where the dashboard's files come from, as the start log names it.
const (
	uiDirectory = "directory"
	uiEmbedded  = "embedded"
	uiNone      = "none"
)

// dashboardFiles picks the dashboard's files: the admin_ui directory when the
// operator set one, else the build embedded in this binary, else none. It
// returns the files (nil for none) and their source.
func dashboardFiles(dir string, embedded fs.FS) (fs.FS, string, error) {
	switch {
	case dir != "":
		files := os.DirFS(dir)
		if !hasIndex(files) {
			return nil, "", fmt.Errorf("admin_ui %q must be a directory holding index.html", dir)
		}
		return files, uiDirectory, nil
	case embedded != nil:
		if !hasIndex(embedded) {
			return nil, "", errors.New("the embedded dashboard has no index.html")
		}
		return embedded, uiEmbedded, nil
	}
	return nil, uiNone, nil
}

func hasIndex(files fs.FS) bool {
	info, err := fs.Stat(files, "index.html")
	return err == nil && info.Mode().IsRegular()
}
