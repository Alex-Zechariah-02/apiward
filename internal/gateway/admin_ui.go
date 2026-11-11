// The built dashboard, served on the Admin API listener under a content
// policy of its own origin only, and the check of its files. The page is
// never cached; its assets, whose names change with their content, are
// cached for a year and sent compressed when the build compressed them.

package gateway

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
)

// assetTypes are the only asset types served, each with a fixed content type
// rather than one guessed from the host's registry. The only page is the
// index.
var assetTypes = map[string]string{
	".js":    "text/javascript; charset=utf-8",
	".css":   "text/css; charset=utf-8",
	".svg":   "image/svg+xml",
	".woff2": "font/woff2",
}

// uiPolicy lets the dashboard load only its own scripts, styles, images and
// fonts and call only its own origin, and forbids framing, so injected markup
// cannot run script or exfiltrate data.
const uiPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; " +
	"base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// assetCaching lets a browser keep an asset for a year without asking again.
// A dashboard build names every file under assets/ after its content, so a
// new build is reached through the page, which is never cached.
const assetCaching = "public, max-age=31536000, immutable"

// compressedSuffix names the gzip copy a build may hold in place of an asset.
const compressedSuffix = ".gz"

// dashboard serves the dashboard's page and assets from files, for the Admin
// API to mount at "GET /{$}" and "GET /assets/{file}". The files hold no data,
// so no session is needed; everything the dashboard shows comes from the
// Admin API.
func dashboard(files fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name, contentType := "index.html", "text/html; charset=utf-8"
		file := r.PathValue("file")
		if file != "" {
			name, contentType = "assets/"+file, assetTypes[path.Ext(file)]
		}
		if contentType == "" || !fs.ValidPath(name) {
			http.NotFound(w, r)
			return
		}
		data, encoding, err := frontendFile(files, name, acceptsGzip(r.Header.Get("Accept-Encoding")))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		header := w.Header()
		header.Set("Content-Type", contentType)
		header.Set("Content-Security-Policy", uiPolicy)
		header.Set("X-Frame-Options", "DENY")
		header.Set("Referrer-Policy", "no-referrer")
		header.Set("Vary", "Accept-Encoding")
		if file != "" {
			header.Set("Cache-Control", assetCaching)
		}
		if encoding != "" {
			header.Set("Content-Encoding", encoding)
		}
		header.Set("Content-Length", strconv.Itoa(len(data)))
		w.Write(data) // #nosec G705 -- a file of the operator's own Dashboard build, sent with its content policy
	})
}

// frontendFile reads one file of a built frontend. A build may hold a gzip
// copy in place of a file: that copy is returned as it is, with its encoding,
// for a client that accepts gzip, and inflated for one that does not.
func frontendFile(files fs.FS, name string, gzipAccepted bool) (data []byte, encoding string, err error) {
	packed, err := fs.ReadFile(files, name+compressedSuffix)
	if err != nil {
		data, err = fs.ReadFile(files, name)
		return data, "", err
	}
	if gzipAccepted {
		return packed, "gzip", nil
	}
	reader, err := gzip.NewReader(bytes.NewReader(packed))
	if err != nil {
		return nil, "", err
	}
	data, err = io.ReadAll(reader)
	return data, "", err
}

// acceptsGzip reports whether an Accept-Encoding header allows gzip: an
// entry naming gzip decides, else one for "*"; a quality of zero refuses.
func acceptsGzip(accepted string) bool {
	wildcard := false
	for entry := range strings.SplitSeq(accepted, ",") {
		coding, parameters, _ := strings.Cut(entry, ";")
		coding = strings.TrimSpace(coding)
		quality, weighted := strings.CutPrefix(strings.ReplaceAll(parameters, " ", ""), "q=")
		value, err := strconv.ParseFloat(quality, 64)
		allowed := !weighted || err != nil || value > 0
		if strings.EqualFold(coding, "gzip") {
			return allowed
		}
		if coding == "*" {
			wildcard = allowed
		}
	}
	return wildcard
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
