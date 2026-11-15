// The built dashboard, served on the Admin API listener under a content
// policy of its own origin only, and the check of its files. The page is
// never stored; its assets, whose names change with their content, are
// cached for a year and sent compressed when the build compressed them, or
// inflated while they are sent. A configured directory is read through
// os.Root, so no link in it reaches a file outside it.

package gateway

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"regexp"
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
// new build is reached through the page, which is never stored.
const assetCaching = "public, max-age=31536000, immutable"

// pageCaching keeps the page out of every cache, so a new build is seen at
// once; the Admin API sends the same for its own answers.
const pageCaching = "no-store"

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
		body, size, encoding, err := frontendFile(files, name, acceptsGzip(r.Header.Get("Accept-Encoding")))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer body.Close()
		header := w.Header()
		header.Set("Content-Type", contentType)
		header.Set("Content-Security-Policy", uiPolicy)
		header.Set("X-Frame-Options", "DENY")
		header.Set("Referrer-Policy", "no-referrer")
		header.Set("Vary", "Accept-Encoding")
		header.Set("Cache-Control", pageCaching)
		if file != "" {
			header.Set("Cache-Control", assetCaching)
		}
		if encoding != "" {
			header.Set("Content-Encoding", encoding)
		}
		if size >= 0 {
			header.Set("Content-Length", strconv.FormatInt(size, 10))
		}
		// #nosec G705 -- a file of the operator's own Dashboard build, sent with its content policy
		if _, err := io.Copy(w, body); err != nil {
			// A copy that broke off must not end as a complete response.
			panic(http.ErrAbortHandler)
		}
	})
}

// frontendFile opens one file of a built frontend and returns its size, or
// -1 when it is inflated while it is read. A build may hold a gzip copy in
// place of a file: that copy is returned as it is, with its encoding, for a
// client that accepts gzip, and inflated as it is sent for one that does not,
// so no file is held in memory whole.
func frontendFile(files fs.FS, name string, gzipAccepted bool) (io.ReadCloser, int64, string, error) {
	packed, size, err := openRegular(files, name+compressedSuffix)
	if err != nil {
		plain, size, err := openRegular(files, name)
		return plain, size, "", err
	}
	if gzipAccepted {
		return packed, size, "gzip", nil
	}
	reader, err := gzip.NewReader(packed)
	if err != nil {
		return nil, 0, "", errors.Join(err, packed.Close())
	}
	return inflated{reader, packed}, -1, "", nil
}

// inflated is a gzip copy read inflated; closing it closes the file too.
type inflated struct {
	*gzip.Reader
	file fs.File
}

func (i inflated) Close() error { return errors.Join(i.Reader.Close(), i.file.Close()) }

// openRegular opens name when it is a regular file and returns its size.
func openRegular(files fs.FS, name string) (fs.File, int64, error) {
	f, err := files.Open(name)
	if err != nil {
		return nil, 0, err
	}
	info, err := f.Stat()
	if err == nil && !info.Mode().IsRegular() {
		err = fmt.Errorf("%s is not a regular file", name)
	}
	if err != nil {
		return nil, 0, errors.Join(err, f.Close())
	}
	return f, info.Size(), nil
}

// qvalue is a weight as RFC 9110 section 12.4.2 writes it: 0 to 1 with at
// most three decimals.
var qvalue = regexp.MustCompile(`^(0(\.[0-9]{0,3})?|1(\.0{0,3})?)$`)

// acceptsGzip reports whether an Accept-Encoding header allows gzip: an
// entry naming gzip decides, else one for "*". An entry's weight is its q
// parameter wherever it stands among the parameters; a weight of zero, or
// one that is not a valid qvalue, refuses.
func acceptsGzip(accepted string) bool {
	wildcard := false
	for entry := range strings.SplitSeq(accepted, ",") {
		coding, parameters, _ := strings.Cut(entry, ";")
		coding = strings.TrimSpace(coding)
		allowed := weighted(parameters)
		if strings.EqualFold(coding, "gzip") {
			return allowed
		}
		if coding == "*" {
			wildcard = allowed
		}
	}
	return wildcard
}

// weighted reports whether an entry's parameters leave it acceptable: no q
// parameter, or a valid nonzero one.
func weighted(parameters string) bool {
	for parameter := range strings.SplitSeq(parameters, ";") {
		name, value, _ := strings.Cut(parameter, "=")
		if !strings.EqualFold(strings.TrimSpace(name), "q") {
			continue
		}
		value = strings.TrimSpace(value)
		weight, err := strconv.ParseFloat(value, 64)
		return qvalue.MatchString(value) && err == nil && weight > 0
	}
	return true
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
		files := rootDir(dir)
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

// rootDir reads a directory through os.Root, which refuses a name or link
// that leads outside it. Each open takes the root anew, so nothing stays open
// between requests; an opened file outlives its root.
type rootDir string

func (dir rootDir) Open(name string) (fs.File, error) {
	root, err := os.OpenRoot(string(dir))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.FS().Open(name)
}

func hasIndex(files fs.FS) bool {
	info, err := fs.Stat(files, "index.html")
	return err == nil && info.Mode().IsRegular()
}
