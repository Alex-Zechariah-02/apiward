//go:build embedui

// The Dashboard build embedded in a release binary.

package adminui

import (
	"embed"
	"io/fs"
)

//go:embed dist
var dist embed.FS

// Files is the embedded build, rooted at its index.html.
var Files fs.FS = root()

// root strips the dist/ prefix; fs.Sub fails only for an invalid name, and
// "dist" is a valid one.
func root() fs.FS {
	files, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	return files
}
