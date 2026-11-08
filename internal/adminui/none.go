//go:build !embedui

// A build without the Dashboard: development and library builds.

package adminui

import "io/fs"

// Files is nil: this build embeds no Dashboard.
var Files fs.FS
