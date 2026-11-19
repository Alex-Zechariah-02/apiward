// A security log export that cannot be written in full aborts the
// connection instead of ending like a complete file.

package admin

import (
	"errors"
	"net/http"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
)

// brokenWriter accepts headers and refuses every body write, as a reset
// connection does.
type brokenWriter struct{ header http.Header }

func (b *brokenWriter) Header() http.Header       { return b.header }
func (b *brokenWriter) WriteHeader(int)           {}
func (b *brokenWriter) Write([]byte) (int, error) { return 0, errors.New("connection reset") }

func TestExportAbortsOnWriteFailure(t *testing.T) {
	defer func() {
		if recovered := recover(); recovered != http.ErrAbortHandler {
			t.Fatalf("recovered %v, want http.ErrAbortHandler", recovered)
		}
	}()
	writeSecurityLogCSV(&brokenWriter{header: http.Header{}}, monitor.Result{}, nil, nil)
}
