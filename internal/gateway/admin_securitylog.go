// Admin API security log search and export.

package gateway

import (
	"errors"
	"net/http"
	"path/filepath"
	"strconv"

	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
)

// handleSecurityLog searches the request records in the active and rotated
// audit files, newest first, with the same secret-free fields as the live
// views. format=csv or format=json exports up to securityLogExportRows rows.
func (c *Controller) handleSecurityLog(w http.ResponseWriter, r *http.Request, who caller) {
	values := r.URL.Query()
	query, field := monitor.ParseQuery(values)
	if field != "" {
		adminError(w, http.StatusBadRequest, "bad_request", field)
		return
	}
	format := values.Get("format")
	if format != "" && format != "csv" && format != "json" {
		adminError(w, http.StatusBadRequest, "bad_request", "format")
		return
	}
	limit, scan := monitor.ExportRows, int64(monitor.ExportScan)
	if format == "" {
		limit, scan = 50, monitor.PageScan
		if text := values.Get("limit"); text != "" {
			n, err := strconv.Atoi(text)
			if err != nil || n < 1 || n > 100 {
				adminError(w, http.StatusBadRequest, "bad_request", "limit")
				return
			}
			limit = n
		}
	}
	var start *monitor.Cursor
	if text := values.Get("after"); text != "" {
		start = monitor.DecodeCursor(text)
		if start == nil {
			adminError(w, http.StatusBadRequest, "bad_request", "after")
			return
		}
	}
	files, missing, err := monitor.LogFiles(c.audit.Path())
	if err != nil {
		adminError(w, http.StatusServiceUnavailable, "gateway_unavailable", "")
		return
	}
	result, err := monitor.Search(filepath.Dir(c.audit.Path()), files, start, query, limit, scan)
	if errors.Is(err, monitor.ErrCursorGone) {
		adminError(w, http.StatusGone, "cursor_gone", "after")
		return
	}
	if err != nil {
		adminError(w, http.StatusServiceUnavailable, "gateway_unavailable", "")
		return
	}
	var next *string
	if result.Next != nil {
		encoded := monitor.EncodeCursor(*result.Next)
		next = &encoded
	}
	if format == "csv" {
		writeSecurityLogCSV(w, result, next, missing)
		return
	}
	if format == "json" {
		w.Header().Set("Content-Disposition", `attachment; filename="security-log.json"`)
	}
	pipeline.WriteJSON(w, http.StatusOK, map[string]any{
		"items":            result.Items,
		"next":             next,
		"complete":         next == nil,
		"files_searched":   result.Searched,
		"files_missing":    missing,
		"unreadable_lines": result.Unreadable,
	})
}
