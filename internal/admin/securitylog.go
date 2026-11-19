// Admin API security log search and export.

package admin

import (
	"errors"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"

	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
)

// maxLogScans is how many security log scans run at once. Each reads up to
// monitor.ExportScan bytes from the disk the log's writer syncs to; parallel
// scans measured beside traffic doubled request p99, so one runs at a time.
const maxLogScans = 1

// scanLog takes the security log scan slot, or answers 503 busy with
// Retry-After at once, as password hashing does: a waiting scan would hold
// a goroutine and a connection with no sign to its client.
func (s *Server) scanLog(w http.ResponseWriter) bool {
	select {
	case s.scans <- struct{}{}:
		return true
	default:
		w.Header().Set("Retry-After", "1")
		adminError(w, http.StatusServiceUnavailable, "busy", "")
		return false
	}
}

func (s *Server) scanDone() { <-s.scans }

// handleSecurityLog searches the request records in the active and rotated
// audit files, newest first, with the same secret-free fields as the live
// views. format=csv or format=json exports up to securityLogExportRows rows.
func (s *Server) handleSecurityLog(w http.ResponseWriter, r *http.Request, who caller) {
	// URL.Query would drop a malformed pair and answer unfiltered rows.
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		adminError(w, http.StatusBadRequest, "bad_request", "query")
		return
	}
	// An unknown or repeated name would be ignored and answer unfiltered rows.
	if !knownQuery(values, "ref", "subject", "operation", "decision", "from", "to", "format", "limit", "after") {
		adminError(w, http.StatusBadRequest, "bad_request", "query")
		return
	}
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
		limit, scan = defaultPageSize, monitor.PageScan
		if text := values.Get("limit"); text != "" {
			n, err := strconv.Atoi(text)
			if err != nil || n < 1 || n > maxPageSize {
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
	if !s.scanLog(w) {
		return
	}
	defer s.scanDone()
	_, _, _, kept := s.audit.Usage()
	files, missing, err := monitor.LogFiles(s.audit.Path(), kept)
	if err != nil {
		s.fail(w, r, &who, "gateway_unavailable", monitor.FailLog, err)
		return
	}
	result, err := monitor.Search(r.Context(), filepath.Dir(s.audit.Path()), files, start, query, limit, scan)
	switch {
	case r.Context().Err() != nil:
		return // the client has gone
	case errors.Is(err, monitor.ErrCursorGone):
		adminError(w, http.StatusGone, "cursor_gone", "after")
		return
	case err != nil:
		s.fail(w, r, &who, "gateway_unavailable", monitor.FailLog, err)
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
