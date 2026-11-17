// Admin API error answers: refusals, failures of the gateway's own parts and
// bare error codes.

package admin

import (
	"context"
	"errors"
	"net/http"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
)

// refuse answers a refused admin request and records why. Only the error code
// reaches the client.
func (s *Server) refuse(w http.ResponseWriter, r *http.Request, status int, code, reason string, who *caller) {
	event := audit.Event{Kind: "admin.rejected", Method: r.Method, Path: r.URL.Path, Status: status, Reason: reason}
	if who != nil {
		event.Kind, event.Actor, event.Session = "admin.denied", who.admin.Name, who.session.Reference
	}
	s.audit.Record(event)
	adminError(w, status, code, "")
}

// fail answers 503 when a part of the gateway failed rather than the request
// (the database, the security log, the password-hashing slots): it logs the
// cause, counts it in the metrics and records the refusal.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, who *caller, code string, f monitor.AdminFailure, err error) {
	// A read whose client left ended for that reason, not a failure: nothing
	// is logged, counted or recorded, and nobody reads an answer.
	if errors.Is(r.Context().Err(), context.Canceled) {
		return
	}
	if err != nil {
		s.logger.Error("admin request failed", "reason", f.String(), "method", r.Method, "path", r.URL.Path, "error", err)
	}
	s.observations.AdminFailed(f)
	s.refuse(w, r, http.StatusServiceUnavailable, code, f.String(), who)
}

// adminError answers with an error code and, where it helps the client, the
// name of the offending field. Nothing else about the failure is disclosed.
func adminError(w http.ResponseWriter, status int, code, field string) {
	body := map[string]string{"error": code}
	if field != "" {
		body["field"] = field
	}
	pipeline.WriteJSON(w, status, body)
}
