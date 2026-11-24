// Admission and forwarding: the durable admission record, the headers the
// upstream may rely on, and the hand-over to the forwarder with the record
// of its outcome.

package pipeline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/forward"
)

// send reserves the upstream slot, signs the identity assertion, records the
// admission of a request that passed every stage, then forwards it to
// destination and records the outcome.
func (h *Handler) send(q *request, r *http.Request, g *compile.Generation, rule *compile.Rule, roles []string, destination compile.Destination) {
	w := q.w
	slot := h.takeUpstream(q, rule.Upstream())
	if slot == nil {
		return
	}
	defer slot.Add(-1)
	assertion, ok := h.assert(q, rule, roles, r.Method, destination.Path())
	if !ok {
		return
	}
	// Admission requires a durable audit record before anything is forwarded.
	// The record is written only when AUDIT passes, so it says so.
	q.event.Kind, q.event.Stage, q.event.Decision = "request.admitted", audit.StageNames[audit.StageAudit], "admit"
	q.pass(audit.StageAudit)
	ctx, cancel := context.WithTimeout(r.Context(), h.auditTimeout)
	err := q.audit.Commit(ctx, q.event)
	cancel()
	if err != nil {
		// A timed-out admission was withdrawn, or is written and superseded
		// by this refusal of the same request.
		if errors.Is(err, audit.ErrTimedOut) {
			q.event.Reason = "audit_timeout"
		}
		q.reject(audit.StageAudit, http.StatusServiceUnavailable, "gateway_unavailable")
		return
	}

	r.Header.Set("X-Request-Id", q.event.RequestID)
	r.Header.Set("X-Gateway-Generation", g.ID)
	if !rule.Public() {
		// The upstream can rely on these for its own object-level rules: client
		// copies were removed at ingress.
		r.Header.Set("X-Gateway-Subject", q.event.Subject)
		r.Header.Set("X-Gateway-Roles", strings.Join(roles, ","))
	}
	if assertion != "" {
		r.Header.Set(AssertionHeader, assertion)
	}
	r = r.WithContext(forward.Bind(r.Context(), destination, q.forwardedFor))
	q.pass(audit.StageBind)

	recorder := &statusRecorder{ResponseWriter: w}
	finished := false
	defer func() {
		if !finished {
			q.abandoned(recover(), recorder)
		}
	}()
	forwardErr := h.forward(recorder, r)
	finished = true
	q.event.UpstreamMS = float64(forward.UpstreamTime(r.Context())) / float64(time.Millisecond)
	if forwardErr != nil {
		status, code := forward.ForwardFailure(forwardErr)
		if !recorder.wrote {
			writeError(w, status, code, q.event.RequestID)
		}
		q.event.Reason = forward.FailureReason(forwardErr)
		if d, bound := forward.Bound(r.Context()); bound && d.Endpoint() != nil {
			q.event.UpstreamAddress = d.Endpoint().Address()
		}
		q.forwarded(status, "upstream_failure", code)
		return
	}
	q.forwarded(recorder.status, "forwarded", "")
}

// abandoned records a forward that ended in a panic, recovered as recovered.
// The forwarder aborts a response it cannot complete, such as a truncated
// upstream body, by panicking with http.ErrAbortHandler after the status was
// sent: that is an upstream failure, and the abort goes on, so the server
// closes the connection and the client sees the response is incomplete. Any
// other panic is the gateway's own failure: answered 500 internal_error when
// nothing was sent, and otherwise aborted the same way.
func (q *request) abandoned(recovered any, recorder *statusRecorder) {
	if recovered == nil || recovered == http.ErrAbortHandler {
		q.forwarded(recorder.status, "upstream_failure", "upstream_incomplete")
		if recovered != nil {
			panic(recovered)
		}
		return
	}
	slog.Error("panic in forwarder", "request_id", q.event.RequestID, "panic", fmt.Sprint(recovered), "stack", string(debug.Stack()))
	if recorder.wrote {
		q.forwarded(recorder.status, "failed", "internal_error")
		panic(http.ErrAbortHandler)
	}
	q.forwarded(http.StatusInternalServerError, "failed", "internal_error")
	writeError(recorder.ResponseWriter, http.StatusInternalServerError, "internal_error", q.event.RequestID)
}
