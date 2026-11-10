// Per-request stage state.

package pipeline

import (
	"net/http"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
)

// request tracks one request through the stages for its security event.
type request struct {
	event        audit.Event
	w            http.ResponseWriter
	audit        *audit.AuditLog
	observations *monitor.Observations
	started      time.Time
	// rateAddress keys the client's address-based rate counters: the
	// address, or for IPv6 its configured prefix.
	rateAddress string
	// bodyPending is true while a declared request body has not been
	// consumed by validation.
	bodyPending bool
}

func (q *request) pass(stage int) { q.event.Stages[stage] = audit.StagePass }

func (q *request) reject(stage int, status int, code string) {
	q.refuse(stage, audit.StageReject, status, code, code)
}

// fail ends the request at stage with 503 gateway_unavailable because a
// module failed; reason names the module and says why, without request data,
// and is what the record keeps as its error.
func (q *request) fail(stage int, reason string) {
	q.refuse(stage, audit.StageFail, http.StatusServiceUnavailable, "gateway_unavailable", reason)
}

// refuse records the stage result and the refusal, then answers with code.
func (q *request) refuse(stage int, result string, status int, code, recorded string) {
	q.event.Kind, q.event.Stage, q.event.Decision = "request.rejected", audit.StageNames[stage], "reject"
	q.event.Stages[stage] = result
	q.event.Status, q.event.Error = status, recorded
	q.event.DurationMS = float64(time.Since(q.started)) / float64(time.Millisecond)
	q.audit.Record(q.event)
	q.observations.Record(q.event)
	if q.bodyPending {
		// Closing the connection stops net/http from reading the unread body
		// before it writes the rejection, which a client that declares a body
		// and never sends it could otherwise hold open.
		q.w.Header().Set("Connection", "close")
	}
	writeError(q.w, status, code, q.event.RequestID)
}

// forwarded records the outcome of a request that was handed to the
// forwarder.
func (q *request) forwarded(status int, decision, code string) {
	q.event.Kind, q.event.Stage = "request.forwarded", audit.StageNames[audit.StageForward]
	q.event.Stages[audit.StageForward] = audit.StagePass
	if decision != "forwarded" {
		q.event.Stages[audit.StageForward] = audit.StageFail
	}
	q.event.Decision, q.event.Status, q.event.Error = decision, status, code
	q.event.DurationMS = float64(time.Since(q.started)) / float64(time.Millisecond)
	q.audit.Record(q.event)
	q.observations.Record(q.event)
}

// answerPreflight records and answers a CORS preflight: 204, with whatever
// CORS headers the caller set. It is never forwarded.
func (q *request) answerPreflight(allowed bool) {
	q.event.Kind, q.event.Stage, q.event.Status = "request.preflight", audit.StageNames[audit.StageRoute], http.StatusNoContent
	q.event.Decision, q.event.Error, q.event.Stages[audit.StageRoute] = "allowed", "cors_preflight", audit.StagePass
	if !allowed {
		q.event.Decision, q.event.Error, q.event.Stages[audit.StageRoute] = "refused", "cors_refused", audit.StageReject
	}
	q.event.DurationMS = float64(time.Since(q.started)) / float64(time.Millisecond)
	q.audit.Record(q.event)
	q.observations.Record(q.event)
	q.w.WriteHeader(http.StatusNoContent)
}
