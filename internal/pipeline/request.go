// Per-request stage state.

package pipeline

import (
	"fmt"
	"net/http"
	"os"
	"runtime/debug"
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
	// bodyPending is true while a declared HTTP/1 request body has not been
	// consumed by validation. HTTP/2 needs no connection close for it: the
	// server resets the stream, and "Connection: close" would end every
	// stream on the connection (a GOAWAY).
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
	q.settle(stage, result, status, recorded)
	q.audit.Record(q.event)
	q.answer(status, code)
}

// summarise refuses at INGRESS a request no policy can act on. The security
// log counts it under reason in its next ingress summary instead of keeping
// a record of its own, so a flood of such requests costs no record each.
func (q *request) summarise(reason string, status int, code string) {
	q.event.Reason = reason
	q.settle(audit.StageIngress, audit.StageReject, status, code)
	q.audit.Summarise(reason, q.event.ClientAddress)
	q.answer(status, code)
}

// settle completes the event of a refused request.
func (q *request) settle(stage int, result string, status int, recorded string) {
	q.event.Kind, q.event.Stage, q.event.Decision = "request.rejected", audit.StageNames[stage], "reject"
	q.event.Stages[stage] = result
	q.event.Status, q.event.Error = status, recorded
	q.event.DurationMS = float64(time.Since(q.started)) / float64(time.Millisecond)
}

// answer reports a refused request to monitoring and writes its error.
func (q *request) answer(status int, code string) {
	q.observations.Record(q.event)
	if q.bodyPending {
		// Closing the connection stops net/http from reading the unread body
		// before it writes the rejection, which a client that declares a body
		// and never sends it could otherwise hold open.
		q.w.Header().Set("Connection", "close")
		// After the handler net/http still reads up to 256 KiB of an unread
		// chunked body, from a client that may have stalled; an expired read
		// deadline ends that read at once, so the connection closes. A writer
		// without deadlines (ErrNotSupported) leaves read_timeout to bound it.
		_ = http.NewResponseController(q.w).SetReadDeadline(time.Now())
	}
	writeError(q.w, status, code, q.event.RequestID)
}

// forwarded records the outcome of a request that was handed to the
// forwarder. The durable record leaves the stage results out: the admission
// record of the same request holds them, and the decision tells FORWARD's.
func (q *request) forwarded(status int, decision, code string) {
	q.event.Kind, q.event.Stage = "request.forwarded", audit.StageNames[audit.StageForward]
	q.event.Stages[audit.StageForward] = audit.StagePass
	if decision != "forwarded" {
		q.event.Stages[audit.StageForward] = audit.StageFail
	}
	q.event.Decision, q.event.Status, q.event.Error = decision, status, code
	q.event.DurationMS = float64(time.Since(q.started)) / float64(time.Millisecond)
	outcome := q.event
	clear(outcome.Stages[:])
	q.audit.Record(outcome)
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

// recoverPanic ends a request whose enforcement panicked, which net/http
// would otherwise end with no outcome in the security log. A request with no
// outcome yet is recorded as failed (internal_error) and answered 500;
// nothing was sent for it, since every response is written with or after its
// outcome. A request whose outcome is recorded may have a response under way,
// so its connection is aborted. The forwarder's own abort, http.ErrAbortHandler,
// passes through: its outcome is recorded by the forward stage.
func (q *request) recoverPanic() {
	recovered := recover()
	if recovered == nil {
		return
	}
	if recovered == http.ErrAbortHandler {
		panic(recovered)
	}
	fmt.Fprintf(os.Stderr, "gateway: panic in request %s: %v\n%s", q.event.RequestID, recovered, debug.Stack())
	if q.event.Kind != "" && q.event.Kind != "request.admitted" {
		panic(http.ErrAbortHandler)
	}
	q.event.Kind, q.event.Decision = "request.rejected", "failed"
	q.event.Status, q.event.Error, q.event.Reason = http.StatusInternalServerError, "internal_error", "internal_error"
	q.event.DurationMS = float64(time.Since(q.started)) / float64(time.Millisecond)
	q.audit.Record(q.event)
	q.observations.Record(q.event)
	writeError(q.w, http.StatusInternalServerError, "internal_error", q.event.RequestID)
}
