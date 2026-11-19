// The in-flight bound per upstream: one slow upstream may hold at most its
// share of the requests in flight, so it cannot starve the others (a
// bulkhead, as Envoy's per-cluster circuit breaker and HAProxy's per-server
// maxconn bound one backend).

package pipeline

import (
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
)

// upstreamSlots counts the requests in flight to each upstream; an upstream
// appears on its first request and stays, bounded by the policy's upstreams.
type upstreamSlots struct {
	max    int64
	counts sync.Map // upstream ID → *atomic.Int64
}

// take counts a request to upstream in, or returns nil when the upstream
// already has max in flight.
func (s *upstreamSlots) take(upstream string) *atomic.Int64 {
	value, ok := s.counts.Load(upstream)
	if !ok {
		value, _ = s.counts.LoadOrStore(upstream, new(atomic.Int64))
	}
	count := value.(*atomic.Int64)
	if count.Add(1) > s.max {
		count.Add(-1)
		return nil
	}
	return count
}

// takeUpstream reserves q's place at its upstream before admission, or
// refuses it 503 upstream_busy with Retry-After. The caller gives the place
// back when the exchange ends.
func (h *Handler) takeUpstream(q *request, upstream string) *atomic.Int64 {
	slot := h.upstreams.take(upstream)
	if slot == nil {
		q.w.Header().Set("Retry-After", "1")
		q.event.Reason = "upstream_busy"
		q.reject(audit.StageAudit, http.StatusServiceUnavailable, "upstream_busy")
	}
	return slot
}
