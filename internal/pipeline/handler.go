// The data-plane request pipeline: every stage from ingress to forwarding.

package pipeline

import (
	"net/http"
	"net/netip"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/fault"
	"github.com/Alex-Zechariah-02/apiward/module"
)

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := &request{
		w:            w,
		audit:        h.audit,
		observations: h.observations,
		started:      time.Now(),
		event:        audit.Event{RequestID: audit.NewRequestID(), Time: time.Now().UTC(), Method: r.Method, Path: r.URL.Path},
		bodyPending:  r.ProtoMajor == 1 && (r.ContentLength != 0 || len(r.TransferEncoding) > 0),
	}
	defer q.recoverPanic()
	w.Header().Set("X-Request-Id", q.event.RequestID)
	if len(h.extensions) > 0 {
		q.event.Modules = make(map[string]string, len(h.extensions))
		for _, info := range h.extensions {
			q.event.Modules[info.ID] = audit.StageNotRun
		}
	}
	if peer, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		q.addr, q.forwardedFor = h.clientAddress(peer.Addr().Unmap(), r.Header)
		q.event.ClientAddress = q.addr.String()
		q.rateAddress = h.rateAddress(q.addr, q.event.ClientAddress)
	}
	// Keep credentials only for authentication; discard client identity metadata
	// before any ingress refusal as well as before forwarding.
	credentials := r.Header.Values("Authorization")
	q.event.SetIdentityKnown(len(credentials) == 0)
	StripUntrusted(r.Header)
	// RFC 9110 section 7.8: a server ignores Upgrade in an HTTP/1.0 request.
	if !r.ProtoAtLeast(1, 1) {
		r.Header.Del("Upgrade")
	}

	if reason := h.ingressRefusal(r); reason == "too_large" {
		q.summarise(reason, http.StatusRequestEntityTooLarge, "payload_too_large")
		return
	} else if reason != "" {
		q.summarise(reason, http.StatusBadRequest, "bad_request")
		return
	}
	// The body is read, within the global ceiling, before an in-flight slot
	// is taken: a slow upload holds only its own connection (bounded by
	// data.max_connections and read_timeout), never a slot other clients need.
	body, refused := bufferBody(r, h.maxBodyBytes)
	if refused != nil {
		q.summarise(refused.reason, refused.status, refused.code)
		return
	}
	q.bodyPending = false

	// Overload: past maxInFlight requests, refuse before any token check, so
	// excess load costs as little as possible.
	if h.inFlight.Add(1) > h.maxInFlight {
		h.inFlight.Add(-1)
		w.Header().Set("Retry-After", "1")
		q.summarise("overloaded", http.StatusServiceUnavailable, "overloaded")
		return
	}
	defer h.inFlight.Add(-1)
	if !h.admitAddress(q) {
		return
	}
	q.pass(audit.StageIngress)
	if !h.runModules(q, r, module.Ingress, moduleView{path: r.URL.Path}) {
		return
	}

	// Capture: the single generation used for every later decision.
	g := h.authority.Current()
	if g == nil || h.held.Load() {
		q.reject(audit.StageCapture, http.StatusServiceUnavailable, "gateway_unavailable")
		return
	}
	// A generation past its earliest deadline (a provisional base's or an
	// override's) admits nothing, even if the controller's timer is late; the
	// controller is asked to end what expired now.
	// Lapsed reads the trusted clock only for a generation with a deadline.
	if g.Lapsed() {
		h.authority.Expired(g)
		q.reject(audit.StageCapture, http.StatusServiceUnavailable, "gateway_unavailable")
		return
	}
	q.event.Generation, q.event.Profile = g.ID, g.Profile
	q.pass(audit.StageCapture)
	fault.SignalCapture(r.URL.Path, g.ID)

	path, ok := compile.CanonicalPath(r)
	if !ok {
		q.reject(audit.StageCanonical, http.StatusBadRequest, "bad_request")
		return
	}
	q.pass(audit.StageCanonical)

	inbound := compile.Inbound{Host: r.Host, Header: r.Header}
	if isPreflight(r) && h.preflight(q, g, path, inbound) {
		return
	}
	// The routing and permission order is the generation's, shared with the
	// access checker (compile.Route, compile.Admit).
	t, rule, code := g.Route(path, r.Method, inbound)
	if code == "not_found" {
		q.reject(audit.StageRoute, http.StatusNotFound, code)
		return
	}
	if r.Method == http.MethodOptions && maxForwards(q, r, t.Allow()) {
		return
	}
	if code == "method_not_allowed" {
		w.Header().Set("Allow", t.Allow())
		q.reject(audit.StageRoute, http.StatusMethodNotAllowed, code)
		return
	}
	q.event.Operation, q.event.API, q.event.Upstream = rule.Operation(), rule.API(), rule.Upstream()
	// From here every answer, refusals included, carries the API's browser
	// access and response headers.
	q.w = newAPIWriter(w, rule, r)
	w = q.w
	if !rule.Admits(q.addr) {
		q.reject(audit.StageRoute, http.StatusForbidden, "address_not_allowed")
		return
	}
	q.pass(audit.StageRoute)

	if !rule.Permitted() {
		q.reject(audit.StageAccess, http.StatusForbidden, "forbidden")
		return
	}
	q.pass(audit.StageAccess)

	// Authentication and authorisation apply to every operation not declared
	// public. Roles come only from verified claims and are filtered through
	// the declared roles of the one captured generation.
	var roles []string
	if rule.Public() {
		q.event.Stages[audit.StageJWT] = audit.StageNotApplicable
		q.event.Stages[audit.StageRBAC] = audit.StageNotApplicable
		view := moduleView{path: path, rule: rule}
		if !h.runModules(q, r, module.Identity, view) || !h.runModules(q, r, module.Authorise, view) {
			return
		}
	} else {
		q.event.SetIdentityKnown(true)
		token, reason := bearerToken(credentials)
		var verified verifiedToken
		if reason == "" {
			verified, reason = h.authority.Verifier().verify(token, time.Now())
			q.event.Subject = verified.subject
		}
		if reason != "" {
			q.event.Reason = reason
			w.Header().Set("WWW-Authenticate", "Bearer")
			q.reject(audit.StageJWT, http.StatusUnauthorized, "unauthenticated")
			return
		}
		q.pass(audit.StageJWT)
		if !h.runModules(q, r, module.Identity, moduleView{path: path, rule: rule}) {
			return
		}
		blocked := h.authority.Blocked()
		if blocked == nil {
			q.reject(audit.StageRBAC, http.StatusServiceUnavailable, "gateway_unavailable")
			return
		}
		roles, q.event.IgnoredRoles, reason = g.Admit(verified.roles, rule, func() bool {
			_, found := (*blocked)[q.event.Subject]
			return found
		})
		q.event.Roles = roles
		switch reason {
		case "":
		case "account_blocked":
			q.event.Reason = reason
			q.reject(audit.StageRBAC, http.StatusForbidden, reason)
			return
		default:
			q.event.Reason = reason
			q.reject(audit.StageRBAC, http.StatusForbidden, "forbidden")
			return
		}
		q.pass(audit.StageRBAC)
		if !h.runModules(q, r, module.Authorise, moduleView{path: path, rule: rule, roles: roles}) {
			return
		}
	}

	if !h.limit(q, rule) || !h.runModules(q, r, module.Traffic, moduleView{path: path, rule: rule, roles: roles}) {
		return
	}

	document, refused := readBody(r, body, rule.Body(), h.maxBodyBytes)
	if refused != nil {
		q.event.Reason = refused.reason
		q.reject(audit.StageBody, refused.status, refused.code)
		return
	}
	q.pass(audit.StageBody)

	if rule.Body() == nil && rule.Headers() == nil {
		q.event.Stages[audit.StageValidation] = audit.StageNotApplicable
	} else {
		if reason := ValidateRequest(r.Header, document, rule); reason != "" {
			q.event.Reason = reason
			q.reject(audit.StageValidation, http.StatusBadRequest, "bad_request")
			return
		}
		q.pass(audit.StageValidation)
	}
	if !h.runModules(q, r, module.Validate, moduleView{path: path, rule: rule, roles: roles}) {
		return
	}

	// The API's forward rule rewrites the path only now, after every decision
	// was made on the inbound path; a rewritten path that is not canonical
	// is never forwarded.
	destination, ok := rule.Destination(path)
	if !ok {
		q.reject(audit.StageBind, http.StatusBadRequest, "path_not_canonical")
		return
	}
	if destination.Path() != path {
		q.event.ForwardedPath = destination.Path()
	}

	h.send(q, r, g, rule, roles, destination)
}
