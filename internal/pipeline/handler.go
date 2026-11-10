// The data-plane request pipeline: every stage from ingress to forwarding.

package pipeline

import (
	"context"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/fault"
	"github.com/Alex-Zechariah-02/apiward/internal/forward"
	"github.com/Alex-Zechariah-02/apiward/module"
)

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := &request{
		w:            w,
		audit:        h.audit,
		observations: h.observations,
		started:      time.Now(),
		event:        audit.Event{RequestID: audit.NewRequestID(), Time: time.Now().UTC(), Method: r.Method, Path: r.URL.Path},
		bodyPending:  r.ContentLength != 0 || len(r.TransferEncoding) > 0,
	}
	w.Header().Set("X-Request-Id", q.event.RequestID)
	if len(h.extensions) > 0 {
		q.event.Modules = make(map[string]string, len(h.extensions))
		for _, info := range h.extensions {
			q.event.Modules[info.ID] = audit.StageNotRun
		}
	}
	if peer, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		addr := peer.Addr().Unmap()
		q.event.ClientAddress = addr.String()
		q.rateAddress = h.rateAddress(addr)
	}
	// Keep credentials only for authentication; discard client identity metadata
	// before any ingress refusal as well as before forwarding.
	credentials := r.Header.Values("Authorization")
	q.event.SetIdentityKnown(len(credentials) == 0)
	StripUntrusted(r.Header)

	// Overload: past maxInFlight requests, refuse before any token check or
	// body read, so excess load costs as little as possible.
	if h.inFlight.Add(1) > h.maxInFlight {
		h.inFlight.Add(-1)
		w.Header().Set("Retry-After", "1")
		q.reject(audit.StageIngress, http.StatusServiceUnavailable, "overloaded")
		return
	}
	defer h.inFlight.Add(-1)

	// Ingress: only origin-form targets, no tunnelling, bounded declared size.
	// A protocol upgrade would turn an admitted request into a raw stream the
	// policy never sees. The proxy removes every header named in Connection,
	// so naming a gateway header there would strip it after it is set here.
	if !strings.HasPrefix(r.RequestURI, "/") ||
		r.Method == http.MethodConnect ||
		r.Header.Get("Upgrade") != "" ||
		slices.ContainsFunc(connectionNames(r.Header), compile.IsGatewayHeader) {
		q.reject(audit.StageIngress, http.StatusBadRequest, "bad_request")
		return
	}
	if r.ContentLength > h.maxBodyBytes {
		q.reject(audit.StageIngress, http.StatusRequestEntityTooLarge, "payload_too_large")
		return
	}
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
	if g.Expired(compile.TrustedNow()) {
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
	t, rule := g.Match(path, r.Method, inbound)
	if t == nil {
		q.reject(audit.StageRoute, http.StatusNotFound, "not_found")
		return
	}
	if rule == nil {
		w.Header().Set("Allow", t.Allow())
		q.reject(audit.StageRoute, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	q.event.Operation, q.event.API, q.event.Upstream = rule.Operation(), rule.API(), rule.Upstream()
	// From here every answer, refusals included, carries the API's browser
	// access and response headers.
	q.w = newAPIWriter(w, rule, r)
	w = q.w
	if !rule.AddressAllowed(q.event.ClientAddress) {
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
		roles, q.event.IgnoredRoles, reason = g.Authorise(verified.roles, rule)
		q.event.Roles = roles
		blocked := h.authority.Blocked()
		if blocked == nil {
			q.reject(audit.StageRBAC, http.StatusServiceUnavailable, "gateway_unavailable")
			return
		}
		if _, found := (*blocked)[q.event.Subject]; found {
			q.event.Reason = "account_blocked"
			q.reject(audit.StageRBAC, http.StatusForbidden, "account_blocked")
			return
		}

		if reason != "" {
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

	document, refused := readBody(r, rule.Body(), h.maxBodyBytes)
	if refused != nil {
		q.event.Reason = refused.reason
		q.reject(audit.StageBody, refused.status, refused.code)
		return
	}
	q.bodyPending = false
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

	// Admission requires a durable audit record before anything is forwarded.
	q.event.Kind, q.event.Stage, q.event.Decision = "request.admitted", audit.StageNames[audit.StageAudit], "admit"
	ctx, cancel := context.WithTimeout(r.Context(), h.auditTimeout)
	err := q.audit.Commit(ctx, q.event)
	cancel()
	if err != nil {
		q.reject(audit.StageAudit, http.StatusServiceUnavailable, "gateway_unavailable")
		return
	}
	q.pass(audit.StageAudit)

	r.Header.Set("X-Request-Id", q.event.RequestID)
	r.Header.Set("X-Gateway-Generation", g.ID)
	if !rule.Public() {
		// The upstream can rely on these for its own object-level rules: client
		// copies were removed at ingress.
		r.Header.Set("X-Gateway-Subject", q.event.Subject)
		r.Header.Set("X-Gateway-Roles", strings.Join(roles, ","))
	}
	r = r.WithContext(forward.Bind(r.Context(), destination))
	q.pass(audit.StageBind)

	recorder := &statusRecorder{ResponseWriter: w}
	finished := false
	defer func() {
		if !finished {
			// The forwarder aborts a response it cannot complete, such as a
			// truncated upstream body, by panicking with http.ErrAbortHandler
			// after the status was sent. The outcome is recorded here; the
			// panic is not recovered, so the server still closes the
			// connection and the client sees the response is incomplete.
			q.forwarded(recorder.status, "upstream_failure", "upstream_incomplete")
		}
	}()
	forwardErr := h.forward(recorder, r)
	finished = true
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
