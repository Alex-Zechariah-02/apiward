// The request views: the compact entry the window keeps for each request and
// the secret-free projection the Admin API serves, built only when read.

package monitor

import (
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// RequestView is the explicit, secret-free Admin API projection. Private audit
// envelopes and their future fields are never serialized to viewers.
type RequestView struct {
	RequestID     string    `json:"request_id"`
	Time          time.Time `json:"time"`
	Method        string    `json:"method"`
	Path          string    `json:"path"`
	Operation     *string   `json:"operation"`
	API           *string   `json:"api"`
	Subject       *string   `json:"subject"`
	Roles         []string  `json:"roles"`
	ClientAddress string    `json:"client_address"`
	Decision      string    `json:"decision"`
	Status        int       `json:"status"`
	Stage         string    `json:"stage"`
	Code          *string   `json:"code"`
	Generation    string    `json:"generation"`
	DurationMS    float64   `json:"duration_ms"`
	// Upstream names the upstream the request was bound to; ForwardedPath is
	// the path sent to it, only when the forward rule changed the path.
	Upstream      *string `json:"upstream"`
	ForwardedPath *string `json:"forwarded_path"`
	// Modules is present only in builds with modules other than the built-ins.
	Modules map[string]string `json:"modules,omitempty"`
	// Truncated says Path was cut to audit.MaxLoggedPath.
	Truncated bool `json:"path_truncated,omitempty"`
}

// The view decisions. Failed is the gateway's own error; UpstreamFailed a
// request whose upstream gave no complete answer.
const (
	Allowed        = "allowed"
	Refused        = "refused"
	Failed         = "failed"
	UpstreamFailed = "upstream_failed"
)

// Decisions are the view decisions a request list may be filtered by.
var Decisions = []string{Allowed, Refused, Failed, UpstreamFailed}

// keptPath is the longest path prefix an entry keeps: the displayed path's
// bound, or one byte beyond the longest target, which tells an exact match
// from a longer request (prefix matching needs no more).
const keptPath = max(audit.MaxLoggedPath, policy.MaxTargetLength+1)

// Entry is one request as the window keeps it: plain values, one allocation
// for its roles and one for its path, so recording builds no view. Fields
// hold the view's values; an empty string is a missing value.
type Entry struct {
	Time          time.Time
	DurationMS    float64
	RequestID     string
	Method        string
	Path          string // at most keptPath bytes
	Operation     string
	API           string
	Subject       string
	ClientAddress string
	Code          string
	Generation    string
	Upstream      string
	ForwardedPath string
	Decision      string // one of Decisions
	Stage         string
	Status        int
	// roles holds the verified roles first, then the roles the active policy
	// dropped; verified counts the first.
	roles     []string
	verified  int
	modules   map[string]string
	sequence  uint64
	truncated bool
	// identityKnown: evaluated authentication, or no credential was supplied;
	// canonical: canonicalization passed, so the path can be matched again.
	identityKnown bool
	canonical     bool
}

// newEntry keeps what the views need of a request's final event. Strings
// that may share a request's buffers (method, path) are copied, so a kept
// entry never holds a whole request line.
func newEntry(event audit.Event) Entry {
	e := Entry{
		Time: event.Time, DurationMS: event.DurationMS, RequestID: event.RequestID, Method: method(event.Method),
		Path: strings.Clone(event.Path[:min(len(event.Path), keptPath)]), Operation: event.Operation, API: event.API,
		Subject: event.Subject, ClientAddress: event.ClientAddress, Code: event.Error, Generation: event.Generation,
		Upstream: event.Upstream, Decision: decision(event.Decision), Stage: stage(event.Stage, event.Error), Status: event.Status,
		verified: len(event.Roles), modules: event.Modules, identityKnown: event.IdentityKnown(),
		canonical: event.Stages[audit.StageCanonical] == audit.StagePass,
		// The path is cut at the stored record's bound, so live and searched
		// views show the same text. A live event still holds the whole path;
		// one read back from the log was cut when written and carries the
		// record's flag.
		truncated: len(event.Path) > audit.MaxLoggedPath || (event.Truncated && len(event.Path) == audit.MaxLoggedPath),
	}
	if event.ForwardedPath != "" {
		e.ForwardedPath = strings.Clone(event.ForwardedPath[:min(len(event.ForwardedPath), audit.MaxLoggedPath)])
	}
	if n := len(event.Roles) + len(event.IgnoredRoles); n > 0 {
		e.roles = append(append(make([]string, 0, n), event.Roles...), event.IgnoredRoles...)
	}
	return e
}

// method returns the registered methods as constants, so an entry does not
// keep the request line a method was cut from; others are copied.
func method(text string) string {
	for _, known := range [...]string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions} {
		if text == known {
			return known
		}
	}
	return strings.Clone(text)
}

func decision(recorded string) string {
	switch recorded {
	case "forwarded", "allowed": // allowed: a CORS preflight the gateway answered
		return Allowed
	case "upstream_failure":
		return UpstreamFailed
	case "failed":
		return Failed
	default:
		return Refused
	}
}

func stage(recorded, code string) string {
	switch recorded {
	case "FORWARD", "BIND":
		return "forward"
	case "ACCESS":
		return "access"
	case "JWT":
		return "token"
	case "RBAC":
		if code == "account_blocked" {
			return "blocked"
		}
		return "permit"
	case "RATE":
		return "rate"
	case "BODY", "VALIDATION", "INGRESS", "CANONICAL":
		return "validation"
	case "AUDIT", "CAPTURE":
		return "record"
	default:
		return "route"
	}
}

// View is the secret-free view of a request's final audit event, shared
// by the live views and the security log search so both show the same fields.
func View(event audit.Event) RequestView {
	e := newEntry(event)
	return e.View()
}

// View projects the entry for a reader; the roles and path are copied, so
// the reader may keep the view.
func (e *Entry) View() RequestView {
	return RequestView{
		RequestID: e.RequestID, Time: e.Time, Method: e.Method, Path: e.Path[:min(len(e.Path), audit.MaxLoggedPath)],
		Operation: OptionalString(e.Operation), API: OptionalString(e.API), Subject: OptionalString(e.Subject),
		Roles: append([]string{}, e.roles[:e.verified]...), ClientAddress: e.ClientAddress, Decision: e.Decision,
		Status: e.Status, Stage: e.Stage, Code: OptionalString(e.Code), Generation: e.Generation, DurationMS: e.DurationMS,
		Upstream: OptionalString(e.Upstream), ForwardedPath: OptionalString(e.ForwardedPath), Modules: e.modules, Truncated: e.truncated,
	}
}

// Sequence is the request's position in the window, for paging.
func (e *Entry) Sequence() uint64 { return e.sequence }

func OptionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

// Observed is a retained request with what an impact preview replays.
type Observed struct {
	RequestView
	sequence      uint64
	assertedRoles []string // verified assertions, including roles dropped by the active policy, sorted
	identityKnown bool
	// routingPath is separate from the displayed path; empty means
	// canonicalization did not pass.
	routingPath string
}

func (e *Entry) observed() Observed {
	o := Observed{RequestView: e.View(), sequence: e.sequence, assertedRoles: slices.Sorted(slices.Values(e.roles)), identityKnown: e.identityKnown}
	if o.assertedRoles == nil {
		o.assertedRoles = []string{}
	}
	if e.canonical {
		o.routingPath = e.Path
	}
	return o
}

// Sequence is the request's position in the window, for paging.
func (e Observed) Sequence() uint64 { return e.sequence }

// ClaimedRoles are the verified role assertions, including roles the active
// policy dropped.
func (e Observed) ClaimedRoles() []string { return e.assertedRoles }

// Allowed reports whether an entry was admitted and answered: traffic
// failures are refusals from the caller's perspective, while request views
// keep the distinction between a refusal and a failure.
func (e *Entry) Allowed() bool {
	return e.Decision == Allowed && e.Status >= http.StatusOK
}
