// Policy changes through the Admin API: staging a candidate, confirmed
// activation and its rollback, and temporary overrides.

package gatewaytest

import (
	"encoding/json"
	"net/http"
	"slices"

	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// Activate asks for a staged candidate to become the provisional base.
func (e *Env) Activate(s AdminSession, c store.CandidateRecord, seconds int64, ifMatch, key string) (int, controller.Outcome, string) {
	e.T.Helper()
	body := string(MustJSON(map[string]any{"candidate": c.ID, "checksum": c.Checksum, "confirm_within_seconds": seconds}))
	code, data, _ := e.As(s, http.MethodPost, "/admin/provisional", body, "If-Match", ifMatch, "Idempotency-Key", key)
	var outcome controller.Outcome
	json.Unmarshal([]byte(data), &outcome)
	return code, outcome, data
}

// Resolve confirms ("confirm") or rolls back ("rollback") a provisional
// revision.
func (e *Env) Resolve(s AdminSession, action string, revision int64, ifMatch, key string) (int, controller.Outcome, string) {
	e.T.Helper()
	body := string(MustJSON(map[string]any{"revision": revision}))
	code, data, _ := e.As(s, http.MethodPost, "/admin/provisional/"+action, body, "If-Match", ifMatch, "Idempotency-Key", key)
	var outcome controller.Outcome
	json.Unmarshal([]byte(data), &outcome)
	return code, outcome, data
}

// ProvisionalFrom stages policy against the confirmed revision parent and
// activates it, failing the test unless both succeed.
func (e *Env) ProvisionalFrom(s AdminSession, policy policy.Policy, parent, seconds int64, key string) (store.CandidateRecord, controller.Outcome) {
	e.T.Helper()
	code, staged, body := e.Stage(s, policy, RevisionTag(parent), "stage-"+key)
	if code != http.StatusCreated {
		e.T.Fatalf("staging: %d %s", code, body)
	}
	code, outcome, body := e.Activate(s, staged.Candidate.CandidateRecord, seconds, RevisionTag(parent), "activate-"+key)
	if code != http.StatusOK {
		e.T.Fatalf("activation: %d %s", code, body)
	}
	return staged.Candidate.CandidateRecord, outcome
}

// CpaCandidate differs from ProtectedPolicy(alice, bob) in three ways: bob
// (READER) loses GET /b/* and gains POST /a/item, and API a moves from
// upstream A to upstream C.
func (e *Env) CpaCandidate() policy.Policy {
	p := e.ProtectedPolicy()
	p.Upstreams = append(p.Upstreams, policy.Upstream{ID: "C", Dial: e.C.Addr})
	p.APIs[0].Upstream = "C"
	p.Permits = slices.DeleteFunc(p.Permits, func(permit policy.Permit) bool { return permit == policy.Permit{Role: "READER", Operation: "read-b"} })
	p.Permits = append(p.Permits, policy.Permit{Role: "READER", Operation: "write-a"})
	return p
}

// StagedCandidate is the reply to a candidate submission.
type StagedCandidate struct {
	Receipt   controller.Outcome `json:"receipt"`
	Candidate struct {
		store.CandidateRecord
		Active *bool `json:"active"`
	} `json:"candidate"`
}

// Stage submits a complete policy candidate as an administrator.
func (e *Env) Stage(s AdminSession, policy any, ifMatch, key string) (int, StagedCandidate, string) {
	e.T.Helper()
	body := string(MustJSON(map[string]any{"policy": policy}))
	code, data, _ := e.As(s, http.MethodPost, "/admin/candidates", body, "If-Match", ifMatch, "Idempotency-Key", key)
	var reply StagedCandidate
	json.Unmarshal([]byte(data), &reply)
	return code, reply, data
}

// OperationContainment is a request to contain one operation for seconds.
func OperationContainment(operation string, seconds int64) controller.OverrideRequest {
	return controller.OverrideRequest{Type: store.OverrideContainment, Control: store.ControlOperation, Operation: operation, ExpiresInSeconds: seconds}
}

// CreateOverride asks for a temporary override; request may be an
// OverrideRequest or raw JSON.
func (e *Env) CreateOverride(s AdminSession, request any, ifMatch, key string) (int, controller.Outcome, string) {
	e.T.Helper()
	body, ok := request.(string)
	if !ok {
		body = string(MustJSON(request))
	}
	code, data, _ := e.As(s, http.MethodPost, "/admin/overrides", body, "If-Match", ifMatch, "Idempotency-Key", key)
	var outcome controller.Outcome
	json.Unmarshal([]byte(data), &outcome)
	return code, outcome, data
}

// MustOverride creates an override, failing the test unless it is created.
func (e *Env) MustOverride(s AdminSession, request controller.OverrideRequest, ifMatch, key string) controller.Outcome {
	e.T.Helper()
	code, outcome, body := e.CreateOverride(s, request, ifMatch, key)
	if code != http.StatusCreated || outcome.Outcome != "committed" || outcome.Override == 0 {
		e.T.Fatalf("creating override %+v: %d %s", request, code, body)
	}
	return outcome
}
