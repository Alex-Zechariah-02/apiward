// Override helpers and request grammar.

package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// These tests cover temporary overrides: the request grammar and the
// resolver on their own, then creation, inspection, revocation, expiry and
// rate counters through the real gateway, where every enforcement claim is
// checked at the receivers.

func permitOverride(kind, role, operation string, seconds int64) controller.OverrideRequest {
	return controller.OverrideRequest{Type: kind, Control: store.ControlPermit, Operation: operation, Role: new(role), ExpiresInSeconds: seconds}
}

func rateOverride(kind, operation string, count, seconds int64) controller.OverrideRequest {
	return controller.OverrideRequest{Type: kind, Control: store.ControlRate, Operation: operation, Count: new(count), ExpiresInSeconds: seconds}
}

func operationContainment(operation string, seconds int64) controller.OverrideRequest {
	return controller.OverrideRequest{Type: store.OverrideContainment, Control: store.ControlOperation, Operation: operation, ExpiresInSeconds: seconds}
}

// createOverride asks for a temporary override; request may be an
// OverrideRequest or raw JSON.
func (e *env) createOverride(s adminSession, request any, ifMatch, key string) (int, controller.Outcome, string) {
	e.t.Helper()
	body, ok := request.(string)
	if !ok {
		body = string(mustJSON(request))
	}
	code, data, _ := e.as(s, http.MethodPost, "/admin/overrides", body, "If-Match", ifMatch, "Idempotency-Key", key)
	var outcome controller.Outcome
	json.Unmarshal([]byte(data), &outcome)
	return code, outcome, data
}

// mustOverride creates an override, failing the test unless it is created.
func (e *env) mustOverride(s adminSession, request controller.OverrideRequest, ifMatch, key string) controller.Outcome {
	e.t.Helper()
	code, outcome, body := e.createOverride(s, request, ifMatch, key)
	if code != http.StatusCreated || outcome.Outcome != "committed" || outcome.Override == 0 {
		e.t.Fatalf("creating override %+v: %d %s", request, code, body)
	}
	return outcome
}

func (e *env) revokeOverride(s adminSession, id int64, key string) (int, controller.Outcome, string) {
	e.t.Helper()
	code, data, _ := e.as(s, http.MethodDelete, fmt.Sprintf("/admin/overrides/%d", id), "", "Idempotency-Key", key)
	var outcome controller.Outcome
	json.Unmarshal([]byte(data), &outcome)
	return code, outcome, data
}

type overridesView struct {
	Revision            int64            `json:"revision"`
	Confirmed           int64            `json:"confirmed"`
	Provisional         int64            `json:"provisional"`
	Overrides           []store.Override `json:"overrides"`
	Generation          string           `json:"generation"`
	GenerationOverrides []int64          `json:"generation_overrides"`
}

func (e *env) activeOverrides(s adminSession) overridesView {
	e.t.Helper()
	code, body, _ := e.as(s, http.MethodGet, "/admin/overrides", "")
	if code != http.StatusOK {
		e.t.Fatalf("GET /admin/overrides: %d %s", code, body)
	}
	return fromJSON[overridesView](e.t, body)
}

// storedOverrides reads every override of a stopped gateway.
func storedOverrides(t *testing.T, path string) []store.Override {
	t.Helper()
	db := inspect(t, path)
	defer db.Close()
	s := store.Adopt(db)
	list, err := s.Overrides(t.Context(), `ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	return list
}

// probe sends one request as subject (or anonymously when subject is empty)
// and returns its status.
func (e *env) probe(subject, method, path string) int {
	e.t.Helper()
	var header []string
	if subject != "" {
		header = bearer(e.t, subject)
	}
	body, contentType := "", ""
	if method == http.MethodPost {
		body, contentType = `{"n":1}`, "application/json"
	}
	code, _ := e.request(method, path, contentType, body, header...)
	return code
}
