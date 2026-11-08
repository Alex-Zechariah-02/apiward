// Override helpers and request grammar.

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
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

func revokeOverride(e *gatewaytest.Env, s gatewaytest.AdminSession, id int64, key string) (int, controller.Outcome, string) {
	e.T.Helper()
	code, data, _ := e.As(s, http.MethodDelete, fmt.Sprintf("/admin/overrides/%d", id), "", "Idempotency-Key", key)
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

func activeOverrides(e *gatewaytest.Env, s gatewaytest.AdminSession) overridesView {
	e.T.Helper()
	code, body, _ := e.As(s, http.MethodGet, "/admin/overrides", "")
	if code != http.StatusOK {
		e.T.Fatalf("GET /admin/overrides: %d %s", code, body)
	}
	return fromJSON[overridesView](e.T, body)
}

// storedOverrides reads every override of a stopped gateway.
func storedOverrides(t *testing.T, path string) []store.Override {
	t.Helper()
	db := gatewaytest.Inspect(t, path)
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
func probe(e *gatewaytest.Env, subject, method, path string) int {
	e.T.Helper()
	var header []string
	if subject != "" {
		header = gatewaytest.Bearer(e.T, subject)
	}
	body, contentType := "", ""
	if method == http.MethodPost {
		body, contentType = `{"n":1}`, "application/json"
	}
	code, _ := e.Request(method, path, contentType, body, header...)
	return code
}
