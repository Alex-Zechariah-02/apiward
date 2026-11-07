//go:build faultinject

// Test routes for fault-injection builds.

package gateway

import (
	"net/http"

	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// registerTestRoutes adds the test publication hook: a whole-policy
// publication for regression tests of the publisher. Production binaries have
// no such route, because whole-policy activation belongs to the confirmed
// activation lifecycle. The hook still needs an administrator session with
// manage_policy, the admin origin and the CSRF token.
func registerTestRoutes(s *adminAPI, mux *http.ServeMux) {
	s.route(mux, "POST /test/publish", store.PermManagePolicy, func(w http.ResponseWriter, r *http.Request, who caller) {
		var change Change
		if !decodeBody(w, r, policy.MaxPolicyBytes, &change) {
			return
		}
		outcome, status := s.control.Publish(r.Context(), who.admin.Name, change)
		pipeline.WriteJSON(w, status, outcome)
	})
}
