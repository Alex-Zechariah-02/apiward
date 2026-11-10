//go:build faultinject

// Test routes for fault-injection builds.

package admin

import (
	"net/http"

	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// registerTestRoutes adds the test publication hook: a whole-policy
// publication for regression tests of the publisher. Production binaries have
// no such route, because whole-policy activation belongs to the confirmed
// activation lifecycle. The hook still needs an administrator session with
// manage_policy, the admin origin and the CSRF token.
func registerTestRoutes(s *Server, mux *http.ServeMux) {
	s.route(mux, "POST /test/publish", store.PermManagePolicy, func(w http.ResponseWriter, r *http.Request, who caller) {
		var change controller.Change
		if !decodeBody(w, r, int64(s.config.Limits.PolicyBytes), &change) {
			return
		}
		outcome, status := s.control.Publish(r.Context(), who.admin.Name, change)
		pipeline.WriteJSON(w, status, outcome)
	})
}
