//go:build !faultinject

// Production builds register no test routes.

package admin

import "net/http"

// registerTestRoutes adds nothing: production binaries have no test hooks.
func registerTestRoutes(*Server, *http.ServeMux) {}
