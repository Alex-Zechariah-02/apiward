// The native gateway process: forwarding to the fixtures, its listeners and
// administration.

package integration

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/session"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// These tests run the gateway, cmd/apiward, as its own process with its
// configuration file. Every forwarding claim is checked at the receivers or
// fixtures themselves.

// The native process serves the three fixture APIs through the one
// enforcement pipeline and the native proxy: every catalogue step reaches
// exactly its fixture or none. Its startup output tells listening apart from
// protected admission.
func TestNativeGatewayServesFixtures(t *testing.T) {
	fixtures := gatewaytest.StartFixtures(t)
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, gatewaytest.FixturePolicy(fixtures), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)

	c := gatewaytest.LoadCatalogue(t)
	results := gatewaytest.RunScenarios(t, e, fixtures, c)
	if len(results) != len(c.Scenarios) {
		t.Fatalf("%d of %d steps ran", len(results), len(c.Scenarios))
	}
	ran := map[string]bool{}
	for _, r := range results {
		ran[r.Operation] = true
	}
	for _, op := range c.Operations {
		if !ran[op.ID] {
			t.Errorf("catalogue operation %s was never exercised", op.ID)
		}
	}
	e.AssertReceipts(0, 0, 0)

	s := e.Status()
	if s.Admission != "ready" || s.State != store.ModeNormal {
		t.Fatalf("status %+v, want normal and ready", s)
	}
	output := e.Output.String()
	for _, want := range []string{
		`"msg":"listening","data":"` + e.DataAddr + `","admin":"` + e.Admin + `"`,
		`"msg":"protected admission","admission":"ready","generation":"` + s.Generation + `"`,
	} {
		if !strings.Contains(output, want) {
			t.Errorf("startup output lacks %s:\n%s", want, output)
		}
	}
	if strings.Contains(strings.ToLower(output), "caddy") {
		t.Errorf("the native process mentions Caddy:\n%s", output)
	}
}

// The native process listens on exactly its data, admin and metrics addresses. It has
// no Caddy administration endpoint, the data plane reaches no Admin API
// route, and the Admin API keeps its Host, session, Origin, CSRF and
// permission checks and its authority over the served policy, including the
// confirmed-activation and temporary-override lifecycles.
func TestNativeListenersAndAdministration(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain, "CADDY_ADMIN="+gatewaytest.FreeAddr(t))
	before := e.Status()

	ports := gatewaytest.ListeningPorts(t, e.Process.Process.Pid)
	if len(ports) != 3 || !strings.Contains(" "+strings.Join(ports, " ")+" ", " "+gatewaytest.Port(e.DataAddr)+" ") ||
		!strings.Contains(" "+strings.Join(ports, " ")+" ", " "+gatewaytest.Port(e.Admin)+" ") || !strings.Contains(" "+strings.Join(ports, " ")+" ", " "+gatewaytest.Port(e.Metrics)+" ") {
		t.Fatalf("listening ports %v, want exactly data %s, admin %s and metrics %s", ports, gatewaytest.Port(e.DataAddr), gatewaytest.Port(e.Admin), gatewaytest.Port(e.Metrics))
	}
	if gatewaytest.Dialable("127.0.0.1:2019") {
		t.Fatal("Caddy's default admin address accepts connections")
	}
	for _, path := range nativeAdminPaths {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			if code, _ := e.Request(method, path, "application/json", `{}`); code != http.StatusNotFound {
				t.Errorf("%s %s on the data plane: %d", method, path, code)
			}
			if code, _ := e.AdminRaw(method, path, `{}`); code != http.StatusNotFound {
				t.Errorf("%s %s on the admin listener with a session: %d", method, path, code)
			}
		}
	}

	// No Admin API route exists on the data plane, with or without the
	// administrator's session and the admin origin.
	harness := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
	signedIn := harness.Headers(e)
	for _, probe := range []struct{ method, path string }{
		{http.MethodGet, "/admin/health"}, {http.MethodGet, "/admin/status"}, {http.MethodPost, "/admin/session"},
		{http.MethodPut, "/admin/blocked-accounts/mallory"}, {http.MethodPost, "/admin/candidates"}, {http.MethodGet, "/"},
	} {
		resp, body := e.Exchange(probe.method, probe.path, "application/json", `{}`, signedIn...)
		_, id := gatewaytest.RequestID(resp, body)
		if events := e.RequestEvents(id, 1); resp.StatusCode != http.StatusNotFound || len(events) != 1 || events[0]["stage"] != "ROUTE" {
			t.Errorf("%s %s on the data plane: %d %s, events %v", probe.method, probe.path, resp.StatusCode, body, events)
		}
	}

	// The Admin API's own boundary.
	membership := `{"reason":"test containment"}`
	put := func(header ...string) int {
		code, _, _ := e.AdminSend(http.MethodPut, "/admin/blocked-accounts/alice", membership,
			append([]string{"If-Match", `"r1"`, "Idempotency-Key", "native-admin-" + session.NewToken()[:8]}, header...)...)
		return code
	}
	cookie := []string{"Cookie", gatewaytest.AdminCookie + "=" + harness.Cookie}
	for name, tc := range map[string]struct {
		header []string
		want   int
	}{
		"no session":      {[]string{"Origin", e.AdminOrigin()}, http.StatusUnauthorized},
		"no CSRF token":   {append(cookie, "Origin", e.AdminOrigin()), http.StatusForbidden},
		"foreign origin":  {append(cookie, gatewaytest.AdminCSRF, harness.CSRF, "Origin", "http://"+e.DataAddr), http.StatusForbidden},
		"data-plane host": {append(signedIn, "Host", e.DataAddr), http.StatusBadRequest},
	} {
		if got := put(tc.header...); got != tc.want {
			t.Errorf("membership change with %s: %d, want %d", name, got, tc.want)
		}
	}
	if after := e.Status(); after.Generation != before.Generation {
		t.Fatalf("refused requests changed the generation to %s", after.Generation)
	}
	if code, _ := e.Get("/a/x", gatewaytest.Bearer(t, "alice")...); code != http.StatusOK {
		t.Fatalf("alice before containment: %d", code)
	}
	if got := put(signedIn...); got != http.StatusOK {
		t.Fatalf("authorised membership change: %d", got)
	}
	member := e.Status()
	if member.Revision != 1 || member.Generation != before.Generation {
		t.Fatalf("containment changed policy: %+v", member)
	}
	e.ResetReceivers()
	if code, _ := e.Get("/a/x", gatewaytest.Bearer(t, "alice")...); code != http.StatusForbidden {
		t.Fatalf("alice after containment: %d", code)
	}
	if code, body := unblockAccount(e, harness, "alice", "native-account-unblock"); code != 200 {
		t.Fatalf("unblock: %d %s", code, body)
	}
	if code, _ := e.Get("/a/x", gatewaytest.Bearer(t, "alice")...); code != 200 {
		t.Fatalf("unblocked account: %d", code)
	}
	if r := e.A.Receipts(); len(r) != 1 || r[0].Generation != member.Generation {
		t.Fatalf("receipts %+v, want one under %s", r, member.Generation)
	}

	// Confirmed activation: the candidate moves API a to C, and its
	// confirmation keeps it there.
	_, outcome := e.ProvisionalFrom(harness, e.CpaCandidate(), 1, 60, "native-cpa")
	if code, _, body := e.Resolve(harness, "confirm", outcome.Provisional, `"r1"`, "native-cpa-confirm"); code != http.StatusOK {
		t.Fatalf("confirmation: %d %s", code, body)
	}
	e.ResetReceivers()
	if code, body := e.Get("/a/x", gatewaytest.Bearer(t, "alice")...); code != http.StatusOK || body != "C ok" {
		t.Fatalf("alice after the confirmed activation: %d %q", code, body)
	}

	// A temporary containment override blocks the operation until it is
	// revoked.
	confirmed := e.Status().Confirmed
	created := e.MustOverride(harness, gatewaytest.OperationContainment("read-a", 60), gatewaytest.RevisionTag(confirmed), "native-tpo-create")
	if code, _ := e.Get("/a/x", gatewaytest.Bearer(t, "alice")...); code != http.StatusForbidden {
		t.Fatalf("alice under the containment override: %d", code)
	}
	if code, _, body := revokeOverride(e, harness, created.Override, "native-tpo-revoke"); code != http.StatusOK {
		t.Fatalf("revocation: %d %s", code, body)
	}
	if code, _ := e.Get("/a/x", gatewaytest.Bearer(t, "alice")...); code != http.StatusOK {
		t.Fatalf("alice after the revocation: %d", code)
	}
	e.AssertReceipts(0, 0, 2)
}
