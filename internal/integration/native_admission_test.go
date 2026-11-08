// Native control enforcement and admission status.

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/issuertest"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// The five controls run in the native process as in the shared enforcement
// pipeline: authentication against the one trusted key, roles held by the
// policy, the rate limit, body and header schemas under the body ceiling, the
// validated-header agreement and the gateway's own identity headers. Every
// refusal is recorded at its stage and reaches no upstream.
func TestNativeGatewayEnforcesControls(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	p := e.ProtectedPolicy()
	for i := range p.Operations {
		switch p.Operations[i].ID {
		case "write-a":
			p.Operations[i].Body = gatewaytest.JSONBody(64, `{"type":"object","additionalProperties":false,"required":["n"],"properties":{"n":{"type":"integer"}}}`)
			p.Operations[i].Headers = json.RawMessage(`{"type":"object","additionalProperties":true,"required":["X-Mode"],"properties":{"X-Mode":{"type":"string","enum":["fast","safe"]}}}`)
		case "read-b":
			p.Operations[i].Rate = &policy.RateRule{Algorithm: "sliding-window", Count: 2, WindowSeconds: 60, Key: "subject"}
		}
	}
	gatewaytest.Seed(t, e.Database, p, gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	generation := e.Status().Generation

	token := func(claims map[string]any) []string {
		return []string{"Authorization", "Bearer " + gatewaytest.Issuer.Token(t, claims)}
	}
	expired, foreign, claimed := issuertest.ValidClaims("alice"), issuertest.ValidClaims("alice"), issuertest.ValidClaims("mallory")
	expired["exp"] = time.Now().Add(-time.Minute).Unix()
	foreign["iss"] = "another-issuer"
	claimed["roles"] = []string{"UNKNOWN"}
	altered := gatewaytest.Issuer.TokenFor(t, "alice")
	altered = altered[:len(altered)-6] + "AAAAAA"
	asAlice := append(gatewaytest.Bearer(t, "alice"), "X-Mode", "fast")

	refusals := []struct {
		name, method, path, contentType, body string
		header                                []string
		status                                int
		stage                                 string
	}{
		{"no token", http.MethodGet, "/a/x", "", "", nil, http.StatusUnauthorized, "JWT"},
		{"expired token", http.MethodGet, "/a/x", "", "", token(expired), http.StatusUnauthorized, "JWT"},
		{"token of another issuer", http.MethodGet, "/a/x", "", "", token(foreign), http.StatusUnauthorized, "JWT"},
		{"altered signature", http.MethodGet, "/a/x", "", "", []string{"Authorization", "Bearer " + altered}, http.StatusUnauthorized, "JWT"},
		{"unknown role claimed in the verified token", http.MethodGet, "/a/x", "", "", token(claimed), http.StatusForbidden, "RBAC"},
		{"role without the permit", http.MethodPost, "/a/item", "application/json", `{"n":1}`, append(gatewaytest.Bearer(t, "bob"), "X-Mode", "fast"), http.StatusForbidden, "RBAC"},
		{"body outside its schema", http.MethodPost, "/a/item", "application/json", `{"n":"one"}`, asAlice, http.StatusBadRequest, "VALIDATION"},
		{"missing validated header", http.MethodPost, "/a/item", "application/json", `{"n":1}`, gatewaytest.Bearer(t, "alice"), http.StatusBadRequest, "VALIDATION"},
		{"validated header named in Connection", http.MethodPost, "/a/item", "application/json", `{"n":1}`, append(asAlice, "Connection", "X-Mode"), http.StatusBadRequest, "VALIDATION"},
		{"body above the operation ceiling", http.MethodPost, "/a/item", "application/json", `{"n":` + strings.Repeat("1", 64) + `}`, asAlice, http.StatusRequestEntityTooLarge, "BODY"},
		{"another media type", http.MethodPost, "/a/item", "text/plain", `{"n":1}`, asAlice, http.StatusUnsupportedMediaType, "BODY"},
		{"operation outside the policy", http.MethodGet, "/c/x", "", "", gatewaytest.Bearer(t, "alice"), http.StatusNotFound, "ROUTE"},
		{"denied operation", http.MethodGet, "/d", "", "", nil, http.StatusForbidden, "ACCESS"},
	}
	for _, r := range refusals {
		resp, body := e.Exchange(r.method, r.path, r.contentType, r.body, r.header...)
		_, id := gatewaytest.RequestID(resp, body)
		events := e.RequestEvents(id, 1)
		if resp.StatusCode != r.status || len(events) != 1 || events[0]["stage"] != r.stage || events[0]["kind"] != "request.rejected" {
			t.Errorf("%s: %d %s, events %v; want %d at %s", r.name, resp.StatusCode, body, events, r.status, r.stage)
		}
	}
	e.AssertReceipts(0, 0, 0)

	// Admitted: the upstream receives the gateway's identity headers, not the
	// client's, with the validated header and body unchanged and no
	// credential.
	forged := append(asAlice, "X-Gateway-Subject", "bob", "X-Gateway-Roles", "ADMIN")
	if code, body := e.Request(http.MethodPost, "/a/item", "application/json", `{"n":1}`, forged...); code != http.StatusOK || body != "A ok" {
		t.Fatalf("admitted write: %d %q", code, body)
	}
	r := e.A.Receipts()[0]
	if r.Headers.Get("X-Gateway-Subject") != "alice" || r.Headers.Get("X-Gateway-Roles") != "WRITER" || r.Headers.Get("X-Mode") != "fast" ||
		r.Authorization || r.Body != `{"n":1}` || r.Generation != generation {
		t.Fatalf("upstream received %+v", r)
	}
	statuses := []int{}
	for range 3 {
		code, _ := e.Get("/b/x", gatewaytest.Bearer(t, "bob")...)
		statuses = append(statuses, code)
	}
	if fmt.Sprint(statuses) != "[200 200 429]" {
		t.Fatalf("rate limit 2 per minute: %v", statuses)
	}
	e.AssertReceipts(1, 2, 0)
	raw, _ := os.ReadFile(e.AuditLog)
	if strings.Contains(string(raw), "Bearer") || strings.Contains(string(raw), altered[:40]) {
		t.Fatal("the audit log holds a credential")
	}
}

// Listening is not admission. The startup output and the protected
// status say whether protected admission can run: not in bootstrap or
// recovery, without usable authority, with a failed audit log or a
// generation past its deadline, and not once the stop has begun. A confirmed
// deny-all base is ready, though it admits nothing. The unauthenticated
// health check stays a liveness and mode report.
func TestNativeAdmissionStatus(t *testing.T) {
	// unavailableAtCapture checks that a protected request is refused before
	// any policy decision and reaches no upstream.
	unavailableAtCapture := func(e *gatewaytest.Env) {
		e.T.Helper()
		resp, body := e.Exchange(http.MethodGet, "/a/x", "", "")
		_, id := gatewaytest.RequestID(resp, body)
		if events := e.RequestEvents(id, 1); resp.StatusCode != http.StatusServiceUnavailable || len(events) != 1 || events[0]["stage"] != "CAPTURE" {
			e.T.Fatalf("request: %d %s, events %v", resp.StatusCode, body, events)
		}
		e.AssertReceipts(0, 0, 0)
	}

	t.Run("bootstrap", func(t *testing.T) {
		e := gatewaytest.NewEnv(t)
		if out, code := e.RunOperator(gatewaytest.Binaries.Plain, nil, "install", "--admin", "root"); code != 0 {
			t.Fatalf("install: %d %s", code, out)
		}
		e.Start(gatewaytest.Binaries.Plain)
		e.WaitOutput(`"msg":"protected admission","admission":"bootstrap_locked"`)
		if health := e.Health(); health != store.ModeBootstrap {
			t.Fatalf("health %q", health)
		}
		unavailableAtCapture(e)
	})

	t.Run("recovery required", func(t *testing.T) {
		e := gatewaytest.NewEnv(t)
		gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{Mode: store.ModeRecovery})
		e.Start(gatewaytest.Binaries.Plain)
		e.WaitOutput(`"admission":"recovery_required"`)
		if s := e.Status(); s.Admission != store.ModeRecovery || s.State != store.ModeRecovery || e.Health() != store.ModeRecovery {
			t.Fatalf("status %+v", s)
		}
		unavailableAtCapture(e)
	})

	for _, tc := range []struct {
		name    string
		prepare func(e *gatewaytest.Env)
		reason  string
	}{
		{"missing database", func(e *gatewaytest.Env) {}, "missing or empty"},
		{"earlier schema version", func(e *gatewaytest.Env) {
			gatewaytest.Seed(e.T, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{Version: store.DatabaseVersion - 1})
		}, "run its migrate command"},
		{"stored revision altered", func(e *gatewaytest.Env) {
			gatewaytest.Seed(e.T, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
			db := gatewaytest.Inspect(e.T, e.Database)
			if _, err := db.Exec(`UPDATE revision SET document = ? WHERE id = 1`, []byte(`{}`)); err != nil {
				e.T.Fatal(err)
			}
			db.Close()
		}, "checksum mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := gatewaytest.NewEnv(t)
			tc.prepare(e)
			e.Start(gatewaytest.Binaries.Plain)
			e.WaitOutput(`"msg":"protected admission","admission":"unavailable"`)
			if health := e.Health(); health != "unavailable" {
				t.Fatalf("health %q", health)
			}
			if reason := e.UnavailableReason(); !strings.Contains(reason, tc.reason) {
				t.Fatalf("recorded reason %q, want %q", reason, tc.reason)
			}
			unavailableAtCapture(e)
		})
	}

	t.Run("confirmed deny-all base", func(t *testing.T) {
		e := gatewaytest.NewEnv(t)
		gatewaytest.Seed(t, e.Database, denyAllPolicy(e), gatewaytest.SeedOptions{})
		e.Start(gatewaytest.Binaries.Plain)
		if s := e.Status(); s.Admission != "ready" {
			t.Fatalf("status %+v", s)
		}
		for path, want := range map[string]int{"/a/x": http.StatusForbidden, "/b/x": http.StatusForbidden, "/zzz": http.StatusNotFound} {
			if code, _ := e.Get(path); code != want {
				t.Errorf("%s: %d, want %d", path, code, want)
			}
		}
		e.AssertReceipts(0, 0, 0)
	})

	t.Run("audit log failed while serving", func(t *testing.T) {
		e := gatewaytest.NewEnv(t)
		gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
		e.Start(gatewaytest.Binaries.Fault, "GATEWAY_FAULT=audit-fail-outcome")
		if s := e.Status(); s.Admission != "ready" {
			t.Fatalf("before the failure %+v", s)
		}
		if code, _ := e.Get("/a/x"); code != http.StatusOK {
			t.Fatalf("first request: %d", code)
		}
		gatewaytest.WaitFor(t, time.Now().Add(10*time.Second), "the audit failure", func() bool { return e.Status().AuditFailed })
		if s := e.Status(); s.Admission != "audit_failed" || s.State != store.ModeNormal || e.Health() != store.ModeNormal {
			t.Fatalf("after the failure %+v, health %q", s, e.Health())
		}
		if code, _ := e.Get("/a/x"); code != http.StatusServiceUnavailable {
			t.Fatalf("request with the failed audit log: %d", code)
		}
		e.AssertReceipts(1, 0, 0)
	})

	t.Run("generation past its deadline", func(t *testing.T) {
		e := gatewaytest.NewEnv(t)
		provisional := e.Policy(e.A, true)
		deadline := time.UnixMilli(time.Now().Add(1500 * time.Millisecond).UnixMilli())
		gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{Provisional: &provisional, Deadline: deadline})
		e.Start(gatewaytest.Binaries.Fault, "GATEWAY_FAULT=no-deadline-timer")
		if s := e.Status(); s.Admission != "ready" || !s.NotAfter.Equal(deadline) {
			t.Fatalf("provisional %+v", s)
		}
		time.Sleep(time.Until(deadline.Add(200 * time.Millisecond)))
		if s := e.Status(); s.Admission != "generation_expired" || s.Provisional != 2 {
			t.Fatalf("past the deadline %+v", s)
		}
		unavailableAtCapture(e)
		// The refused request ends the provisional base; the restored one is
		// ready.
		gatewaytest.WaitFor(t, time.Now().Add(10*time.Second), "the rollback", func() bool { s := e.Status(); return s.Admission == "ready" && s.Revision == 1 })
		if code, _ := e.Get("/b/x"); code != http.StatusNotFound {
			t.Fatalf("operation of the rolled-back revision: %d", code)
		}
	})
}
