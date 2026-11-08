// An administrator disconnecting while a change waits for its outcome record.

package integration

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

// An administrator who disconnects while a committed change waits for its
// outcome record does not stop the gateway: the change finishes, its outcome
// is recorded and protected requests are still admitted.
func TestDisconnectDuringOutcomeKeepsAudit(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Fault, "GATEWAY_FAULT=cancel-before-outcome")
	admin := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)

	req, err := http.NewRequest(http.MethodPut, "http://"+e.Admin+"/admin/blocked-accounts/someone", strings.NewReader(`{"reason":"disconnect test"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	headers := append(admin.Headers(e), "Idempotency-Key", "disconnect-block")
	for i := 0; i+1 < len(headers); i += 2 {
		if headers[i] == "Host" {
			req.Host = headers[i+1]
			continue
		}
		req.Header.Set(headers[i], headers[i+1])
	}
	// The client gives up while the change waits for its outcome record.
	if resp, err := (&http.Client{Timeout: 500 * time.Millisecond}).Do(req); err == nil {
		resp.Body.Close()
		t.Fatalf("the change was answered (%d) before the client gave up", resp.StatusCode)
	}

	transition := "admin:" + gatewaytest.HarnessAdmin + ":disconnect-block"
	e.EventsWhen(func(events []map[string]any) bool {
		for _, ev := range events {
			if ev["kind"] == "account.block" && ev["transition"] == transition {
				return true
			}
		}
		return false
	})
	if s := e.Status(); s.AuditFailed {
		t.Fatal("a client disconnect failed the audit log")
	}
	if code, _ := e.Get("/a/x", "Authorization", "Bearer "+gatewaytest.Issuer.TokenFor(t, "alice")); code != http.StatusOK {
		t.Fatalf("protected request after the disconnect: %d", code)
	}
}
