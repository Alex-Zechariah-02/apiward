// The metrics listener end to end.

package integration

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

func TestFetchMetrics(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	e.Get("/a/customer-order-identifier", gatewaytest.Bearer(t, "alice")...)
	e.Get("/a/no-token")
	e.Get("/unknown-item-identifier")
	admin := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
	if code, body, _ := e.As(admin, "PUT", "/admin/blocked-accounts/secret-subject", `{"reason":"test"}`, "Idempotency-Key", "metrics-block-test"); code != 200 {
		t.Fatalf("block: %d %s", code, body)
	}
	response, err := http.Get("http://" + e.Metrics + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	if response.StatusCode != 200 || response.Header.Get("Content-Type") != "text/plain; version=0.0.4; charset=utf-8" {
		t.Fatalf("metrics: %d %v", response.StatusCode, response.Header)
	}
	for _, text := range []string{`gateway_requests_total{api="a",operation="read-a",decision="allowed",code=""} 1`, `gateway_request_duration_seconds_count{api="a"} 2`, "gateway_policy_revision 1", "gateway_temporary_rules_active 0", "gateway_blocked_accounts 1", "gateway_event_stream_dropped_total 0"} {
		if !strings.Contains(body, text) {
			t.Errorf("missing %s in %s", text, body)
		}
	}
	for _, secret := range []string{"alice", "secret-subject", "customer-order-identifier", "unknown-item-identifier", "127.0.0.1"} {
		if strings.Contains(body, secret) {
			t.Errorf("metric leaks %q", secret)
		}
	}
	for _, path := range []string{"/admin/status", "/", "/metrics/"} {
		response, err := http.Get("http://" + e.Metrics + path)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 404 {
			t.Errorf("metrics %s: %d", path, response.StatusCode)
		}
	}
	if code, _ := e.Get("/metrics"); code != 404 {
		t.Errorf("metrics exposed on data: %d", code)
	}
}
