// Fetch response references: each response correlated with its audit record
// and upstream receipt.

package integration

import (
	"net/http"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

// A reference must correlate the response with both audit and upstream receipt,
// even when either the client or an upstream tries to supply its own reference.
func TestFetchResponseReferences(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
	e.A.Handle = func(w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("X-Request-Id", "upstream-forged")
		w.WriteHeader(http.StatusCreated)
		return true
	}
	e.Start(gatewaytest.Binaries.Plain)
	for _, tc := range []struct {
		method, target string
		status         int
	}{
		{http.MethodGet, "/a/x", 201},
		{http.MethodGet, "/d", 403},
		{http.MethodGet, "/unknown", 404},
		{http.MethodDelete, "/a/x", 405},
		{http.MethodGet, "/a/%2f", 400},
	} {
		resp, body := e.Exchange(tc.method, tc.target, "", "", "X-Request-Id", "client-forged", "X-Gateway-Subject", "root")
		if resp.StatusCode != tc.status {
			t.Fatalf("%s %s: %d %s", tc.method, tc.target, resp.StatusCode, body)
		}
		id := resp.Header.Get("X-Request-Id")
		if len(id) != 32 {
			t.Fatalf("%s has no gateway reference: %q", tc.target, id)
		}
		if tc.status == http.StatusCreated {
			receipts := e.A.Receipts()
			if len(receipts) != 1 || receipts[0].RequestID != id || receipts[0].Headers.Get("X-Gateway-Subject") != "" {
				t.Fatalf("response reference disagrees with trusted receipt: %+v", receipts)
			}
		} else if _, bodyID := gatewaytest.RequestID(resp, body); bodyID != id {
			t.Fatalf("response/body references disagree: %q vs %q", id, bodyID)
		}
		if events := e.RequestEvents(id, 1); len(events) == 0 {
			t.Fatalf("reference %s cannot be found in audit", id)
		}
	}
	e.AssertReceipts(1, 0, 0)
	e.A.Server.Close()
	resp, body := e.Exchange(http.MethodGet, "/a/x", "", "")
	if resp.StatusCode != http.StatusBadGateway || len(resp.Header.Get("X-Request-Id")) != 32 {
		t.Fatalf("forwarding failure lost its reference: %d %s headers %v", resp.StatusCode, body, resp.Header)
	}
}
