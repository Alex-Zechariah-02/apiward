// Fetch client identity headers discarded at ingress, and the separate
// network address under a port offset.

package gateway

import (
	"net/http/httptest"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
)

func TestFetchIngressDiscardsClientIdentityHeaders(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	_, handler, _ := serveEnforcement(e, e.Policy(e.A, true), pipeline.Limits{})
	for _, method := range []string{"CONNECT", "POST"} {
		request := httptest.NewRequest(method, "http://gateway/a/x", nil)
		request.RequestURI = "/a/x"
		if method == "POST" {
			request.ContentLength = pipeline.DefaultMaxBody + 1
		}
		request.Header.Set("X-Request-Id", "client-value")
		request.Header.Set("X-Gateway-Subject", "forged")
		request.Header.Set("X-Gateway-Extra", "forged")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != 400 && response.Code != 413 {
			t.Fatalf("ingress status: %d", response.Code)
		}
		for _, name := range []string{"X-Request-Id", "X-Gateway-Subject", "X-Gateway-Extra"} {
			if request.Header.Get(name) != "" {
				t.Errorf("%s retained %s", method, name)
			}
		}
	}
	e.AssertReceipts(0, 0, 0)
}

func TestFetchSeparateNetworkAddressRespectsOffset(t *testing.T) {
	t.Setenv("EAT_PORT_OFFSET", "1000")
	if got := gatewaytest.WSLDataAddress(t, "192.0.2.1"); got != "192.0.2.1:19443" {
		t.Fatalf("separate-network listener: %s", got)
	}
}
