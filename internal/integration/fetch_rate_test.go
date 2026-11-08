// Fetch rate limits keyed by client address on a running gateway.

package integration

import (
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

func TestFetchClientAddressQuota(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	p := e.Policy(e.A, false)
	p.Operations[0].Rate = &policy.RateRule{Algorithm: "sliding-window", Count: 2, WindowSeconds: 60, Key: "client_address"}
	gatewaytest.Seed(t, e.Database, p, gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	for _, tc := range []struct {
		address string
		status  int
	}{
		{"127.0.0.50", 200}, {"127.0.0.50", 200}, {"127.0.0.50", 429},
		{"127.0.0.51", 200},
	} {
		transport := &http.Transport{DialContext: (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(tc.address)}}).DialContext, DisableKeepAlives: true}
		client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
		r, err := http.NewRequest(http.MethodGet, "http://"+e.DataAddr+"/a/x", nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("X-Forwarded-For", audit.NewRequestID())
		r.Header.Set("Forwarded", "for=192.0.2.1")
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		transport.CloseIdleConnections()
		if err != nil || response.StatusCode != tc.status {
			t.Fatalf("peer %s: %d %s (%v), want %d", tc.address, response.StatusCode, body, err, tc.status)
		}
	}
	e.AssertReceipts(3, 0, 0)
}
