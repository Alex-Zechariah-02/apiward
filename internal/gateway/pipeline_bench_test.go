// BenchmarkPipeline measures requests through the whole data plane as the
// embedded gateway serves them over a loopback server: token verification,
// roles, rate limiting, body validation, the durable audit log on the real
// disk and forwarding to a loopback upstream. Each sub-benchmark is one kind
// of request of the load mix; allocations include the client and upstream,
// which stay the same between compared builds.

package gateway

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/issuertest"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// benchOrder is a valid checkout body of about 200 bytes.
const benchOrder = `{"merchant":"MER-001","items":[{"item":"ITM-001","quantity":1},{"item":"ITM-002","quantity":2}],` +
	`"address":{"line1":"12 Jalan Telawi 3","postcode":"59100","city":"Kuala Lumpur"},"payment":"cash"}`

// benchSchema is the checkout body's schema, in the subset the compiler takes.
const benchSchema = `{"type":"object","additionalProperties":false,"required":["merchant","items","payment"],"properties":{` +
	`"merchant":{"type":"string","minLength":1,"maxLength":16},` +
	`"items":{"type":"array","maxItems":20,"items":{"type":"object","additionalProperties":false,"required":["item","quantity"],` +
	`"properties":{"item":{"type":"string","maxLength":16},"quantity":{"type":"integer","minimum":1,"maximum":50}}}},` +
	`"address":{"type":"object","additionalProperties":true},"payment":{"type":"string","enum":["cash","wallet"]}}}`

// benchPolicy protects an orders API (signed-in reads and writes for
// CUSTOMER, rate-limited per account high enough never to refuse here) and
// serves a public inventory search, all from the upstream at dial.
func benchPolicy(dial string) policy.Policy {
	limit := gatewaytest.Rate(1_000_000, 3600)
	return policy.Policy{
		SchemaVersion: policy.SchemaVersion,
		Profile:       policy.ProfileCore,
		Upstreams:     []policy.Upstream{{ID: "shop", Dial: dial}},
		APIs:          []policy.API{{ID: "orders", Upstream: "shop"}, {ID: "inventory", Upstream: "shop"}},
		Roles:         []policy.Role{{ID: "CUSTOMER"}},
		Operations: []policy.Operation{
			{ID: "orders.mine", API: "orders", Method: "GET", Target: "/orders/mine", Access: "allow", Auth: "required", Rate: limit},
			{ID: "orders.create", API: "orders", Method: "POST", Target: "/orders", Access: "allow", Auth: "required", Rate: limit,
				Body: gatewaytest.JSONBody(4096, benchSchema)},
			{ID: "inventory.search", API: "inventory", Method: "GET", Target: "/inventory/search", Access: "allow", Auth: "none"},
		},
		Permits: []policy.Permit{{Role: "CUSTOMER", Operation: "orders.mine"}, {Role: "CUSTOMER", Operation: "orders.create"}},
	}
}

// startBench starts an embedded gateway on a seeded deployment in a new
// temporary directory, in front of upstream, and returns its loopback server.
func startBench(b *testing.B, upstream string) *httptest.Server {
	b.Helper()
	dir := b.TempDir()
	key, database := filepath.Join(dir, "issuer.pem"), filepath.Join(dir, "state.db")
	if err := os.WriteFile(key, gatewaytest.Issuer.PublicPEM(), 0o600); err != nil {
		b.Fatal(err)
	}
	gatewaytest.Seed(b, database, benchPolicy(upstream), gatewaytest.SeedOptions{})
	gatewaytest.WriteIdentityKey(b, filepath.Join(dir, gatewaytest.IdentityFile))
	settings, err := json.Marshal(map[string]any{
		"version": 1,
		"gateway": map[string]any{
			"database":       database,
			"audit_log":      filepath.Join(dir, "audit.log"),
			"admin_listen":   gatewaytest.FreeAddr(b),
			"metrics_listen": gatewaytest.FreeAddr(b),
			"jwt":            gatewaytest.TestTrust(issuertest.Name, issuertest.Audience, key),
		},
		"data": map[string]any{"listen": gatewaytest.FreeAddr(b)},
	})
	if err != nil {
		b.Fatal(err)
	}
	config := filepath.Join(dir, "gateway.json")
	if err := os.WriteFile(config, settings, 0o600); err != nil {
		b.Fatal(err)
	}
	loaded, err := LoadSettings(config)
	if err != nil {
		b.Fatal(err)
	}
	gw, err := OpenEmbedded(loaded, slog.New(slog.DiscardHandler))
	if err != nil {
		b.Fatal(err)
	}
	if err := gw.Start(); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { gw.Stop(context.Background()) })
	host := httptest.NewUnstartedServer(gw)
	gw.ServerSettings().Apply(host.Config)
	host.Start()
	b.Cleanup(host.Close)
	host.Client().Transport.(*http.Transport).MaxIdleConnsPerHost = 256
	return host
}

func BenchmarkPipeline(b *testing.B) {
	reply := []byte(`{"data":"` + strings.Repeat("x", 500) + `"}`)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write(reply)
	}))
	b.Cleanup(upstream.Close)
	host := startBench(b, upstream.Listener.Addr().String())
	token := "Bearer " + gatewaytest.Issuer.TokenFor(b, "cust-001")

	send := func(method, path, body string, signed bool) (int, error) {
		req, err := http.NewRequest(method, host.URL+path, strings.NewReader(body))
		if err != nil {
			return 0, err
		}
		if signed {
			req.Header.Set("Authorization", token)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := host.Client().Do(req)
		if err != nil {
			return 0, err
		}
		_, err = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode, err
	}
	cases := []struct {
		name, method, path, body string
		signed                   bool
		status                   int
	}{
		{"SignedRead", "GET", "/orders/mine", "", true, http.StatusOK},
		{"PublicRead", "GET", "/inventory/search?q=rice", "", false, http.StatusOK},
		{"SignedWrite", "POST", "/orders", benchOrder, true, http.StatusOK},
		{"Refusal", "GET", "/orders/mine", "", false, http.StatusUnauthorized},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if status, err := send(c.method, c.path, c.body, c.signed); err != nil || status != c.status {
					b.Fatalf("%s %s: %d %v", c.method, c.path, status, err)
				}
			}
		})
	}
	// Concurrent signed reads: admissions share audit syncs and contend for
	// the gateway's locks, as under load.
	b.Run("SignedReadParallel", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if status, err := send("GET", "/orders/mine", "", true); err != nil || status != http.StatusOK {
					b.Errorf("GET /orders/mine: %d %v", status, err)
					return
				}
			}
		})
	})
}
