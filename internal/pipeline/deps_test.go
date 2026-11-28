// Construction of the enforcement handler.

package pipeline

import (
	"math"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

type noAuthority struct{}

func (noAuthority) Current() *compile.Generation      { return nil }
func (noAuthority) Expired(*compile.Generation)       {}
func (noAuthority) Verifier() *Verifier               { return nil }
func (noAuthority) Blocked() *store.BlockedAccounts   { return nil }
func (noAuthority) AddressIndex() *store.AddressIndex { return nil }

// A ceiling of zero or less selects the default.
func TestNewSelectsDefaultCeiling(t *testing.T) {
	forward := func(http.ResponseWriter, *http.Request) error { return nil }
	for _, ceiling := range []int64{0, -1} {
		h, err := New(Deps{Authority: noAuthority{}, Audit: &audit.AuditLog{}, Observations: monitor.New(policy.DefaultWindow, policy.DefaultAPIs), Limiter: NewLimiter(policy.DefaultRateCounters), Clock: NewClock(), AuditTimeout: time.Second, Limits: Limits{MaxBodyBytes: ceiling}, Forward: forward})
		if err != nil || h.maxBodyBytes != DefaultMaxBody {
			t.Fatalf("ceiling %d: %v, %v", ceiling, h, err)
		}
	}
}

// A handler without a positive audit timeout is refused: it would refuse
// every admission.
func TestNewNeedsAuditTimeout(t *testing.T) {
	forward := func(http.ResponseWriter, *http.Request) error { return nil }
	for _, wait := range []time.Duration{0, -time.Second} {
		if _, err := New(Deps{Authority: noAuthority{}, Audit: &audit.AuditLog{}, Observations: monitor.New(policy.DefaultWindow, policy.DefaultAPIs), Limiter: NewLimiter(policy.DefaultRateCounters), Clock: NewClock(), AuditTimeout: wait, Forward: forward}); err == nil {
			t.Fatalf("audit timeout %v accepted", wait)
		}
	}
}

// IPv6 clients in one /64 share their address rate key; other /64s, and
// IPv4 addresses, keep their own. A prefix outside 48 to 128 is refused.
func TestIPv6RateKey(t *testing.T) {
	forward := func(http.ResponseWriter, *http.Request) error { return nil }
	deps := Deps{Authority: noAuthority{}, Audit: &audit.AuditLog{}, Observations: monitor.New(policy.DefaultWindow, policy.DefaultAPIs), Limiter: NewLimiter(policy.DefaultRateCounters), Clock: NewClock(), AuditTimeout: time.Second, Forward: forward}
	h, err := New(deps)
	if err != nil {
		t.Fatal(err)
	}
	key := func(s string) string { return h.rateAddress(netip.MustParseAddr(s), s) }
	if key("2001:db8::1") != key("2001:db8::ffff:1") || key("2001:db8::1") == key("2001:db8:0:1::1") || key("192.0.2.1") != "192.0.2.1" {
		t.Fatalf("keys: %s %s %s %s", key("2001:db8::1"), key("2001:db8::ffff:1"), key("2001:db8:0:1::1"), key("192.0.2.1"))
	}
	for _, prefix := range []int{47, 129} {
		deps.Limits = Limits{IPv6RatePrefix: prefix}
		if _, err := New(deps); err == nil {
			t.Fatalf("prefix %d accepted", prefix)
		}
	}
}

func TestDefaultPerUpstreamPreservesFraction(t *testing.T) {
	t.Parallel()
	for _, scenario := range []struct{ global, upstream int64 }{
		{1, 1}, {2, 1}, {3, 2}, {4, 3}, {5, 3},
	} {
		if got := DefaultPerUpstream(scenario.global); got != scenario.upstream {
			t.Errorf("global cap %d: got %d, want %d", scenario.global, got, scenario.upstream)
		}
	}
	for _, ceiling := range []int64{DefaultMaxInFlight, math.MaxInt64 / upstreamNumerator, math.MaxInt64/upstreamNumerator + 1, math.MaxInt64} {
		fraction := new(big.Int).Mul(big.NewInt(ceiling), big.NewInt(upstreamNumerator))
		fraction.Quo(fraction, big.NewInt(upstreamDenominator))
		if !fraction.IsInt64() {
			t.Fatal("the expected upstream share does not fit int64")
		}
		want := max(int64(1), fraction.Int64())
		if got := DefaultPerUpstream(ceiling); got != want {
			t.Errorf("global cap %d: got %d, want %d", ceiling, got, want)
		}
	}
}

func TestTrustedProxyConfigurationOwnsPrefixes(t *testing.T) {
	t.Parallel()
	proxies := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	s := setup{
		ops:    []policy.Operation{public(http.MethodGet, "/a/x")},
		limits: Limits{TrustedProxies: proxies},
		forward: func(w http.ResponseWriter, _ *http.Request) error {
			proxies[0] = netip.MustParsePrefix("198.51.100.0/24")
			w.WriteHeader(http.StatusOK)
			return nil
		},
	}
	request := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/a/x", nil)
		r.RemoteAddr = "198.51.100.2:1"
		r.Header.Set("X-Forwarded-For", "203.0.113.9")
		return r
	}
	rec, records, recovered := exchange(t, s, request(), request())
	if recovered != nil || rec.Code != http.StatusOK {
		t.Fatalf("request did not complete: status %d, panic %v", rec.Code, recovered)
	}
	if got := last(records)["client_address"]; got != "198.51.100.2" {
		t.Fatalf("caller mutation changed the trusted peer set: client %v, want 198.51.100.2", got)
	}
}
