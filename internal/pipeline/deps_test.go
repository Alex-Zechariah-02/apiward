// Construction of the enforcement handler.

package pipeline

import (
	"net/http"
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
