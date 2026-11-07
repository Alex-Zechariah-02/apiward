// Construction of the enforcement handler.

package pipeline

import (
	"net/http"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

type noAuthority struct{}

func (noAuthority) Current() *compile.Generation       { return nil }
func (noAuthority) Expired(*compile.Generation)        {}
func (noAuthority) Verifier() *Verifier                { return nil }
func (noAuthority) Blocked() *store.BlockedAccounts    { return nil }
func (noAuthority) Addresses() *store.BlockedAddresses { return nil }

// A ceiling of zero or less selects the default.
func TestNewSelectsDefaultCeiling(t *testing.T) {
	forward := func(http.ResponseWriter, *http.Request) error { return nil }
	for _, ceiling := range []int64{0, -1} {
		h, err := New(Deps{Authority: noAuthority{}, Audit: &audit.AuditLog{}, Observations: monitor.New(), Limiter: NewLimiter(), Clock: NewClock(), MaxBodyBytes: ceiling, Forward: forward})
		if err != nil || h.maxBodyBytes != DefaultMaxBody {
			t.Fatalf("ceiling %d: %v, %v", ceiling, h, err)
		}
	}
}
