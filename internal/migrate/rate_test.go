// The gateway's rate bounds measured on a live gateway: the guarantee every conforming sender gets and the ceiling no sender passes.

package migrate

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	"github.com/Alex-Zechariah-02/apiward/internal/probe"
)

// TestRateBounds checks the bounds the rate conversions rely on, for
// count N = 4 in a 1 s window: a sender of G = N/2 requests per window is
// never refused, and in any 1 s at most M = 2N-1 requests are admitted,
// against the burst that reaches the ceiling (N late in one window, then
// as many as are admitted in the next).
func TestRateBounds(t *testing.T) {
	const count, guarantee, ceiling = 4, 2, 7
	s, up := newSigner(t), startUpstream(t)
	p := base()
	p.Upstreams[0].Dial = up.addr
	p.Operations = []policy.Operation{{ID: "inventory.limited", API: "inventory", Method: http.MethodGet, Target: "/limited",
		Access: "allow", Auth: "none", Rate: &policy.RateRule{Algorithm: "sliding-window", Count: count, WindowSeconds: 1, Key: "client_address"}}}
	document, _ := json.Marshal(p)
	addr := startGateway(t, document, s)
	request := probe.Probe{Method: http.MethodGet, Path: "/limited", Identity: "none"}
	admitted := func() bool { return send(t, addr, request, nil, s).Status != http.StatusTooManyRequests }

	for i := range 4 {
		for range guarantee {
			if !admitted() {
				t.Fatalf("window %d: a sender of %d per window was refused", i, guarantee)
			}
		}
		time.Sleep(1050 * time.Millisecond) // just over a window: no window holds two pairs
	}

	time.Sleep(2 * time.Second) // both windows the limit reads are empty
	now := time.Now()
	// 0.9 s into a window: N are admitted there, and the next window adds
	// N-1 more within one second of them.
	time.Sleep(now.Truncate(time.Second).Add(1900 * time.Millisecond).Sub(now))
	var times []time.Time
	for end := time.Now().Add(1500 * time.Millisecond); time.Now().Before(end); { // into the next window's end
		at := time.Now()
		if admitted() {
			times = append(times, at)
		}
	}
	most := 0
	for i := range times {
		inWindow := 0
		for _, at := range times[i:] {
			if at.Sub(times[i]) < time.Second {
				inWindow++
			}
		}
		most = max(most, inWindow)
	}
	if most > ceiling || most < count {
		t.Errorf("at most %d admitted in one second, want %d to %d (times %v)", most, count, ceiling, times)
	}
	t.Logf("guarantee %d per window held; busiest second admitted %d (ceiling %d)", guarantee, most, ceiling)
}
