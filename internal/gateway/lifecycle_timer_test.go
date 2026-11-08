// Controller stop against the deadline timer.

package gateway

import (
	"sync"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

// Stop racing the deadline timer leaves the rollback either complete,
// published and audited, or not started; never half done. The next owner
// always ends with the rollback applied exactly once.
func TestStopRacesDeadline(t *testing.T) {
	outcomes := map[string]int{}
	for round := range 10 {
		e := gatewaytest.NewEnv(t)
		provisional := e.Policy(e.A, true)
		deadline := time.UnixMilli(time.Now().Add(400 * time.Millisecond).UnixMilli())
		gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{Provisional: &provisional, Deadline: deadline})
		c, _ := own(e, controllerConfig(e))

		// Stop lands from a few milliseconds before to a few after the timer.
		time.Sleep(time.Until(deadline.Add(time.Duration(round-5) * time.Millisecond)))
		var wg sync.WaitGroup
		errs := make([]error, 3)
		for i := range errs {
			wg.Go(func() { errs[i] = c.Stop() })
		}
		wg.Wait()
		for _, err := range errs {
			if err != nil {
				t.Fatalf("round %d: Stop: %v", round, err)
			}
		}

		rolledBack := gatewaytest.QueryInt(t, e.Database, `SELECT count(*) FROM transition WHERE id = 'auto-rollback:2' AND outcome = 'committed'`)
		base := gatewaytest.QueryInt(t, e.Database, `SELECT coalesce(provisional, 0) FROM base`)
		unaudited := gatewaytest.QueryInt(t, e.Database, `SELECT count(*) FROM transition WHERE outcome = 'committed' AND audited_at IS NULL`)
		switch {
		case rolledBack == 1 && base == 0 && unaudited == 0:
			outcomes["rolled back before the stop"]++
		case rolledBack == 0 && base == 2:
			outcomes["stopped before the rollback"]++
		default:
			t.Fatalf("round %d: rollback %d, provisional %d, unaudited %d", round, rolledBack, base, unaudited)
		}

		again, _ := own(e, controllerConfig(e))
		if g := again.Current(); g == nil || g.Revision != 1 {
			t.Fatalf("round %d: after restart %+v", round, g)
		}
		if err := again.Stop(); err != nil {
			t.Fatal(err)
		}
		if n := gatewaytest.QueryInt(t, e.Database, `SELECT count(*) FROM transition WHERE id = 'auto-rollback:2'`); n != 1 {
			t.Fatalf("round %d: %d rollbacks", round, n)
		}
	}
	t.Logf("outcomes: %v", outcomes)
}
