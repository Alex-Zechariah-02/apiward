// Controller stop, the deadline timer and generations that expire without a
// stored deadline.

package controller

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
	"github.com/Alex-Zechariah-02/apiward/internal/storetest"
)

// Stop ends the deadline timer: a provisional base whose deadline passes
// after the controller stopped is not rolled back by it, and the next owner
// rolls it back at startup, once.
func TestStopEndsDeadlineTimer(t *testing.T) {
	e := newEnv(t)
	provisional := storetest.Policy(true)
	deadline := time.UnixMilli(time.Now().Add(1500 * time.Millisecond).UnixMilli())
	storetest.Seed(t, e.database, storetest.Policy(false), storetest.Options{Provisional: &provisional, Deadline: deadline})

	c := e.own(e.controllerConfig())
	if g := c.Current(); g == nil || g.Revision != 2 || !g.NotAfter.Equal(deadline) {
		t.Fatalf("published %+v, want provisional revision 2 until %s", g, deadline)
	}
	if err := c.Stop(); err != nil {
		t.Fatal(err)
	}
	if c.timer == nil || c.timer.Stop() {
		t.Fatal("the deadline timer was still armed after Stop")
	}
	time.Sleep(time.Until(deadline.Add(700 * time.Millisecond)))
	if n := storetest.Int(t, e.database, `SELECT coalesce(provisional, 0) FROM base`); n != 2 {
		t.Fatalf("provisional %d after the deadline passed while stopped, want 2", n)
	}
	if n := storetest.Int(t, e.database, `SELECT count(*) FROM transition WHERE id LIKE 'auto-rollback:%'`); n != 0 {
		t.Fatalf("%d rollbacks recorded by a stopped controller", n)
	}

	again := e.own(e.controllerConfig())
	if g := again.Current(); g == nil || g.Revision != 1 || !g.NotAfter.IsZero() {
		t.Fatalf("after restart %+v, want confirmed revision 1", g)
	}
	if err := again.Stop(); err != nil {
		t.Fatal(err)
	}
	if n := storetest.Int(t, e.database, `SELECT count(*) FROM transition WHERE id = 'auto-rollback:2' AND outcome = 'committed' AND audited_at IS NOT NULL`); n != 1 {
		t.Fatalf("%d audited rollbacks, want 1", n)
	}
}

// Stop releases the database and the audit log, also when it is called more
// than once.
func TestStopReleasesDeployment(t *testing.T) {
	e := newEnv(t)
	storetest.Seed(t, e.database, storetest.Policy(false), storetest.Options{})
	c := e.own(e.controllerConfig())
	for range 2 {
		if err := c.Stop(); err != nil {
			t.Fatal(err)
		}
	}
	if c.store.Ping() == nil {
		t.Fatal("the database is still open")
	}
	if !c.audit.Closed() {
		t.Fatal("the audit file is still open")
	}
}

// A published generation past its deadline with no stored deadline behind it,
// as a late timer would leave it, is withdrawn rather than served.
func TestExpiredGenerationWithoutDeadlineIsWithdrawn(t *testing.T) {
	e := newEnv(t)
	p := storetest.Policy(false)
	storetest.Seed(t, e.database, p, storetest.Options{})
	c := e.own(e.controllerConfig())
	stale, err := compile.Compile(p, 1, time.Now().Add(-time.Second), policy.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	c.current.Store(stale)
	c.Expired(stale)
	stop := time.Now().Add(5 * time.Second)
	for c.Current() != nil && time.Now().Before(stop) {
		time.Sleep(10 * time.Millisecond)
	}
	if c.Current() != nil {
		t.Fatal("the expired generation is still published")
	}
	if reason := c.State(); reason != "deadline_mismatch" {
		t.Fatalf("reason %q", reason)
	}
}

// State answers while a mutation holds the controller's mutex, so /readyz
// does not fail on a gateway that still serves.
func TestStateWithoutMutex(t *testing.T) {
	e := newEnv(t)
	storetest.Seed(t, e.database, storetest.Policy(false), storetest.Options{})
	c := e.own(e.controllerConfig())
	c.mu.Lock()
	defer c.mu.Unlock()
	read := make(chan string, 1)
	go func() { read <- c.State() }()
	select {
	case state := <-read:
		if state != "normal" {
			t.Fatalf("state %q", state)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("State waited for the controller's mutex")
	}
}

// A stopped controller refuses to open again, so it never re-reads its
// database or publishes; a mutation refused while it stops is recorded in
// the security log.
func TestStoppedControllerRefuses(t *testing.T) {
	e := newEnv(t)
	storetest.Seed(t, e.database, storetest.Policy(false), storetest.Options{})
	c := e.own(e.controllerConfig())
	c.BeginStop()
	refused := store.TransitionRecord{ID: "withdraw-during-stop", Kind: "candidate.withdraw", Actor: "admin"}
	if _, status := c.WithdrawCandidate(t.Context(), refused, 1); status != http.StatusServiceUnavailable {
		t.Fatalf("a mutation during the stop answered %d, want 503", status)
	}
	if err := c.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := c.Open(); err == nil || c.Current() != nil {
		t.Fatalf("Open after Stop: %v, generation %v", err, c.Current())
	}
	data, err := os.ReadFile(filepath.Join(e.dir, "audit.log"))
	if err != nil || !bytes.Contains(data, []byte(`"transition":"withdraw-during-stop","reason":"UNAVAILABLE"`)) {
		t.Fatalf("no record of the refused mutation (%v)", err)
	}
}
