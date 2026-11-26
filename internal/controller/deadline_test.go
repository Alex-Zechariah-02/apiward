// Settling overrides whose expiry times have passed: several together, and
// one while a provisional base is pending; and the authority a timeout
// rollback leaves.

package controller

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
	"github.com/Alex-Zechariah-02/apiward/internal/storetest"
)

// Overrides that expired together end in one settlement: each keeps its own
// transition, intent and outcome, every outcome names the one generation
// published for them all, and the authority settle returns holds none of them.
func TestSettleSeveralExpired(t *testing.T) {
	e := newEnv(t)
	storetest.Seed(t, e.database, storetest.Protected(), storetest.Options{})
	c := e.own(e.controllerConfig())
	requests := []OverrideRequest{
		permitOverride(store.OverrideException, "READER", "write-a", store.MinOverrideSeconds),
		permitOverride(store.OverrideContainment, "WRITER", "read-a", store.MinOverrideSeconds),
		operationContainment("read-b", store.MinOverrideSeconds),
	}
	for i, request := range requests {
		record := store.TransitionRecord{ID: fmt.Sprintf("create-%d", i), Kind: "tpo.create", Actor: "admin", Target: "override"}
		record.Expected.Int64, record.Expected.Valid, record.Digest = 1, true, record.ID
		if result, status := c.CreateOverride(context.Background(), record, request); status != http.StatusOK {
			t.Fatalf("override %d: %d %+v", i, status, result)
		}
	}
	if g := c.Current(); len(g.Overrides) != 3 {
		t.Fatalf("published overrides %v, want 3", g.Overrides)
	}
	// Without the timer, which would end each at its own expiry time, all
	// three are due at the one check below.
	c.mu.Lock()
	c.timer.Stop()
	c.mu.Unlock()
	time.Sleep(time.Duration(store.MinOverrideSeconds)*time.Second + 100*time.Millisecond)

	c.mu.Lock()
	a, settled := c.settle(context.Background(), compile.TrustedNow(), false)
	c.mu.Unlock()
	if !settled || len(a.Overrides) != 0 || a.Revision != 1 {
		t.Fatalf("settled %v: revision %d overrides %+v", settled, a.Revision, a.Overrides)
	}
	g := c.Current()
	if g == nil || len(g.Overrides) != 0 || !g.NotAfter.IsZero() {
		t.Fatalf("published %+v, want the base without overrides", g)
	}
	if err := c.Stop(); err != nil {
		t.Fatal(err)
	}
	if n := storetest.Int(t, e.database, `SELECT count(*) FROM transition WHERE id LIKE 'auto-expire:%' AND outcome = 'committed'`); n != 3 {
		t.Fatalf("%d expiries committed, want 3", n)
	}
	intents, generations := expiryRecords(t, filepath.Join(e.dir, "audit.log"))
	if intents != 3 || len(generations) != 1 || !generations[g.ID] {
		t.Fatalf("%d expiry intents, outcome generations %v; want 3 intents and only %s", intents, generations, g.ID)
	}
	// No provisional base was pending, so no expiry record names one.
	data, err := os.ReadFile(filepath.Join(e.dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		var r struct {
			Kind           string
			Provisional    int64
			RollbackTarget int64 `json:"rollback_target"`
		}
		if json.Unmarshal([]byte(line), &r) == nil && r.Kind == "tpo.expired" && (r.Provisional != 0 || r.RollbackTarget != 0) {
			t.Fatalf("expiry record names provisional %d and rollback target %d with no base pending", r.Provisional, r.RollbackTarget)
		}
	}
}

// An override that expires while a provisional base waits for confirmation
// names that base, its rollback target and its deadline in its expiry record.
func TestExpiryNamesPendingBase(t *testing.T) {
	e := newEnv(t)
	storetest.Seed(t, e.database, storetest.Protected(), storetest.Options{})
	c := e.own(e.controllerConfig())
	ctx := context.Background()
	record := func(id, kind, target string) store.TransitionRecord {
		r := store.TransitionRecord{ID: id, Kind: kind, Actor: "admin", Target: target}
		r.Expected.Int64, r.Expected.Valid, r.Digest = 1, true, id
		return r
	}
	if result, status := c.CreateOverride(ctx, record("create", "tpo.create", "override"), permitOverride(store.OverrideException, "READER", "write-a", store.MinOverrideSeconds)); status != http.StatusOK {
		t.Fatalf("override: %d %+v", status, result)
	}
	candidate := storetest.Protected()
	candidate.Permits = append(candidate.Permits, policy.Permit{Role: "WRITER", Operation: "read-b"})
	document, err := json.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	staged, status := c.StageCandidate(ctx, record("stage", "candidate.create", "candidate"), document)
	if status != http.StatusOK {
		t.Fatalf("candidate: %d %+v", status, staged)
	}
	stored, found, err := c.store.Candidate(ctx, staged.Candidate)
	if err != nil || !found {
		t.Fatalf("candidate %d: found %v, %v", staged.Candidate, found, err)
	}
	activated, status := c.Activate(ctx, record("activate", "cpa.activate", "candidate"), staged.Candidate, stored.Checksum, 600)
	if status != http.StatusOK {
		t.Fatalf("activation: %d %+v", status, activated)
	}
	c.mu.Lock()
	c.timer.Stop()
	c.mu.Unlock()
	time.Sleep(time.Duration(store.MinOverrideSeconds)*time.Second + 100*time.Millisecond)
	c.mu.Lock()
	_, settled := c.settle(ctx, compile.TrustedNow(), false)
	c.mu.Unlock()
	if !settled {
		t.Fatal("the expiry was not settled")
	}
	if err := c.Stop(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(e.dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		var r struct {
			Kind           string
			Provisional    int64
			RollbackTarget int64 `json:"rollback_target"`
			Deadline       string
		}
		if json.Unmarshal([]byte(line), &r) != nil || r.Kind != "tpo.expired" {
			continue
		}
		if r.Provisional != activated.Provisional || r.RollbackTarget != 1 || r.Deadline == "" {
			t.Fatalf("expiry record %+v, want provisional %d, rollback target 1 and a deadline", r, activated.Provisional)
		}
		return
	}
	t.Fatal("no expiry record")
}

// A provisional base whose deadline passed is rolled back, and the
// authority settle returns is the stored one after the rollback: no base
// pending and the rollback target confirmed.
func TestTimeoutReturnsStoredAuthority(t *testing.T) {
	e := newEnv(t)
	provisional := storetest.Policy(true)
	deadline := time.UnixMilli(time.Now().Add(time.Second).UnixMilli())
	storetest.Seed(t, e.database, storetest.Policy(false), storetest.Options{Provisional: &provisional, Deadline: deadline})
	c := e.own(e.controllerConfig())
	c.mu.Lock()
	c.timer.Stop()
	c.mu.Unlock()
	time.Sleep(time.Until(deadline.Add(200 * time.Millisecond)))
	c.mu.Lock()
	a, settled := c.settle(context.Background(), compile.DeadlineNow(), true)
	c.mu.Unlock()
	if !settled || a.Provisional != 0 || a.Confirmed != 1 {
		t.Fatalf("settled %v: provisional %d, confirmed %d; want no base pending and revision 1 confirmed", settled, a.Provisional, a.Confirmed)
	}
}

// expiryRecords counts the expiry intents in the audit log at path and
// collects the generations its expiry outcomes name.
func expiryRecords(t *testing.T, path string) (int, map[string]bool) {
	t.Helper()
	data, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer data.Close()
	intents, generations := 0, map[string]bool{}
	lines := bufio.NewScanner(data)
	lines.Buffer(nil, 1<<20)
	for lines.Scan() {
		var record struct{ Kind, Transition, Generation string }
		if json.Unmarshal(lines.Bytes(), &record) != nil {
			continue
		}
		switch {
		case record.Kind == "transition.intent" && strings.HasPrefix(record.Transition, "auto-expire:"):
			intents++
		case record.Kind == "tpo.expired":
			generations[record.Generation] = true
		}
	}
	if err := lines.Err(); err != nil {
		t.Fatal(err)
	}
	return intents, generations
}
