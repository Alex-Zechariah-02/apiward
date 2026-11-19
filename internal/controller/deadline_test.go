// Settling several overrides whose expiry times have passed together.

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
