// Override conflicts with candidates and each other.

package integration

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// At most one active override governs a control and target: a second one is
// refused naming the first, also when created concurrently, and the database
// refuses it too. Overrides of different targets coexist, including several
// controls of one operation and permits of different roles on it. Targets
// are policy identifiers, so another spelling is simply unknown.
func TestOverrideConflicts(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	p := e.ProtectedPolicy()
	p.Operations[0].Rate = gatewaytest.Rate(4, 60) // read-a
	gatewaytest.Seed(t, e.Database, p, gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	harness := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)

	first := e.MustOverride(harness, rateOverride(store.OverrideException, "read-a", 8, 600), `"r1"`, "conflict-first-001")
	refused := []struct {
		name    string
		request controller.OverrideRequest
		reason  string
	}{
		{"same target", rateOverride(store.OverrideException, "read-a", 8, 600), "OVERRIDE_CONFLICT"},
		{"same target, other action", rateOverride(store.OverrideContainment, "read-a", 1, 60), "OVERRIDE_CONFLICT"},
		{"same target, other count and expiry", rateOverride(store.OverrideException, "read-a", 100, 30), "OVERRIDE_CONFLICT"},
		{"case variant", rateOverride(store.OverrideException, "Read-a", 8, 600), "UNKNOWN_REFERENCE"},
		{"path instead of identifier", rateOverride(store.OverrideException, "/a/*", 8, 600), "INVALID_VALUE"},
		{"trailing space", rateOverride(store.OverrideException, "read-a ", 8, 600), "INVALID_VALUE"},
	}
	for i, r := range refused {
		code, outcome, body := e.CreateOverride(harness, r.request, `"r1"`, fmt.Sprintf("conflict-refused-%02d", i))
		if outcome.Reason != r.reason || (r.reason == "OVERRIDE_CONFLICT" && (code != http.StatusConflict || outcome.Override != first.Override)) {
			t.Errorf("%s: %d %s", r.name, code, body)
		}
	}

	// Independent targets on the same operations coexist.
	independent := []controller.OverrideRequest{
		permitOverride(store.OverrideContainment, "READER", "read-a", 600),
		permitOverride(store.OverrideContainment, "WRITER", "read-a", 600),
		gatewaytest.OperationContainment("read-a", 600),
		permitOverride(store.OverrideException, "READER", "write-a", 600),
	}
	var last controller.Outcome
	for i, r := range independent {
		last = e.MustOverride(harness, r, `"r1"`, fmt.Sprintf("conflict-independent-%d", i))
	}
	if !strings.HasPrefix(last.Generation, "r1+o1.") || len(activeOverrides(e, harness).Overrides) != 5 {
		t.Fatalf("independent overrides: %+v", last)
	}
	// With read-a contained, every read of /a is refused before
	// authentication and reaches nothing; bob's granted write works.
	e.ResetReceivers()
	if probe(e, "bob", http.MethodGet, "/a/x") != http.StatusForbidden || probe(e, "", http.MethodGet, "/a/x") != http.StatusForbidden ||
		probe(e, "bob", http.MethodPost, "/a/item") != http.StatusOK {
		t.Fatal("independent overrides not all enforced")
	}
	e.AssertReceipts(1, 0, 0)

	// Eight concurrent creations of one new target: exactly one succeeds.
	var wg sync.WaitGroup
	start := make(chan struct{})
	var mu sync.Mutex
	codes := map[int]int{}
	for i := range 8 {
		wg.Go(func() {
			<-start
			code, outcome, _ := e.CreateOverride(harness, gatewaytest.OperationContainment("read-b", 600), `"r1"`, fmt.Sprintf("conflict-race-%02d-xx", i))
			mu.Lock()
			codes[code]++
			if code == http.StatusConflict && outcome.Reason != "OVERRIDE_CONFLICT" {
				codes[-1]++
			}
			mu.Unlock()
		})
	}
	close(start)
	wg.Wait()
	if codes[http.StatusCreated] != 1 || codes[http.StatusConflict] != 7 || codes[-1] != 0 {
		t.Fatalf("concurrent creations answered %v", codes)
	}

	e.Stop()
	list := storedOverrides(t, e.Database)
	active := map[string]int{}
	for _, o := range list {
		if o.Status == store.OverrideActive {
			active[o.Target]++
		}
	}
	// The first, four independent ones and one race winner.
	if len(list) != 6 || len(active) != 6 {
		t.Fatalf("stored overrides %+v", list)
	}
	for target, n := range active {
		if n != 1 {
			t.Fatalf("%d active overrides of %s", n, target)
		}
	}
	// The database itself refuses a second active override of a target.
	db := gatewaytest.Inspect(t, e.Database)
	_, err := db.Exec(`INSERT INTO override (id, type, control, operation, count, target, base, created_at, expires_at, actor, creation, status)
		VALUES (100, 'containment', 'rate', 'read-a', 1, 'rate:read-a', 1, 1, 2, 'x', ?, 'active')`, list[0].Creation)
	if err == nil {
		t.Fatal("the database accepted a second active override of rate:read-a")
	}
	// It also refuses a target that does not match the override.
	_, err = db.Exec(`INSERT INTO override (id, type, control, operation, count, target, base, created_at, expires_at, actor, creation, status)
		VALUES (101, 'containment', 'rate', 'read-b', 1, 'rate:read-a', 1, 1, 2, 'x', ?, 'revoked')`, list[1].Creation)
	if err == nil {
		t.Fatal("the database accepted an override whose target names another operation")
	}
	db.Close()
}
