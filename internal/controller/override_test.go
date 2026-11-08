// Override requests and applying overrides to generations.

package controller

import (
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
	"github.com/Alex-Zechariah-02/apiward/internal/testdb"
)

// Only the supported controls and actions can be requested, each with
// exactly the members it takes, well-formed identifiers and a bounded
// lifetime. JWT, validation, logging, upstream or route-allow changes have no
// representation and are refused by name.
func TestOverrideRequestGrammar(t *testing.T) {
	valid := []OverrideRequest{
		permitOverride(store.OverrideException, "READER", "write-a", 60),
		permitOverride(store.OverrideContainment, "WRITER", "read-a", 60),
		rateOverride(store.OverrideException, "read-a", 10, 60),
		rateOverride(store.OverrideContainment, "read-a", 1, 60),
		operationContainment("read-b", 60),
		permitOverride(store.OverrideException, "READER", "write-a", store.MinOverrideSeconds),
		permitOverride(store.OverrideException, "READER", "write-a", store.MaxOverrideSeconds),
	}
	wantTargets := []string{"permit:READER:write-a", "permit:WRITER:read-a", "rate:read-a", "rate:read-a", "operation:read-b",
		"permit:READER:write-a", "permit:READER:write-a"}
	for i, r := range valid {
		o, err := r.check()
		if err != nil || o.Target != wantTargets[i] || o.Status != "" {
			t.Errorf("valid request %d %+v: %+v %v", i, r, o, err)
		}
	}

	withRole := func(r OverrideRequest, role string) OverrideRequest { r.Role = new(role); return r }
	withCount := func(r OverrideRequest, count int64) OverrideRequest { r.Count = new(count); return r }
	withSeconds := func(r OverrideRequest, s int64) OverrideRequest { r.ExpiresInSeconds = s; return r }
	permit := permitOverride(store.OverrideException, "READER", "write-a", 60)
	refused := []struct {
		name    string
		request OverrideRequest
		want    string
	}{
		{"JWT control", OverrideRequest{Type: store.OverrideException, Control: "jwt", Operation: "read-a", ExpiresInSeconds: 60}, "UNSUPPORTED_CONTROL@control"},
		{"authentication control", OverrideRequest{Type: store.OverrideException, Control: "auth", Operation: "read-a", ExpiresInSeconds: 60}, "UNSUPPORTED_CONTROL@control"},
		{"validation control", OverrideRequest{Type: store.OverrideException, Control: "validation", Operation: "write-a", ExpiresInSeconds: 60}, "UNSUPPORTED_CONTROL@control"},
		{"schema control", OverrideRequest{Type: store.OverrideContainment, Control: "schema", Operation: "write-a", ExpiresInSeconds: 60}, "UNSUPPORTED_CONTROL@control"},
		{"logging control", OverrideRequest{Type: store.OverrideException, Control: "logging", Operation: "read-a", ExpiresInSeconds: 60}, "UNSUPPORTED_CONTROL@control"},
		{"audit control", OverrideRequest{Type: store.OverrideContainment, Control: "audit", Operation: "read-a", ExpiresInSeconds: 60}, "UNSUPPORTED_CONTROL@control"},
		{"upstream control", OverrideRequest{Type: store.OverrideException, Control: "upstream", Operation: "read-a", ExpiresInSeconds: 60}, "UNSUPPORTED_CONTROL@control"},
		{"route control name", OverrideRequest{Type: store.OverrideContainment, Control: "route", Operation: "read-a", ExpiresInSeconds: 60}, "UNSUPPORTED_CONTROL@control"},
		{"case variant control", OverrideRequest{Type: store.OverrideException, Control: "Permit", Operation: "write-a", Role: new("READER"), ExpiresInSeconds: 60}, "UNSUPPORTED_CONTROL@control"},
		{"operation allow", OverrideRequest{Type: store.OverrideException, Control: store.ControlOperation, Operation: "denied", ExpiresInSeconds: 60}, "UNSUPPORTED_ACTION@type"},
		{"missing type", OverrideRequest{Control: store.ControlPermit, Operation: "write-a", Role: new("READER"), ExpiresInSeconds: 60}, "INVALID_VALUE@type"},
		{"unknown type", OverrideRequest{Type: "priority", Control: store.ControlPermit, Operation: "write-a", Role: new("READER"), ExpiresInSeconds: 60}, "INVALID_VALUE@type"},
		{"missing control", OverrideRequest{Type: store.OverrideException, Operation: "write-a", ExpiresInSeconds: 60}, "UNSUPPORTED_CONTROL@control"},
		{"missing operation", OverrideRequest{Type: store.OverrideException, Control: store.ControlPermit, Role: new("READER"), ExpiresInSeconds: 60}, "INVALID_VALUE@operation"},
		{"path as operation", OverrideRequest{Type: store.OverrideException, Control: store.ControlPermit, Operation: "/a/*", Role: new("READER"), ExpiresInSeconds: 60}, "INVALID_VALUE@operation"},
		{"method and path as operation", OverrideRequest{Type: store.OverrideException, Control: store.ControlPermit, Operation: "POST /a/item", Role: new("READER"), ExpiresInSeconds: 60}, "INVALID_VALUE@operation"},
		{"encoded operation", OverrideRequest{Type: store.OverrideException, Control: store.ControlPermit, Operation: "write%2Da", Role: new("READER"), ExpiresInSeconds: 60}, "INVALID_VALUE@operation"},
		{"oversized operation", OverrideRequest{Type: store.OverrideContainment, Control: store.ControlOperation, Operation: strings.Repeat("a", policy.MaxIDLength+1), ExpiresInSeconds: 60}, "INVALID_VALUE@operation"},
		{"permit without role", OverrideRequest{Type: store.OverrideException, Control: store.ControlPermit, Operation: "write-a", ExpiresInSeconds: 60}, "INVALID_VALUE@role"},
		{"empty role", withRole(permit, ""), "INVALID_VALUE@role"},
		{"role with a line break", withRole(permit, "READER\r\nX"), "INVALID_VALUE@role"},
		{"role on a rate override", withRole(rateOverride(store.OverrideException, "read-a", 10, 60), "READER"), "INVALID_VALUE@role"},
		{"role on an operation containment", withRole(operationContainment("read-a", 60), "READER"), "INVALID_VALUE@role"},
		{"count on a permit override", withCount(permit, 5), "INVALID_VALUE@count"},
		{"rate without count", OverrideRequest{Type: store.OverrideException, Control: store.ControlRate, Operation: "read-a", ExpiresInSeconds: 60}, "INVALID_VALUE@count"},
		{"zero count", rateOverride(store.OverrideContainment, "read-a", 0, 60), "INVALID_VALUE@count"},
		{"negative count", rateOverride(store.OverrideContainment, "read-a", -1, 60), "INVALID_VALUE@count"},
		{"unlimited count", rateOverride(store.OverrideException, "read-a", compile.MaxRateCount+1, 60), "INVALID_VALUE@count"},
		{"missing expiry", withSeconds(permit, 0), "INVALID_EXPIRY@expires_in_seconds"},
		{"negative expiry", withSeconds(permit, -60), "INVALID_EXPIRY@expires_in_seconds"},
		{"expiry above a day", withSeconds(permit, store.MaxOverrideSeconds+1), "INVALID_EXPIRY@expires_in_seconds"},
		{"expiry past the duration range", withSeconds(permit, 10_000_000_000), "INVALID_EXPIRY@expires_in_seconds"},
	}
	for _, r := range refused {
		if _, err := r.request.check(); overrideErrorCode(err) != r.want {
			t.Errorf("%s: %v, want %s", r.name, err, r.want)
		}
	}
}

// The resolver applies each supported change to a copy of the base and
// nothing else, refuses a change that no longer does what its type says, and
// produces the same generation whatever order the overrides come in.
func TestApplyOverrides(t *testing.T) {
	basePolicy := testdb.Protected()
	basePolicy.Operations[0].Rate = testdb.Rate(4, 60) // read-a
	pristine := string(mustJSON(basePolicy))

	stored := func(id int64, r OverrideRequest) store.Override {
		o, err := r.check()
		if err != nil {
			t.Fatalf("request %+v: %v", r, err)
		}
		o.ID, o.ExpiresAt = id, time.UnixMilli(time.Now().Add(time.Hour).UnixMilli())
		return o
	}
	all := []store.Override{
		stored(1, permitOverride(store.OverrideException, "READER", "write-a", 60)),
		stored(2, permitOverride(store.OverrideContainment, "WRITER", "read-a", 60)),
		stored(3, rateOverride(store.OverrideException, "read-a", 9, 60)),
		stored(4, operationContainment("read-b", 60)),
		stored(5, permitOverride(store.OverrideContainment, "READER", "read-a", 60)),
	}
	p, err := applyOverrides(basePolicy, all)
	if err != nil {
		t.Fatal(err)
	}
	if string(mustJSON(basePolicy)) != pristine {
		t.Fatal("applying overrides changed the base policy")
	}
	wantPermits := []policy.Permit{{Role: "WRITER", Operation: "write-a"}, {Role: "READER", Operation: "read-b"}, {Role: "READER", Operation: "write-a"}}
	if !slices.Equal(p.Permits, wantPermits) {
		t.Fatalf("permits %v, want %v", p.Permits, wantPermits)
	}
	readA, _ := findOperation(p, "read-a")
	readB, _ := findOperation(p, "read-b")
	if readA.Rate.Count != 9 || readA.Rate.WindowSeconds != 60 || readA.Rate.Key != "subject" || readA.Rate.Algorithm != "sliding-window" ||
		readA.Access != "allow" || readB.Access != "deny" {
		t.Fatalf("operations after overrides: read-a %+v rate %+v, read-b %+v", readA, readA.Rate, readB)
	}
	// Apart from the permits, the rate count and the access flag, the
	// result is the base: same routes, methods, destinations, authentication,
	// schemas, roles and subjects.
	restored := p
	restored.Permits = basePolicy.Permits
	restored.Operations = slices.Clone(p.Operations)
	restored.Operations[0].Rate = basePolicy.Operations[0].Rate
	for i := range restored.Operations {
		if restored.Operations[i].ID == "read-b" {
			restored.Operations[i].Access = "allow"
		}
	}
	if string(mustJSON(restored)) != pristine {
		t.Fatalf("overrides changed more than their targets:\n%s\n%s", mustJSON(restored), pristine)
	}

	// The same overrides in any order give one generation; none gives the
	// base's own generation identity.
	deadline := time.Time{}
	first, err := effectiveGeneration(basePolicy, 7, deadline, all)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(first.ID, "r7+o1.2.3.4.5-") || !slices.Equal(first.Overrides, []int64{1, 2, 3, 4, 5}) {
		t.Fatalf("generation %s overrides %v", first.ID, first.Overrides)
	}
	for range 50 {
		shuffled := slices.Clone(all)
		rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		again, err := effectiveGeneration(basePolicy, 7, deadline, shuffled)
		if err != nil || again.ID != first.ID {
			t.Fatalf("order %v gave %v %v, want %s", overrideIDs(shuffled), again, err, first.ID)
		}
	}
	plain, err := compile.Compile(basePolicy, 7, deadline)
	if err != nil {
		t.Fatal(err)
	}
	none, err := effectiveGeneration(basePolicy, 7, deadline, nil)
	if err != nil || none.ID != plain.ID || len(none.Overrides) != 0 {
		t.Fatalf("no overrides: %v %v, want %s", none, err, plain.ID)
	}
	// The generation expires at the earliest expiry of its overrides.
	soon := slices.Clone(all)
	soon[2].ExpiresAt = time.UnixMilli(time.Now().Add(time.Minute).UnixMilli())
	g, err := effectiveGeneration(basePolicy, 7, time.UnixMilli(time.Now().Add(2*time.Minute).UnixMilli()), soon)
	if err != nil || !g.NotAfter.Equal(soon[2].ExpiresAt) {
		t.Fatalf("NotAfter %v, want %v (%v)", g.NotAfter, soon[2].ExpiresAt, err)
	}

	// Each refusal names what no longer fits; nothing is partly applied.
	refused := []struct {
		name string
		list []store.Override
		want string
	}{
		{"grant of a permit the base has", []store.Override{stored(1, permitOverride(store.OverrideException, "WRITER", "write-a", 60))}, "INVALID_VALUE@role"},
		{"removal of a permit the base lacks", []store.Override{stored(1, permitOverride(store.OverrideContainment, "READER", "write-a", 60))}, "INVALID_VALUE@role"},
		{"permit on a public operation", []store.Override{stored(1, permitOverride(store.OverrideException, "READER", "denied", 60))}, "INVALID_VALUE@operation"},
		{"unknown role", []store.Override{stored(1, permitOverride(store.OverrideException, "ADMIN", "write-a", 60))}, "UNKNOWN_REFERENCE@role"},
		{"unknown operation", []store.Override{stored(1, operationContainment("delete-a", 60))}, "UNKNOWN_REFERENCE@operation"},
		{"rate exception that does not raise", []store.Override{stored(1, rateOverride(store.OverrideException, "read-a", 4, 60))}, "INVALID_VALUE@count"},
		{"rate containment that does not lower", []store.Override{stored(1, rateOverride(store.OverrideContainment, "read-a", 5, 60))}, "INVALID_VALUE@count"},
		{"rate override without a base rule", []store.Override{stored(1, rateOverride(store.OverrideException, "read-b", 10, 60))}, "INVALID_VALUE@operation"},
		{"containment of a denied operation", []store.Override{stored(1, operationContainment("denied", 60))}, "INVALID_VALUE@operation"},
		{"two overrides of one target", []store.Override{stored(1, rateOverride(store.OverrideException, "read-a", 9, 60)), stored(2, rateOverride(store.OverrideContainment, "read-a", 1, 60))}, "OVERRIDE_CONFLICT@rate:read-a"},
	}
	for _, r := range refused {
		if _, err := applyOverrides(basePolicy, r.list); overrideErrorCode(err) != r.want {
			t.Errorf("%s: %v, want %s", r.name, err, r.want)
		}
		if g, err := effectiveGeneration(basePolicy, 7, deadline, r.list); g != nil || err == nil {
			t.Errorf("%s: a generation was compiled", r.name)
		}
	}
	// A permit exception on an operation the base denies cannot open it.
	denied := basePolicy
	denied.Operations = slices.Clone(basePolicy.Operations)
	denied.Operations[1].Access = "deny" // write-a
	if _, err := applyOverrides(denied, []store.Override{stored(1, permitOverride(store.OverrideException, "READER", "write-a", 60))}); overrideErrorCode(err) != "INVALID_VALUE@operation" {
		t.Errorf("permit exception on a denied operation: %v", err)
	}
	tooMany := make([]store.Override, store.MaxActiveOverrides+1)
	if _, err := effectiveGeneration(basePolicy, 7, deadline, tooMany); overrideErrorCode(err) != "LIMIT_EXCEEDED@overrides" {
		t.Errorf("too many overrides: %v", err)
	}
}
