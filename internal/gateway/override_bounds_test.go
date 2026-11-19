// The store checks an override's lifetime and the active-override cap
// inside the transaction that commits it, not only in its callers.

package gateway

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

func TestOverrideBoundsInStore(t *testing.T) {
	t.Parallel()
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	db, err := store.Connect(e.Database, "WAL")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := store.Adopt(db)
	now := time.Now()
	commit := func(id int64, life time.Duration) error {
		o := store.Override{ID: id, Type: store.OverrideContainment, Control: store.ControlOperation, Operation: fmt.Sprintf("op-%d", id),
			Base: 1, CreatedAt: now, ExpiresAt: now.Add(life), Actor: gatewaytest.HarnessAdmin}
		o.Target = o.Control + ":" + o.Operation
		creation := store.TransitionRecord{ID: fmt.Sprintf("create-%d", id), Kind: "tpo.create", Actor: gatewaytest.HarnessAdmin, Target: "override", Digest: "d"}
		return s.CommitOverride(t.Context(), creation, o, now)
	}
	if err := commit(1, 25*time.Hour); !errors.Is(err, store.ErrOverrideBounds) {
		t.Fatalf("an override living 25 h: %v", err)
	}
	for id := int64(1); id <= store.MaxActiveOverrides; id++ {
		if err := commit(id, time.Hour); err != nil {
			t.Fatalf("override %d: %v", id, err)
		}
	}
	if err := commit(store.MaxActiveOverrides+1, time.Hour); !errors.Is(err, store.ErrOverrideBounds) {
		t.Fatalf("override beyond the active cap: %v", err)
	}
}
