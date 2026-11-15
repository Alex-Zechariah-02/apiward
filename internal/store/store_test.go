// Store reads and writes: Load reads one consistent state while revisions
// are committed, unused candidates are bounded, a snapshot stops when its
// context ends, and a payload that cannot be digested is an error.

package store_test

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/store"
	"github.com/Alex-Zechariah-02/apiward/internal/storetest"
)

func open(t *testing.T) *store.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gateway.db")
	storetest.Seed(t, path, storetest.Policy(false), storetest.Options{})
	st, err := store.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// Each commit makes a new confirmed revision and prunes the one before, so a
// Load that read the base and the document in separate statements would
// meet a base whose document is already gone.
func TestLoadConsistent(t *testing.T) {
	st := open(t)
	ctx := context.Background()
	document := []byte(`{"schema_version":4,"profile":"core"}`)
	var wg sync.WaitGroup
	done := make(chan struct{})
	failures := make(chan error, 1)
	wg.Go(func() {
		for {
			select {
			case <-done:
				return
			default:
			}
			if _, err := st.Load(ctx); err != nil {
				select {
				case failures <- err:
				default:
				}
				return
			}
		}
	})
	parent := int64(1)
	for i := range 300 {
		id := fmt.Sprintf("test:publish:%d", i)
		revision, err := st.CommitRevision(ctx, store.TransitionRecord{ID: id, Kind: "publish", Actor: "test", Target: "policy", Digest: "d"},
			store.RevisionChange{Parent: parent, Origin: "publish", Document: document, Actor: "test", Mode: store.ModeNormal, Keep: 1}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err := st.MarkAudited(ctx, id, time.Now()); err != nil {
			t.Fatal(err)
		}
		parent = revision
	}
	close(done)
	wg.Wait()
	select {
	case err := <-failures:
		t.Fatalf("Load during commits: %v", err)
	default:
	}
}

// Staging past MaxUnused deletes the oldest unused candidates whose records
// are audited; one whose record is not yet audited is kept.
func TestUnusedCandidatesBounded(t *testing.T) {
	st := open(t)
	ctx := context.Background()
	document := []byte(`{"schema_version":4,"profile":"core"}`)
	stage := func(i int, audited bool) int64 {
		id := fmt.Sprintf("test:stage:%d", i)
		candidate, err := st.CommitCandidate(ctx, store.TransitionRecord{ID: id, Kind: "candidate.create", Actor: "test", Target: "candidate", Digest: "d"},
			store.CandidateRecord{Parent: 1, Document: document, Checksum: store.DocumentChecksum(document), Actor: "test"}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if audited {
			if err := st.MarkAudited(ctx, id, time.Now()); err != nil {
				t.Fatal(err)
			}
		}
		return candidate
	}
	unaudited := stage(0, false)
	var ids []int64
	for i := 1; i <= store.MaxUnused+10; i++ {
		ids = append(ids, stage(i, true))
	}
	list, err := st.Candidates(ctx, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != store.MaxUnused+1 {
		t.Fatalf("%d candidates kept, want %d unused and the unaudited one", len(list), store.MaxUnused)
	}
	kept := map[int64]bool{}
	for _, c := range list {
		kept[c.ID] = true
	}
	if !kept[unaudited] || !kept[ids[len(ids)-1]] || kept[ids[0]] || kept[ids[9]] || !kept[ids[10]] {
		t.Fatalf("wrong candidates kept: %v", kept)
	}
	if _, found, err := st.Transition(ctx, "test:stage:1"); err != nil || found {
		t.Fatalf("the staging record of a deleted candidate: found %v, %v", found, err)
	}
}

// A cancelled context stops a snapshot before it writes anything.
func TestSnapshotCancelled(t *testing.T) {
	st := open(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	path := filepath.Join(t.TempDir(), "copy.db")
	if err := st.Snapshot(ctx, path); err == nil {
		t.Fatal("snapshot with a cancelled context succeeded")
	}
	if err := st.Snapshot(context.Background(), path); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
}

func TestDigestError(t *testing.T) {
	if _, err := store.Digest("kind", "target", sql.NullInt64{}, func() {}); err == nil {
		t.Fatal("a payload JSON cannot encode was digested")
	}
}
