// Enrolment expiry checked at consumption.

package gateway

import (
	"errors"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/session"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

func TestEnrolmentExpiryAtConsumption(t *testing.T) {
	for _, delta := range []time.Duration{-time.Millisecond, 0, time.Millisecond} {
		t.Run(delta.String(), func(t *testing.T) {
			e := gatewaytest.NewEnv(t)
			gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
			st, err := store.OpenStore(e.Database)
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			issued := time.Now().UTC().Truncate(time.Millisecond)
			expires := issued.Add(time.Minute)
			pending := store.Enrolment{Name: "late", Secret: session.Hash(session.NewToken()), Permissions: store.PermRead, ExpiresAt: expires}
			issue := store.TransitionRecord{ID: "operator:expiry-test", Kind: "operator.enrol", Actor: "operator", Target: pending.Name, Digest: "test"}
			if err := st.IssueEnrolment(t.Context(), issue, pending, issued); err != nil {
				t.Fatal(err)
			}
			// The HTTP handler can read a valid secret before password hashing or
			// waiting for the controller. Consumption must check its lifetime too.
			observed, found, err := st.Enrolment(t.Context(), pending.Secret)
			if err != nil || !found {
				t.Fatalf("pending enrolment: found=%t err=%v", found, err)
			}
			consume := store.TransitionRecord{ID: "enrol:expiry-test", Kind: "admin.enrol", Actor: pending.Name, Target: pending.Name, Digest: "test"}
			err = st.CommitEnrolment(t.Context(), consume, observed, gatewaytest.HarnessHash(), expires.Add(delta))
			if delta < 0 {
				if err != nil {
					t.Fatalf("valid enrolment was not consumed: %v", err)
				}
				if err := st.CommitEnrolment(t.Context(), consume, observed, gatewaytest.HarnessHash(), expires.Add(delta)); !errors.Is(err, store.ErrNotUpdated) {
					t.Fatalf("consumed enrolment replay: %v", err)
				}
				// The store holds the database exclusively until it closes.
				st.Close()
				if gatewaytest.QueryInt(t, e.Database, `SELECT COUNT(*) FROM administrator WHERE name = 'late'`) != 1 {
					t.Fatal("valid enrolment was not consumed")
				}
				return
			}
			if !errors.Is(err, store.ErrNotUpdated) {
				t.Errorf("expired enrolment was consumed: %v", err)
			}
			st.Close()
			if gatewaytest.QueryInt(t, e.Database, `SELECT COUNT(*) FROM administrator WHERE name = 'late'`) != 0 ||
				gatewaytest.QueryInt(t, e.Database, `SELECT COUNT(*) FROM enrolment WHERE administrator = 'late'`) != 1 ||
				gatewaytest.QueryInt(t, e.Database, `SELECT COUNT(*) FROM transition WHERE id = ?`, consume.ID) != 0 {
				t.Error("expired enrolment changed credential, pending secret or history")
			}
		})
	}
}
