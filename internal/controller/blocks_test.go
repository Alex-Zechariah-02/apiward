// Account blocks whose stored receipt cannot be read on a resend.

package controller

import (
	"context"
	"database/sql"
	"net/http"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/store"
	"github.com/Alex-Zechariah-02/apiward/internal/storetest"
)

// STORE_ERROR says only that this request did not complete. When the record
// of an earlier, committed attempt cannot be read, a resend of the same
// change is answered store_error while that change stays in force, so the
// Dashboard must never describe store_error as "nothing changed". Once the
// store can be read, the resend returns the recorded receipt.
func TestStoreErrorOnResendDoesNotMeanNothingChanged(t *testing.T) {
	e := newEnv(t)
	storetest.Seed(t, e.database, storetest.Protected(), storetest.Options{Administrator: "root"})
	c := e.own(e.controllerConfig())
	const reason = "store error test"
	request := struct {
		Reason string `json:"reason"`
	}{reason}
	block := store.TransitionRecord{ID: "admin:root:store-error-resend-01", Kind: "account.block", Actor: "root", Target: "cust-500",
		Digest: store.Digest("account.block", "cust-500", sql.NullInt64{}, request)}
	receipt, status := c.Block(t.Context(), block, reason)
	if status != http.StatusOK {
		t.Fatalf("block: %d %s", status, receipt)
	}
	// A cancelled request makes the read of the earlier record fail.
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if body, status := c.Block(cancelled, block, reason); status != http.StatusServiceUnavailable || string(body) != `{"error":"store_error"}` {
		t.Fatalf("resend with an unreadable record: %d %s", status, body)
	}
	if failures := c.Gauges()[5]; failures.Name != "gateway_control_store_failures_total" || failures.Value != 1 {
		t.Fatalf("failure metric %+v, want gateway_control_store_failures_total 1", failures)
	}
	if _, inForce := (*c.Blocked())["cust-500"]; !inForce {
		t.Fatal("the committed block is no longer in force")
	}
	if body, status := c.Block(t.Context(), block, reason); status != http.StatusOK || string(body) != string(receipt) {
		t.Fatalf("resend with a readable record: %d %s, want the receipt %s", status, body, receipt)
	}
}
