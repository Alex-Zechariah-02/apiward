// Controller settings: a host that builds its own Config gets the same
// bounds as the gateway's settings file.

package controller

import (
	"log/slog"
	"testing"
	"time"
)

// The audit wait is held under the controller's lock, so a value beyond its
// bound is refused rather than letting one mutation stall every other one.
func TestPrepareBoundsAuditWait(t *testing.T) {
	e := newEnv(t)
	for _, tc := range []struct {
		wait time.Duration
		ok   bool
	}{{0, true}, {MinAuditWait, true}, {MaxAuditWait, true}, {MinAuditWait - time.Millisecond, false}, {10 * time.Minute, false}} {
		cfg := e.controllerConfig()
		cfg.AuditTimeout = tc.wait
		if _, err := Prepare(cfg, slog.New(slog.DiscardHandler)); (err == nil) != tc.ok {
			t.Errorf("audit wait %s: %v", tc.wait, err)
		}
	}
}
