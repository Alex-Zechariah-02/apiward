// Damaged override state and audit failures.

package integration

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// Stored overrides that do not fit the base they would apply to make startup
// refuse to serve rather than drop or keep them. Audit failures during an
// override change never report success that was not durable, and never keep
// serving an override whose revocation could not be completed.
func TestDamagedOverrideStateAndAuditFailures(t *testing.T) {
	damaged := []struct {
		name   string
		insert string
		reason string
	}{
		{"unknown role", `INSERT INTO override (id, type, control, operation, role, target, base, created_at, expires_at, actor, creation, status)
			VALUES (1, 'exception', 'permit', 'write-a', 'ADMIN', 'permit:ADMIN:write-a', 1, 1, ?, 'x', 'seed-override', 'active')`, "UNKNOWN_REFERENCE"},
		{"rate exception lower than the base", `INSERT INTO override (id, type, control, operation, count, target, base, created_at, expires_at, actor, creation, status)
			VALUES (1, 'exception', 'rate', 'read-a', 1, 'rate:read-a', 1, 1, ?, 'x', 'seed-override', 'active')`, "INVALID_VALUE"},
		{"unknown operation", `INSERT INTO override (id, type, control, operation, target, base, created_at, expires_at, actor, creation, status)
			VALUES (1, 'containment', 'operation', 'gone', 'operation:gone', 1, 1, ?, 'x', 'seed-override', 'active')`, "UNKNOWN_REFERENCE"},
	}
	for _, d := range damaged {
		t.Run(d.name, func(t *testing.T) {
			e := gatewaytest.NewEnv(t)
			p := e.ProtectedPolicy()
			p.Operations[0].Rate = gatewaytest.Rate(4, 60)
			gatewaytest.Seed(t, e.Database, p, gatewaytest.SeedOptions{})
			db := gatewaytest.Inspect(t, e.Database)
			mustExec(t, db, `INSERT INTO transition (id, kind, actor, target, digest, outcome, reason, committed_at, published_at, audited_at)
				VALUES ('seed-override', 'tpo.create', 'x', 'override', 'x', 'committed', '', 1, 1, 1)`)
			if _, err := db.Exec(d.insert, time.Now().Add(time.Hour).UnixMilli()); err != nil {
				t.Fatal(err)
			}
			db.Close()
			e.Start(gatewaytest.Binaries.Plain)
			if health := e.Health(); health != "unavailable" {
				t.Fatalf("health %q", health)
			}
			if reason := e.UnavailableReason(); !strings.Contains(reason, "overrides [1]") || !strings.Contains(reason, d.reason) {
				t.Fatalf("reason %q", reason)
			}
			expectNothingServed(e)
		})
	}

	t.Run("audit unavailable for a creation", func(t *testing.T) {
		e := gatewaytest.NewEnv(t)
		gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
		e.Start(gatewaytest.Binaries.Plain)
		harness := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
		e.Stop()
		e.Start(gatewaytest.Binaries.Fault, "GATEWAY_FAULT=audit-full")
		harness = e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
		code, outcome, body := e.CreateOverride(harness, permitOverride(store.OverrideException, "READER", "write-a", 600), `"r1"`, "audit-full-create-01")
		if code != http.StatusServiceUnavailable || outcome.Reason != "AUDIT_UNAVAILABLE" {
			t.Fatalf("creation without audit: %d %s", code, body)
		}
		e.Stop()
		if list := storedOverrides(t, e.Database); len(list) != 0 {
			t.Fatalf("stored overrides %+v", list)
		}
	})

	t.Run("outcome not recorded for a creation", func(t *testing.T) {
		e := gatewaytest.NewEnv(t)
		gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
		e.Start(gatewaytest.Binaries.Fault, "GATEWAY_FAULT=audit-fail-published")
		harness := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
		code, outcome, body := e.CreateOverride(harness, permitOverride(store.OverrideException, "READER", "write-a", 600), `"r1"`, "audit-pending-create")
		if code != http.StatusServiceUnavailable || outcome.Outcome != "committed" || outcome.Reason != "OUTCOME_AUDIT_PENDING" {
			t.Fatalf("creation with a lost outcome event: %d %s", code, body)
		}
		// Admission stops until a restart records the missing event.
		e.ResetReceivers()
		if code := probe(e, "bob", http.MethodPost, "/a/item"); code != http.StatusServiceUnavailable {
			t.Fatalf("admission with a failed audit log: %d", code)
		}
		e.AssertReceipts(0, 0, 0)
		e.Stop()
		e.Start(gatewaytest.Binaries.Plain)
		if code := probe(e, "bob", http.MethodPost, "/a/item"); code != http.StatusOK {
			t.Fatalf("committed grant after restart: %d", code)
		}
		events := e.EventsWhen(func(events []map[string]any) bool { return gatewaytest.CountKind(events, "tpo.created") >= 1 })
		ev := findTransition(events, "tpo.created", outcome.Transition)
		if ev == nil || ev["reason"] != "reconciled" || ev["override"] != float64(outcome.Override) {
			t.Fatalf("reconciled outcome event %v", ev)
		}
	})

	t.Run("audit unavailable for an expiry", func(t *testing.T) {
		e := gatewaytest.NewEnv(t)
		gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
		e.Start(gatewaytest.Binaries.Plain)
		harness := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
		o := e.MustOverride(harness, permitOverride(store.OverrideException, "READER", "write-a", 3), `"r1"`, "audit-expiry-create")
		// The audit file fails from now on: the expiry cannot be recorded.
		e.Stop()
		e.Start(gatewaytest.Binaries.Fault, "GATEWAY_FAULT=audit-full")
		if health := e.Health(); health != store.ModeNormal {
			t.Fatalf("health %q before the expiry", health)
		}
		gatewaytest.WaitFor(t, o.Expires.Add(5*time.Second), "protected admission to stop", func() bool { return e.Health() == "unavailable" })
		expectNothingServed(e)
		e.Stop()
		if list := storedOverrides(t, e.Database); len(list) != 1 || list[0].Status != store.OverrideActive {
			t.Fatalf("an expiry that could not be recorded was committed: %+v", list)
		}
		// With the audit file working again, startup ends it before serving.
		e.Start(gatewaytest.Binaries.Plain)
		e.ResetReceivers()
		if code := probe(e, "bob", http.MethodPost, "/a/item"); code != http.StatusForbidden {
			t.Fatalf("first write after restart: %d", code)
		}
		e.AssertReceipts(0, 0, 0)
		e.Stop()
		if list := storedOverrides(t, e.Database); list[0].Status != store.OverrideExpired {
			t.Fatalf("override after restart %+v", list[0])
		}
	})

	t.Run("audit unavailable for a revocation", func(t *testing.T) {
		e := gatewaytest.NewEnv(t)
		gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
		e.Start(gatewaytest.Binaries.Plain)
		harness := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
		o := e.MustOverride(harness, permitOverride(store.OverrideException, "READER", "write-a", 600), `"r1"`, "audit-revoke-create")
		e.Stop()
		e.Start(gatewaytest.Binaries.Fault, "GATEWAY_FAULT=audit-full")
		harness = e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
		code, outcome, body := revokeOverride(e, harness, o.Override, "audit-full-revoke-01")
		if code != http.StatusServiceUnavailable || outcome.Reason != "AUDIT_UNAVAILABLE" {
			t.Fatalf("revocation without audit: %d %s", code, body)
		}
		// The grant being withdrawn is not served any more.
		if health := e.Health(); health != "unavailable" {
			t.Fatalf("health %q", health)
		}
		expectNothingServed(e)
		// After a restart nothing was revoked: the override is still active
		// and can be revoked properly.
		e.Stop()
		e.Start(gatewaytest.Binaries.Plain)
		harness = e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
		if code, outcome, body := revokeOverride(e, harness, o.Override, "audit-revoke-retry-01"); code != http.StatusOK || outcome.Disposition != store.OverrideRevoked {
			t.Fatalf("revocation after restart: %d %s", code, body)
		}
	})
}
