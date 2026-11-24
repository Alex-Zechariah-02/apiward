// Tests for retryable controller recovery when the audit log refuses an
// outcome record or an automatic ending's intent, while manual revocations
// remain transition_incomplete.

package integration

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

func TestOutcomeAuditFailureRecoversWithoutRestart(t *testing.T) {
	t.Parallel()
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	armed := filepath.Join(e.Dir, "fault-armed")
	os.Remove(armed)
	e.Start(gatewaytest.Binaries.Fault, "GATEWAY_FAULT=audit-fail-published", "GATEWAY_FAULT_ARMED="+armed)
	e.Status()
	harness := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)

	code, staged, body := e.Stage(harness, e.CpaCandidate(), `"r1"`, "cr83-stage-candidate")
	if code != http.StatusCreated {
		t.Fatalf("staging: %d %s", code, body)
	}
	candidate := staged.Candidate.CandidateRecord

	if err := os.WriteFile(armed, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	code, outcome, body := e.Activate(harness, candidate, 60, `"r1"`, "cr83-outcome-recover")
	if code != http.StatusServiceUnavailable || outcome.Outcome != "committed" || outcome.Reason != "OUTCOME_AUDIT_PENDING" {
		t.Fatalf("activate with outcome failure: %d %s", code, body)
	}
	if s := e.Status(); s.State != "audit_reconcile_failed" {
		t.Fatalf("status after outcome failure: %+v", s)
	}
	if got := probe(e, "bob", http.MethodGet, "/a/x"); got != http.StatusServiceUnavailable {
		t.Fatalf("protected request during outage: %d, want 503", got)
	}

	if err := os.Remove(armed); err != nil {
		t.Fatal(err)
	}
	gatewaytest.WaitFor(t, time.Now().Add(10*time.Second), "admission to resume without restart", func() bool {
		return e.Status().State == store.ModeNormal && probe(e, "bob", http.MethodGet, "/a/x") == http.StatusOK
	})
	count := 0
	for _, ev := range e.AuditEvents() {
		if ev["kind"] == "cpa.activated" && ev["transition"] == outcome.Transition {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("cpa.activated count for %s = %d, want 1", outcome.Transition, count)
	}
	e.Stop()
	if n := gatewaytest.QueryInt(t, e.Database, fmt.Sprintf(`SELECT count(*) FROM transition WHERE id='%s' AND audited_at IS NOT NULL`, outcome.Transition)); n != 1 {
		t.Fatalf("audited transition count = %d, want 1", n)
	}
}

func TestExpiryDuringAuditOutageRecovers(t *testing.T) {
	t.Parallel()
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	armed := filepath.Join(e.Dir, "fault-armed")
	os.Remove(armed)
	e.Start(gatewaytest.Binaries.Fault, "GATEWAY_FAULT=audit-full", "GATEWAY_FAULT_ARMED="+armed)
	e.Status()
	harness := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)

	o := e.MustOverride(harness, permitOverride(store.OverrideException, "READER", "write-a", 2), `"r1"`, "cr83-expiry-create")
	if err := os.WriteFile(armed, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	gatewaytest.WaitFor(t, o.Expires.Add(5*time.Second), "audit_reconcile_failed on expiry", func() bool {
		return e.Status().State == "audit_reconcile_failed"
	})
	if got := probe(e, "bob", http.MethodGet, "/a/x"); got != http.StatusServiceUnavailable {
		t.Fatalf("protected request during expiry outage: %d, want 503", got)
	}

	if err := os.Remove(armed); err != nil {
		t.Fatal(err)
	}
	gatewaytest.WaitFor(t, time.Now().Add(10*time.Second), "admission to resume after expiry recovery", func() bool {
		return e.Status().State == store.ModeNormal && probe(e, "bob", http.MethodGet, "/a/x") == http.StatusOK
	})
	if got := probe(e, "bob", http.MethodPost, "/a/item"); got != http.StatusForbidden {
		t.Fatalf("expired override request after recovery: %d, want 403", got)
	}
	wantID := fmt.Sprintf("auto-expire:%d", o.Override)
	count := 0
	for _, ev := range e.AuditEvents() {
		if ev["kind"] == "tpo.expired" && ev["transition"] == wantID {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("tpo.expired count for %s = %d, want 1", wantID, count)
	}
}

func TestRevocationDuringAuditOutageStaysIncomplete(t *testing.T) {
	t.Parallel()
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	harness := e.StartFailingAudit("audit-full")
	armed := filepath.Join(e.Dir, "fault-armed")
	if err := os.Remove(armed); err != nil {
		t.Fatal(err)
	}
	o := e.MustOverride(harness, permitOverride(store.OverrideException, "READER", "write-a", 600), `"r1"`, "cr83-revoke-create")
	if err := os.WriteFile(armed, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	code, outcome, body := revokeOverride(e, harness, o.Override, "cr83-revoke-fail")
	if code != http.StatusServiceUnavailable || outcome.Reason != "AUDIT_UNAVAILABLE" {
		t.Fatalf("revocation during audit outage: %d %s", code, body)
	}
	if s := e.Status(); s.State != "transition_incomplete" {
		t.Fatalf("status after failed revocation: %+v", s)
	}
	if got := probe(e, "bob", http.MethodGet, "/a/x"); got != http.StatusServiceUnavailable {
		t.Fatalf("protected request after failed revocation: %d, want 503", got)
	}

	if err := os.Remove(armed); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2500 * time.Millisecond)
	if s := e.Status(); s.State != "transition_incomplete" {
		t.Fatalf("status after audit recovery: %+v, want transition_incomplete", s)
	}
	if got := probe(e, "bob", http.MethodGet, "/a/x"); got != http.StatusServiceUnavailable {
		t.Fatalf("protected request after audit recovery: %d, want 503", got)
	}
}

// An override that ran out while the gateway was stopped ends at start. When
// its outcome record fails there, start-up publishes nothing until a retry
// has recorded it.
func TestExpiryOutcomeFailureAtStartRecovers(t *testing.T) {
	t.Parallel()
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	e.Status()
	harness := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
	o := e.MustOverride(harness, permitOverride(store.OverrideException, "READER", "write-a", 2), `"r1"`, "expiry-outcome-at-start")
	e.Stop()
	time.Sleep(time.Until(o.Expires) + time.Second)

	armed := filepath.Join(e.Dir, "fault-armed")
	if err := os.WriteFile(armed, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	e.Start(gatewaytest.Binaries.Fault, "GATEWAY_FAULT=audit-fail-published", "GATEWAY_FAULT_ARMED="+armed)
	if s := e.Status(); s.State != "audit_reconcile_failed" {
		t.Fatalf("status after the expiry outcome failed at start: %+v", s)
	}
	if got := probe(e, "bob", http.MethodGet, "/a/x"); got != http.StatusServiceUnavailable {
		t.Fatalf("protected request while the expiry outcome is unrecorded: %d, want 503", got)
	}

	if err := os.Remove(armed); err != nil {
		t.Fatal(err)
	}
	gatewaytest.WaitFor(t, time.Now().Add(10*time.Second), "admission to resume once the outcome is recorded", func() bool {
		return e.Status().State == store.ModeNormal && probe(e, "bob", http.MethodGet, "/a/x") == http.StatusOK
	})
	wantID := fmt.Sprintf("auto-expire:%d", o.Override)
	count := 0
	for _, ev := range e.AuditEvents() {
		if ev["kind"] == "tpo.expired" && ev["transition"] == wantID {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("tpo.expired count for %s = %d, want 1", wantID, count)
	}
}
