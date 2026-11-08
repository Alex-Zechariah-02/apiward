// Historical restore quarantines overrides.

package integration

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// A declared historical restore of a backup taken while an override was
// active never brings that override back, even though it was revoked after
// the backup and its stored expiry is still in the future: the restored
// database is marked recovery_required before it becomes live, every
// restart keeps it so, and recovery ends under a deny-all base with no
// override. An ordinary restart of the current database keeps the override.
func TestHistoricalRestoreQuarantinesOverrides(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	harness := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
	grant := e.MustOverride(harness, permitOverride(store.OverrideException, "READER", "write-a", 3600), `"r1"`, "restore-grant-00001")

	// Ordinary restart: the current database keeps the eligible override.
	e.Stop()
	e.Start(gatewaytest.Binaries.Plain)
	if code := probe(e, "bob", http.MethodPost, "/a/item"); code != http.StatusOK {
		t.Fatalf("grant after an ordinary restart: %d", code)
	}

	backup := filepath.Join(t.TempDir(), "with-override.db")
	e.Stop()
	writeBackup(e, backup)
	e.Start(gatewaytest.Binaries.Plain)
	harness = e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
	if code, _, body := revokeOverride(e, harness, grant.Override, "restore-revoke-0001"); code != http.StatusOK {
		t.Fatalf("revocation: %d %s", code, body)
	}
	e.Stop()

	// An interrupted restore leaves the current database, which serves the
	// revocation.
	if out, code := e.RunOperator(gatewaytest.Binaries.Fault, []string{"GATEWAY_FAULT=restore-before-promote"}, "restore", "--backup", backup); code != crashExit {
		t.Fatalf("interrupted restore exited %d: %s", code, out)
	}
	e.Start(gatewaytest.Binaries.Plain)
	if code := probe(e, "bob", http.MethodPost, "/a/item"); code != http.StatusForbidden {
		t.Fatalf("after an interrupted restore: %d", code)
	}
	e.Stop()

	if out, code := e.RunOperator(gatewaytest.Binaries.Plain, nil, "restore", "--backup", backup); code != 0 {
		t.Fatalf("restore exited %d: %s", code, out)
	}
	if mode := gatewaytest.QueryString(t, e.Database, `SELECT mode FROM deployment`); mode != store.ModeRecovery {
		t.Fatalf("restored mode %q", mode)
	}
	list := storedOverrides(t, e.Database)
	if len(list) != 1 || list[0].Status != store.OverrideQuarantined || list[0].ResolvedBy != "operator" || !list[0].ExpiresAt.After(time.Now()) {
		t.Fatalf("restored overrides %+v", list)
	}
	for range 2 {
		e.Start(gatewaytest.Binaries.Plain)
		if health := e.Health(); health != store.ModeRecovery {
			t.Fatalf("health %q after the restore", health)
		}
		expectNothingServed(e)
		e.Stop()
	}

	root := recoverAdministrator(e)
	establishRecoveryBase(e, root)
	view := activeOverrides(e, root)
	if len(view.Overrides) != 0 || len(view.GenerationOverrides) != 0 {
		t.Fatalf("overrides after recovery %+v", view)
	}
	expectNothingServed(e)
	if code, outcome, body := revokeOverride(e, root, grant.Override, "restore-revoke-0002"); code != http.StatusConflict || outcome.Disposition != store.OverrideQuarantined {
		t.Fatalf("revocation of the quarantined override: %d %s", code, body)
	}
	e.Stop()
	if list := storedOverrides(t, e.Database); list[0].Status != store.OverrideQuarantined {
		t.Fatalf("override after recovery %+v", list[0])
	}
}

// A declared historical restore of a backup holding several active overrides
// on distinct targets, with or without a provisional base, quarantines all of
// them under the one restore transition. Each keeps its own identity, target
// and creation history, and none is served again, although one was revoked
// after the backup and every stored expiry is still in the future. An
// interrupted restore leaves the live database authoritative and unchanged;
// repeating the restore completes it. Recovery ends under a deny-all base with
// no override, and a quarantined override can never be revoked or resumed.
func TestHistoricalRestoreQuarantinesSeveralOverrides(t *testing.T) {
	for _, withProvisional := range []bool{false, true} {
		name := "overrides"
		if withProvisional {
			name = "overrides and a provisional base"
		}
		t.Run(name, func(t *testing.T) {
			e := gatewaytest.NewEnv(t)
			gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
			e.Start(gatewaytest.Binaries.Plain)
			harness := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
			grant := e.MustOverride(harness, permitOverride(store.OverrideException, "READER", "write-a", 3600), `"r1"`, "several-grant-00001")
			e.MustOverride(harness, gatewaytest.OperationContainment("read-b", 3600), `"r1"`, "several-contain-0001")
			if withProvisional {
				e.ProvisionalFrom(harness, upstreamCandidate(e), 1, 3600, "several-provisional")
			}
			if s := e.Status(); len(s.Overrides) != 2 || (s.Provisional == 2) != withProvisional {
				t.Fatalf("status before the backup %+v", s)
			}
			e.Stop()
			backup := filepath.Join(t.TempDir(), "several-overrides.db")
			writeBackup(e, backup)
			backedUp := storedOverrides(t, backup)

			e.Start(gatewaytest.Binaries.Plain)
			harness = e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
			if code, _, body := revokeOverride(e, harness, grant.Override, "several-revoke-0001"); code != http.StatusOK {
				t.Fatalf("revocation after the backup: %d %s", code, body)
			}
			e.Stop()

			// An interrupted restore changes nothing live; the staged copy was
			// already marked before it could have been promoted. Reading the
			// stopped database first applies its write-ahead log, so the file
			// hash compared below is the whole live state.
			if mode := gatewaytest.QueryString(t, e.Database, `SELECT mode FROM deployment`); mode != store.ModeNormal {
				t.Fatalf("live mode %q", mode)
			}
			live := gatewaytest.FileSHA256(t, e.Database)
			if out, code := e.RunOperator(gatewaytest.Binaries.Fault, []string{"GATEWAY_FAULT=restore-before-promote"}, "restore", "--backup", backup); code != crashExit {
				t.Fatalf("interrupted restore exited %d: %s", code, out)
			}
			if gatewaytest.FileSHA256(t, e.Database) != live {
				t.Fatal("the interrupted restore changed the live database")
			}
			if retired, _ := filepath.Glob(e.Database + ".replaced-*"); len(retired) != 0 {
				t.Fatalf("the interrupted restore retired the live database: %v", retired)
			}
			if mode := gatewaytest.QueryString(t, e.Database+".restore", `SELECT mode FROM deployment`); mode != store.ModeRecovery {
				t.Fatalf("staged copy mode %q", mode)
			}
			e.Start(gatewaytest.Binaries.Plain)
			if health := e.Health(); health != store.ModeNormal {
				t.Fatalf("health %q after the interrupted restore", health)
			}
			if a, b := probe(e, "bob", http.MethodPost, "/a/item"), probe(e, "bob", http.MethodGet, "/b/x"); a != http.StatusForbidden || b != http.StatusForbidden {
				t.Fatalf("revoked grant and active containment after the interrupted restore: %d %d", a, b)
			}
			if code := probe(e, "alice", http.MethodGet, "/a/x"); code != http.StatusOK {
				t.Fatalf("live base after the interrupted restore: %d", code)
			}
			e.Stop()

			if mode := gatewaytest.QueryString(t, e.Database, `SELECT mode FROM deployment`); mode != store.ModeNormal {
				t.Fatalf("live mode %q before the restore", mode)
			}
			live = gatewaytest.FileSHA256(t, e.Database)
			if out, code := e.RunOperator(gatewaytest.Binaries.Plain, nil, "restore", "--backup", backup); code != 0 || !strings.Contains(out, store.ModeRecovery) {
				t.Fatalf("restore exited %d: %s", code, out)
			}
			if retired, _ := filepath.Glob(e.Database + ".replaced-*"); len(retired) != 1 || gatewaytest.FileSHA256(t, retired[0]) != live {
				t.Fatalf("the replaced live database is not kept unchanged: %v", retired)
			}

			// Every override active in the backup is quarantined, changed in
			// nothing but its disposition, and all name one restore transition.
			restored := storedOverrides(t, e.Database)
			if len(restored) != 2 {
				t.Fatalf("restored overrides %+v", restored)
			}
			resolution := restored[0].Resolution
			for i, o := range restored {
				unchanged := o
				unchanged.Status, unchanged.ResolvedAt, unchanged.ResolvedBy, unchanged.Resolution = store.OverrideActive, nil, "", ""
				if unchanged != backedUp[i] || o.Status != store.OverrideQuarantined || o.ResolvedBy != "operator" || o.ResolvedAt == nil ||
					o.Resolution != resolution || !o.ExpiresAt.After(time.Now()) {
					t.Fatalf("override restored as %+v from %+v", o, backedUp[i])
				}
			}
			if resolution != "operator:restore:"+gatewaytest.QueryString(t, e.Database, `SELECT recovery_episode FROM deployment`) {
				t.Fatalf("resolution %q is not the restore transition of the recovery episode", resolution)
			}
			quarantinedActivations := 0
			if withProvisional {
				quarantinedActivations = 1
			}
			for query, want := range map[string]int{
				`SELECT COUNT(*) FROM transition WHERE kind = 'operator.restore'`:                                         1,
				`SELECT COUNT(*) FROM transition WHERE id = '` + resolution + `' AND outcome = 'committed'`:               1,
				`SELECT COUNT(*) FROM activation WHERE disposition = 'quarantined' AND resolution = '` + resolution + `'`: quarantinedActivations,
				`SELECT COUNT(*) FROM base WHERE confirmed = 1 AND provisional IS NULL AND deadline IS NULL`:              1,
				`SELECT COUNT(*) FROM override WHERE status = 'active'`:                                                   0,
				`SELECT COUNT(*) FROM pragma_foreign_key_check`:                                                           0,
			} {
				if n := gatewaytest.QueryInt(t, e.Database, query); n != want {
					t.Errorf("%s = %d, want %d", query, n, want)
				}
			}
			if check := gatewaytest.QueryString(t, e.Database, `PRAGMA integrity_check`); check != "ok" {
				t.Fatalf("integrity check of the restored database %q", check)
			}

			for range 2 {
				e.Start(gatewaytest.Binaries.Plain)
				if health := e.Health(); health != store.ModeRecovery {
					t.Fatalf("health %q after the restore", health)
				}
				expectNothingServed(e)
				e.Stop()
			}

			// Only re-established trust and a deny-all recovery base end the
			// recovery; restored administrators stay quarantined and no
			// override can be created or revoked meanwhile.
			root := recoverAdministrator(e)
			if _, code := e.Login(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword); code != http.StatusUnauthorized {
				t.Fatalf("restored administrator during recovery: %d", code)
			}
			if code, outcome, body := e.CreateOverride(root, gatewaytest.OperationContainment("read-a", 60), `"r1"`, "several-recovery-create"); code != http.StatusConflict || outcome.Reason != "INVALID_STATE" {
				t.Fatalf("override creation during recovery: %d %s", code, body)
			}
			if code, outcome, body := revokeOverride(e, root, grant.Override, "several-recovery-revoke"); code != http.StatusConflict || outcome.Reason != "INVALID_STATE" {
				t.Fatalf("revocation during recovery: %d %s", code, body)
			}
			expectNothingServed(e)
			recovery := establishRecoveryBase(e, root)
			code, body, _ := e.As(root, http.MethodGet, "/admin/status", "")
			if s := fromJSON[gatewaytest.Status](t, body); code != http.StatusOK || s.State != store.ModeNormal || s.Confirmed != recovery.Revision || s.Provisional != 0 || len(s.Overrides) != 0 {
				t.Fatalf("status after the recovery base: %d %s", code, body)
			}
			if view := activeOverrides(e, root); len(view.Overrides) != 0 || len(view.GenerationOverrides) != 0 {
				t.Fatalf("overrides after recovery %+v", view)
			}
			expectNothingServed(e)
			for i, o := range restored {
				code, outcome, body := revokeOverride(e, root, o.ID, fmt.Sprintf("several-after-revoke-%d", i))
				if code != http.StatusConflict || outcome.Reason != "ALREADY_RESOLVED" || outcome.Disposition != store.OverrideQuarantined {
					t.Fatalf("revocation of quarantined override %d: %d %s", o.ID, code, body)
				}
			}
			if withProvisional {
				code, outcome, body := e.Resolve(root, "confirm", 2, gatewaytest.RevisionTag(recovery.Revision), "several-confirm-0001")
				if code != http.StatusConflict || outcome.Reason != "ALREADY_RESOLVED" || outcome.Disposition != store.DispositionQuarantined {
					t.Fatalf("confirmation of the quarantined provisional base: %d %s", code, body)
				}
			}
			restores := 0
			for _, ev := range e.AuditEvents() {
				id, _ := ev["transition"].(string)
				if ev["kind"] == "transition.committed" && strings.HasPrefix(id, "operator:restore:") {
					restores++
				}
			}
			if restores != 1 {
				t.Fatalf("%d committed restore events, want 1 (the interrupted attempt has only its intent)", restores)
			}
			e.Stop()
			if after := storedOverrides(t, e.Database); fmt.Sprintf("%+v", after) != fmt.Sprintf("%+v", restored) {
				t.Fatalf("quarantined overrides changed during recovery: %+v", after)
			}
		})
	}
}
