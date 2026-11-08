// Restore quarantine and crash during restore.

package integration

import (
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// A backup taken while a provisional base was active, whether its
// deadline has passed by the time of the restore or not, never brings that
// provisional authority back: the restore closes its activation as
// quarantined (not confirmed, not rolled back), nothing is served until a new
// deny-all recovery base is confirmed, and that base has no provisional base.
func TestHistoricalRestoreQuarantinesProvisional(t *testing.T) {
	for _, tc := range []struct {
		name    string
		seconds int64
		expired bool // restore after the deadline has passed
	}{{"deadline not yet passed", 3600, false}, {"deadline passed", 2, true}} {
		t.Run(tc.name, func(t *testing.T) {
			e := gatewaytest.NewEnv(t)
			gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
			e.Start(gatewaytest.Binaries.Plain)
			harness := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
			_, activated := e.ProvisionalFrom(harness, e.CpaCandidate(), 1, tc.seconds, "restore-provisional")
			e.Stop()
			backup := filepath.Join(e.Dir, "provisional.db")
			writeBackup(e, backup)
			if n := gatewaytest.QueryInt(t, backup, `SELECT COUNT(*) FROM base WHERE provisional = 2`); n != 1 {
				t.Fatal("the backup does not hold the provisional base")
			}
			if tc.expired {
				time.Sleep(time.Until(activated.Deadline.Add(200 * time.Millisecond)))
			}

			if out, code := e.RunOperator(gatewaytest.Binaries.Plain, nil, "restore", "--backup", backup); code != 0 {
				t.Fatalf("restore exited %d: %s", code, out)
			}
			list := storedActivations(t, e.Database)
			if len(list) != 1 || list[0].Disposition != store.DispositionQuarantined || list[0].ResolvedBy != "operator" ||
				!strings.HasPrefix(list[0].Resolution, "operator:restore:") {
				t.Fatalf("restored activations %+v", list)
			}
			if n := gatewaytest.QueryInt(t, e.Database, `SELECT COUNT(*) FROM base WHERE provisional IS NULL AND deadline IS NULL AND confirmed = 1`); n != 1 {
				t.Fatal("the restored base still points at the provisional revision")
			}

			e.Start(gatewaytest.Binaries.Plain)
			if health := e.Health(); health != store.ModeRecovery {
				t.Fatalf("health %q", health)
			}
			expectNothingServed(e)
			root := recoverAdministrator(e)
			expectNothingServed(e)
			recovery := establishRecoveryBase(e, root)
			// Restored administrators, the harness's among them, stay
			// quarantined: only the re-enrolled root can read the status.
			code, body, _ := e.As(root, http.MethodGet, "/admin/status", "")
			if s := fromJSON[gatewaytest.Status](t, body); code != http.StatusOK || s.Provisional != 0 || s.Confirmed != recovery.Revision || !s.NotAfter.IsZero() {
				t.Fatalf("status after the recovery base: %d %s", code, body)
			}
			expectNothingServed(e)
			// The quarantined revision cannot be confirmed or rolled back.
			for _, action := range []string{"confirm", "rollback"} {
				code, outcome, body := e.Resolve(root, action, 2, gatewaytest.RevisionTag(recovery.Revision), "restored-"+action+"-xxxxx")
				if code != http.StatusConflict || outcome.Reason != "ALREADY_RESOLVED" || outcome.Disposition != store.DispositionQuarantined {
					t.Fatalf("%s of the quarantined revision: %d %s", action, code, body)
				}
			}
			code, body, _ = e.As(root, http.MethodGet, "/admin/activations", "")
			if items := fromJSON[struct {
				Items []store.ActivationRecord `json:"items"`
			}](t, body).Items; code != http.StatusOK || len(items) != 1 || items[0].Disposition != store.DispositionQuarantined {
				t.Fatalf("activation history: %d %s", code, body)
			}
		})
	}
}

// expectNothingServed checks that no protected or public probe reaches any
// receiver.
func expectNothingServed(e *gatewaytest.Env) {
	e.T.Helper()
	e.ResetReceivers()
	bobToken := "Bearer " + gatewaytest.Issuer.TokenFor(e.T, "bob")
	for _, probe := range []struct{ method, path string }{{"GET", "/b/x"}, {"POST", "/a/item"}, {"GET", "/a/x"}, {"GET", "/d"}} {
		code, _ := e.Request(probe.method, probe.path, "application/json", `{}`, "Authorization", bobToken)
		if code == http.StatusOK {
			e.T.Fatalf("%s %s admitted", probe.method, probe.path)
		}
	}
	e.AssertReceipts(0, 0, 0)
}

// A crash at each step of a restore leaves
// the original database, no database or the marked copy, never an unmarked
// historical one, and running the restore again completes it.
func TestRestoreSurvivesCrash(t *testing.T) {
	for _, tc := range []struct {
		point  string
		health string // after the crash, before the restore is repeated
	}{
		{"restore-before-promote", store.ModeNormal},
		{"restore-after-retire", "unavailable"},
		{"restore-after-promote", store.ModeRecovery},
	} {
		t.Run(tc.point, func(t *testing.T) {
			e := gatewaytest.NewEnv(t)
			gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
			older := filepath.Join(e.Dir, "older.db")
			writeBackup(e, older)

			if _, code := e.RunOperator(gatewaytest.Binaries.Fault, []string{"GATEWAY_FAULT=" + tc.point}, "restore", "--backup", older); code != crashExit {
				t.Fatalf("restore exit code %d", code)
			}
			if staged, err := os.Stat(e.Database + ".restore"); err == nil && staged.Size() > 0 {
				if mode := gatewaytest.QueryString(t, e.Database+".restore", `SELECT mode FROM deployment`); mode != store.ModeRecovery {
					t.Fatalf("the staged copy is not marked: %q", mode)
				}
			}

			e.Start(gatewaytest.Binaries.Plain)
			if health := e.Health(); health != tc.health {
				t.Fatalf("health after the crash %q, want %q", health, tc.health)
			}
			want := http.StatusServiceUnavailable
			if tc.health == store.ModeNormal {
				want = http.StatusOK
			}
			if code, _ := e.Get("/a/x", "Authorization", "Bearer "+gatewaytest.Issuer.TokenFor(t, "alice")); code != want {
				t.Fatalf("data plane after the crash: %d, want %d", code, want)
			}
			if tc.point == "restore-after-promote" {
				// The lost outcome event is recorded from the database.
				restore := func(ev map[string]any) bool {
					id, _ := ev["transition"].(string)
					return ev["kind"] == "transition.committed" && ev["reason"] == "reconciled" && strings.HasPrefix(id, "operator:restore:")
				}
				events := e.EventsWhen(func(events []map[string]any) bool {
					return gatewaytest.CountKind(events, "controller.unavailable") > 0 && slices.ContainsFunc(events, restore)
				})
				if !slices.ContainsFunc(events, restore) {
					t.Fatal("no reconciled outcome event for the promoted restore")
				}
				e.Stop()
				if n := gatewaytest.QueryInt(t, e.Database, `SELECT COUNT(*) FROM transition WHERE kind = 'operator.restore' AND audited_at IS NOT NULL`); n != 1 {
					t.Fatalf("%d audited restore transitions", n)
				}
				return
			}
			e.Stop()

			out, code := e.RunOperator(gatewaytest.Binaries.Plain, nil, "restore", "--backup", older)
			if code != 0 {
				t.Fatalf("repeated restore exited %d: %s", code, out)
			}
			e.Start(gatewaytest.Binaries.Plain)
			if health := e.Health(); health != store.ModeRecovery {
				t.Fatalf("health after the repeated restore %q", health)
			}
			e.Stop()
			if _, err := os.Stat(e.Database + ".restore"); err == nil {
				t.Fatal("the staging file remains")
			}
		})
	}
}
