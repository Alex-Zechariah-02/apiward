// Backup helpers, backup with WAL and backup refusals.

package integration

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// writeBackup runs the backup command and returns the backup's manifest.
func writeBackup(e *gatewaytest.Env, output string) manifestFile {
	e.T.Helper()
	out, code := e.RunOperator(gatewaytest.Binaries.Plain, nil, "backup", "--output", output)
	if code != 0 {
		e.T.Fatalf("backup exited %d: %s", code, out)
	}
	data, err := os.ReadFile(manifestOf(output))
	if err != nil {
		e.T.Fatal(err)
	}
	return fromJSON[manifestFile](e.T, string(data))
}

// recoverAdministrator enrols root on a stopped gateway, starts it and logs
// root in with every permission.
func recoverAdministrator(e *gatewaytest.Env) gatewaytest.AdminSession {
	e.T.Helper()
	e.Stop()
	out, code := e.RunOperator(gatewaytest.Binaries.Plain, nil, "enrol", "--admin", "root", "--permissions", "read,read_history,manage_subjects,manage_policy")
	if code != 0 {
		e.T.Fatalf("enrol exited %d: %s", code, out)
	}
	e.Start(gatewaytest.Binaries.Plain)
	password := testPassword()
	if code, body := enrol(e, "root", gatewaytest.EnrolmentSecret(e.T, out), password); code != http.StatusCreated {
		e.T.Fatalf("enrolment: %d %s", code, body)
	}
	return e.MustLogin("root", password)
}

// establishRecoveryBase stages a deny-all candidate and confirms it as the
// recovery base.
func establishRecoveryBase(e *gatewaytest.Env, s gatewaytest.AdminSession) controller.Outcome {
	e.T.Helper()
	code, staged, body := e.Stage(s, denyAllPolicy(e), `"r0"`, "recovery-deny-all")
	if code != http.StatusCreated || staged.Candidate.Parent != 0 || !staged.Candidate.DenyAll {
		e.T.Fatalf("staging the recovery base: %d %s", code, body)
	}
	code, outcome := establish(e, s, "/admin/recovery-base", staged.Candidate.ID, staged.Candidate.Checksum)
	if code != http.StatusOK || !strings.HasPrefix(outcome.Transition, "recovery:") {
		e.T.Fatalf("recovery base: %d %+v", code, outcome)
	}
	return outcome
}

func historyItems(e *gatewaytest.Env, s gatewaytest.AdminSession) []store.HistoryEntry {
	e.T.Helper()
	code, body, _ := e.As(s, http.MethodGet, "/admin/history?limit=100", "")
	if code != http.StatusOK {
		e.T.Fatalf("history: %d %s", code, body)
	}
	return fromJSON[struct {
		Items []store.HistoryEntry `json:"items"`
	}](e.T, body).Items
}

// A backup taken after the gateway stopped abruptly includes the
// changes still in the write-ahead log, and restores in an isolated location
// into a recovery that keeps the history and trusts nothing restored.
func TestBackupIncludesWALAndRestoresElsewhere(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	confirmPolicy(e, e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword), withoutRole(e.ProtectedPolicy(), "WRITER"), 1, "change-before-backup")
	e.Stop()

	// The change is only in the write-ahead log: the main file alone lacks it.
	info, err := os.Stat(e.Database + "-wal")
	if err != nil || info.Size() == 0 {
		t.Fatalf("no write-ahead log after the abrupt stop: %v", err)
	}
	mainOnly := filepath.Join(t.TempDir(), "main-only.db")
	copyFile(t, e.Database, mainOnly)
	if n := gatewaytest.QueryInt(t, mainOnly, `SELECT COUNT(*) FROM revision`); n != 1 {
		t.Fatalf("the main file alone holds %d revisions; the test needs the change to be in the log only", n)
	}

	output := filepath.Join(e.Dir, "backup.db")
	manifest := writeBackup(e, output)
	if manifest.Revision != 2 || manifest.Mode != store.ModeNormal || manifest.SchemaVersion != store.DatabaseVersion || manifest.Format != backupFormatName {
		t.Fatalf("manifest %+v", manifest)
	}
	if manifest.SHA256 != gatewaytest.FileSHA256(t, output) || manifest.Installation != gatewaytest.QueryString(t, e.Database, `SELECT installation FROM deployment`) {
		t.Fatalf("manifest does not describe the backup: %+v", manifest)
	}
	if n := gatewaytest.QueryInt(t, output, `SELECT COUNT(*) FROM revision`); n != 2 {
		t.Fatalf("backup holds %d revisions, want 2", n)
	}
	if mode := gatewaytest.QueryString(t, output, `PRAGMA journal_mode`); mode != "delete" {
		t.Fatalf("backup journal mode %q", mode)
	}
	if _, err := os.Stat(output + ".partial"); err == nil {
		t.Fatal("the temporary backup file remains")
	}
	backupHash := gatewaytest.FileSHA256(t, output)
	backups := 0
	for _, ev := range e.AuditEvents() {
		if ev["kind"] == "operator.backup" && ev["actor"] == "operator" && ev["revision"] == float64(2) {
			backups++
		}
	}
	if backups != 1 {
		t.Fatalf("%d operator.backup events", backups)
	}

	// Restore into a separate deployment.
	other := gatewaytest.NewEnv(t)
	out, code := other.RunOperator(gatewaytest.Binaries.Plain, nil, "restore", "--backup", output)
	if code != 0 || !strings.Contains(out, "recovery_required") {
		t.Fatalf("restore exited %d: %s", code, out)
	}
	if gatewaytest.FileSHA256(t, output) != backupHash {
		t.Fatal("restore changed the backup")
	}
	for query, want := range map[string]int{
		`SELECT COUNT(*) FROM revision`:                                                           2,
		`SELECT COUNT(*) FROM administrator WHERE status = 'active'`:                              0,
		`SELECT COUNT(*) FROM administrator WHERE status = 'quarantined'`:                         1,
		`SELECT COUNT(*) FROM enrolment`:                                                          0,
		`SELECT COUNT(*) FROM deployment WHERE mode = 'recovery_required'`:                        1,
		`SELECT COUNT(*) FROM transition WHERE kind = 'operator.restore'`:                         1,
		`SELECT COUNT(*) FROM transition WHERE id = 'admin:harness:confirm-change-before-backup'`: 1,
	} {
		if n := gatewaytest.QueryInt(t, other.Database, query); n != want {
			t.Errorf("%s = %d, want %d", query, n, want)
		}
	}

	other.Start(gatewaytest.Binaries.Plain)
	if health := other.Health(); health != store.ModeRecovery {
		t.Fatalf("health %q", health)
	}
	carol := gatewaytest.Issuer.TokenFor(t, "carol")
	if code, _ := other.Get("/a/x", "Authorization", "Bearer "+carol); code != http.StatusServiceUnavailable {
		t.Fatalf("restored subject before the recovery base: %d", code)
	}
	if _, code := other.Login(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword); code != http.StatusUnauthorized {
		t.Fatalf("restored administrator logs in: %d", code)
	}

	root := recoverAdministrator(other)
	found := false
	for _, entry := range historyItems(other, root) {
		found = found || (entry.ID == "admin:harness:confirm-change-before-backup" && entry.Revision == 2 && entry.Actor == gatewaytest.HarnessAdmin)
	}
	if !found {
		t.Fatal("the change that was in the write-ahead log is missing from the restored history")
	}
	recovered := establishRecoveryBase(other, root)
	if recovered.Revision != 3 || other.Health() != store.ModeNormal {
		t.Fatalf("recovery base %+v", recovered)
	}
	if code, _ := other.Get("/a/x", "Authorization", "Bearer "+carol); code != http.StatusForbidden {
		t.Fatalf("restored subject after the deny-all recovery base: %d", code)
	}
	other.AssertReceipts(0, 0, 0)
	other.Stop()
	if origin := gatewaytest.QueryString(t, other.Database, `SELECT origin FROM revision WHERE id = 3`); origin != "recovery_base" {
		t.Fatalf("recovery base origin %q", origin)
	}
}

// An existing output is never replaced, and an interrupted or
// failed backup leaves no file that looks complete.
func TestBackupRefusalsAndInterruption(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	liveRevisions := gatewaytest.QueryInt(t, e.Database, `SELECT COUNT(*) FROM revision`)

	existing := filepath.Join(e.Dir, "existing.db")
	if err := os.WriteFile(existing, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, code := e.RunOperator(gatewaytest.Binaries.Plain, nil, "backup", "--output", existing); code == 0 || !strings.Contains(out, "already exists") {
		t.Fatalf("backup over an existing file: %d %s", code, out)
	}
	if data, err := os.ReadFile(existing); err != nil || string(data) != "keep me" {
		t.Fatal("the existing file was changed")
	}

	unwritable := filepath.Join(e.Dir, "no-such-directory", "backup.db")
	if out, code := e.RunOperator(gatewaytest.Binaries.Plain, nil, "backup", "--output", unwritable); code == 0 {
		t.Fatalf("backup into a missing directory: %s", out)
	}
	if _, err := os.Stat(manifestOf(unwritable)); err == nil {
		t.Fatal("a failed backup wrote a manifest")
	}

	interrupted := filepath.Join(e.Dir, "interrupted.db")
	if _, code := e.RunOperator(gatewaytest.Binaries.Fault, []string{"GATEWAY_FAULT=backup-before-verify"}, "backup", "--output", interrupted); code != crashExit {
		t.Fatalf("interrupted backup exit code %d", code)
	}
	for path, present := range map[string]bool{interrupted + ".partial": true, interrupted: false, manifestOf(interrupted): false} {
		if _, err := os.Stat(path); (err == nil) != present {
			t.Errorf("%s present = %v, want %v", filepath.Base(path), err == nil, present)
		}
	}
	// A restore of the incomplete backup is refused, and backing up again
	// replaces the stale temporary file.
	if out, code := e.RunOperator(gatewaytest.Binaries.Plain, nil, "restore", "--backup", interrupted); code == 0 {
		t.Fatalf("restore of an interrupted backup: %s", out)
	}
	manifest := writeBackup(e, interrupted)
	if manifest.SHA256 != gatewaytest.FileSHA256(t, interrupted) {
		t.Fatal("the repeated backup does not match its manifest")
	}
	if _, err := os.Stat(interrupted + ".partial"); err == nil {
		t.Fatal("the stale temporary file remains")
	}

	if n := gatewaytest.QueryInt(t, e.Database, `SELECT COUNT(*) FROM revision`); n != liveRevisions {
		t.Fatalf("live database revisions %d, want %d", n, liveRevisions)
	}
	if mode := gatewaytest.QueryString(t, e.Database, `SELECT mode FROM deployment`); mode != store.ModeNormal {
		t.Fatalf("live mode %q", mode)
	}
	e.Start(gatewaytest.Binaries.Plain)
	if code, _ := e.Get("/a/x", "Authorization", "Bearer "+gatewaytest.Issuer.TokenFor(t, "alice")); code != http.StatusOK {
		t.Fatalf("live gateway after the backup failures: %d", code)
	}
}

// manifestFile is the manifest a backup writes beside itself, as the restore
// command and an operator read it.
type manifestFile struct {
	Format        string    `json:"format"`
	Installation  string    `json:"installation"`
	SchemaVersion int       `json:"schema_version"`
	Mode          string    `json:"mode"`
	Revision      int64     `json:"confirmed_revision"`
	CreatedAt     time.Time `json:"created_at"`
	SHA256        string    `json:"sha256"`
	Bytes         int64     `json:"bytes"`
}

// backupFormatName names the manifest format.
const backupFormatName = "gateway-backup-1"

// manifestOf is the manifest path of the backup at path.
func manifestOf(backup string) string { return backup + ".manifest.json" }
