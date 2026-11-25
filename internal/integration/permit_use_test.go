// Permission-use tracking in SQLite and bounded 30-day U1 advice tests.

package integration

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

type adviceReply struct {
	Rules         string `json:"rules"`
	UnusedPermits struct {
		Requests    int     `json:"requests"`
		Since       *string `json:"since"`
		WindowDays  int     `json:"window_days"`
		Withheld    *string `json:"withheld"`
		MinMinutes  int     `json:"min_minutes"`
		MinRequests int     `json:"min_requests"`
		Items       []struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
			Object   string `json:"object"`
		} `json:"items"`
	} `json:"unused_permits"`
}

func getAdvice(t *testing.T, e *gatewaytest.Env, admin gatewaytest.AdminSession) (adviceReply, map[string]any) {
	t.Helper()
	code, body, _ := e.As(admin, http.MethodGet, "/admin/advice", "")
	if code != http.StatusOK {
		t.Fatalf("GET /admin/advice: %d %s", code, body)
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(body), &raw); err != nil {
		t.Fatal(err)
	}
	return fromJSON[adviceReply](t, body), raw
}

func seedPermitWindow(t *testing.T, dbPath string, since time.Time, requests int) {
	t.Helper()
	db, err := sql.Open("sqlite", store.DatabaseURI(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO permit_use_window (id, since, requests) VALUES (1, ?, ?)
		ON CONFLICT(id) DO UPDATE SET since = excluded.since, requests = excluded.requests`,
		since.UnixMilli(), requests); err != nil {
		t.Fatalf("seed permit_use_window: %v", err)
	}
}

func TestPermitUseTracksAdmittedPairs(t *testing.T) {
	t.Parallel()
	e := gatewaytest.NewEnv(t)
	e.Interruptible = true
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)

	token := gatewaytest.Issuer.TokenFor(t, "alice")
	if code, body := e.Get("/a/x", "Authorization", "Bearer "+token); code != http.StatusOK {
		t.Fatalf("GET /a/x: %d %s", code, body)
	}
	if code, _ := e.Request(http.MethodPost, "/a/item", "application/json", `{"n":1}`, "Authorization", "Bearer "+gatewaytest.Issuer.TokenFor(t, "bob")); code != http.StatusForbidden {
		t.Fatalf("POST /a/item as bob: %d, want 403", code)
	}

	admin := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
	rep, raw := getAdvice(t, e, admin)
	if rep.UnusedPermits.WindowDays != 30 {
		t.Fatalf("window_days = %d, want 30", rep.UnusedPermits.WindowDays)
	}
	if rep.UnusedPermits.Requests != 1 {
		t.Fatalf("requests = %d, want 1 admitted request", rep.UnusedPermits.Requests)
	}
	up := raw["unused_permits"].(map[string]any)
	for _, removed := range []string{"complete", "files_searched", "files_missing"} {
		if _, exists := up[removed]; exists {
			t.Fatalf("removed member %q still present in unused_permits", removed)
		}
	}
}

func TestPermitUseSurvivesRestart(t *testing.T) {
	t.Parallel()
	e := gatewaytest.NewEnv(t)
	e.Interruptible = true
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	seedPermitWindow(t, e.Database, time.Now().Add(-2*time.Hour), 500)
	e.Start(gatewaytest.Binaries.Plain)

	if code, body := e.Get("/a/x", "Authorization", "Bearer "+gatewaytest.Issuer.TokenFor(t, "bob")); code != http.StatusOK {
		t.Fatalf("GET /a/x: %d %s", code, body)
	}
	e.Shutdown()

	e.Start(gatewaytest.Binaries.Plain)
	admin := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
	rep, _ := getAdvice(t, e, admin)
	if rep.UnusedPermits.Withheld != nil {
		t.Fatalf("withheld = %q, want nil", *rep.UnusedPermits.Withheld)
	}
	if rep.UnusedPermits.Requests < 501 {
		t.Fatalf("requests = %d, want >= 501 after restart", rep.UnusedPermits.Requests)
	}
	var sawUnusedWrite bool
	for _, item := range rep.UnusedPermits.Items {
		if item.ID != "U1" {
			continue
		}
		if strings.Contains(item.Object, "READER") && strings.Contains(item.Object, "read-a") {
			t.Fatalf("READER -> read-a reported unused after restart: %+v", item)
		}
		if strings.Contains(item.Object, "WRITER") && strings.Contains(item.Object, "write-a") {
			sawUnusedWrite = true
		}
	}
	if !sawUnusedWrite {
		t.Fatalf("WRITER -> write-a missing from U1 items: %+v", rep.UnusedPermits.Items)
	}
}

func TestUnusedPermitsBeyondLogScan(t *testing.T) {
	t.Parallel()
	e := gatewaytest.NewEnv(t)
	e.Interruptible = true
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	seedPermitWindow(t, e.Database, time.Now().Add(-2*time.Hour), 600)

	// Create sparse rotated security log files exceeding monitor.ExportScan (256 MiB).
	dir := filepath.Dir(e.AuditLog)
	for i := range 5 {
		p := filepath.Join(dir, "audit-2026-11-25T00-00-0"+string(rune('1'+i))+".000.log")
		f, err := os.Create(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate((monitor.ExportScan / 4) + 1<<20); err != nil {
			f.Close()
			t.Fatal(err)
		}
		f.Close()
	}

	e.Start(gatewaytest.Binaries.Plain)
	admin := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
	rep, _ := getAdvice(t, e, admin)
	if rep.UnusedPermits.Withheld != nil {
		t.Fatalf("U1 withheld despite >256 MiB retained log: %q", *rep.UnusedPermits.Withheld)
	}
	if len(rep.UnusedPermits.Items) == 0 {
		t.Fatalf("expected U1 items, got none")
	}
}
