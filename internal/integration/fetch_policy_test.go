// The Fetch policy version a running gateway stores.

package integration

import (
	"strings"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

func TestFetchStoredVersion3IsNotMigrated(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	policy := e.ProtectedPolicy()
	gatewaytest.Seed(t, e.Database, policy, gatewaytest.SeedOptions{})
	legacy := []byte(strings.Replace(string(gatewaytest.MustJSON(policy)), `"schema_version":4`, `"schema_version":3`, 1))
	db := gatewaytest.Inspect(t, e.Database)
	if _, err := db.Exec(`UPDATE revision SET document=?,checksum=? WHERE id=1`, legacy, store.DocumentChecksum(legacy)); err != nil {
		t.Fatal(err)
	}
	db.Close()
	e.Start(gatewaytest.Binaries.Plain)
	if e.Health() != "unavailable" || !strings.Contains(e.UnavailableReason(), "SCHEMA_VERSION_UNSUPPORTED") {
		t.Fatal("legacy policy was served")
	}
	if code, _ := e.Get("/a/x", gatewaytest.Bearer(t, "alice")...); code != 503 {
		t.Fatalf("legacy deployment admitted: %d", code)
	}
	e.AssertReceipts(0, 0, 0)
	e.Stop()
	if document := gatewaytest.QueryString(t, e.Database, `SELECT document FROM revision WHERE id=1`); document != string(legacy) {
		t.Fatal("legacy policy was silently converted")
	}
}
