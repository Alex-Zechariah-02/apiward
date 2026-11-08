// Operator commands with literal database and backup paths.

package integration

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

func TestOperatorLiteralDatabaseAndBackupPaths(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	e.Database = filepath.Join(e.Dir, "state%20#literal.db")
	e.WriteConfig(gatewaytest.ConfigOptions{})
	out, code := e.RunOperator(gatewaytest.Binaries.Plain, nil, "install", "--admin", "root")
	if code != 0 {
		t.Fatalf("install at a literal path: %d %s", code, out)
	}
	if info, err := os.Stat(e.Database); err != nil || info.Size() == 0 {
		t.Fatalf("the configured database file was not populated: %v", err)
	}
	e.Start(gatewaytest.Binaries.Plain)
	if code, body := enrol(e, "root", gatewaytest.EnrolmentSecret(t, out), testPassword()); code != http.StatusCreated {
		t.Fatalf("enrol at a literal path: %d %s", code, body)
	}
	e.Stop()
	backup := filepath.Join(e.Dir, "backup%20#literal.db")
	if out, code := e.RunOperator(gatewaytest.Binaries.Plain, nil, "backup", "--output", backup); code != 0 {
		t.Fatalf("backup at a literal path: %d %s", code, out)
	}
	if out, code := e.RunOperator(gatewaytest.Binaries.Plain, nil, "restore", "--backup", backup); code != 0 {
		t.Fatalf("restore at a literal path: %d %s", code, out)
	}
	e.Start(gatewaytest.Binaries.Plain)
	if mode := e.Health(); mode != store.ModeRecovery {
		t.Fatalf("restored mode %q, want recovery_required", mode)
	}
}
