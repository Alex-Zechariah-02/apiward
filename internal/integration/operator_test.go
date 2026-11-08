// Operator commands of the native gateway: arguments, paths and deployment
// ownership.

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

func TestNativeOperatorArguments(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	e.WriteNative(e.NativeSettings())
	legacy := filepath.Join(e.Dir, "caddy.json")
	if err := os.WriteFile(legacy, legacyCaddyFile(e), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		nil,
		{"unknown"},
		{"install"},
		{"install", "--config", e.Config},
		{"enrol", "--config", e.Config, "--admin", "root"},
		{"backup", "--config", e.Config},
		{"restore", "--config", e.Config},
		{"migrate", "--config", e.Config, "extra"},
		{"install", "--config", e.Config, "--admin", "root", "--unknown", "x"},
		{"install", "--config", e.Config, "--config", e.Config, "--admin", "root"},
		{"install", "--config", e.Config, "--admin", "root", "--admin", "other"},
		{"install", "--config", legacy, "--admin", "root"},
	} {
		cmd := exec.Command(gatewaytest.Binaries.Plain, args...)
		out, err := cmd.CombinedOutput()
		if err == nil || cmd.ProcessState.ExitCode() != 1 || len(out) == 0 {
			t.Fatalf("arguments %v: exit %v, output %s", args, err, out)
		}
		if _, err := os.Stat(e.Database); !os.IsNotExist(err) {
			t.Fatalf("invalid arguments created the database: %v", args)
		}
		t.Logf("%v: exit 1, database absent", args)
	}
}

func TestNativeOperatorPaths(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	before := gatewaytest.FileSHA256(t, e.Database)
	for _, output := range []string{
		e.Database, e.AuditLog, e.PublicKey, e.Config,
		e.Database + ".lock",
		filepath.Join(e.Dir, "missing", "backup.db"),
	} {
		if out, code := e.RunOperator(gatewaytest.Binaries.Plain, nil, "backup", "--output", output); code != 1 {
			t.Fatalf("unsafe backup destination %s: exit %d: %s", output, code, out)
		}
		if gatewaytest.FileSHA256(t, e.Database) != before {
			t.Fatal("refused backup changed the live database")
		}
	}
	output := filepath.Join(e.Dir, "unsafe-partial.db")
	if err := os.Link(e.Database, output+".partial"); err != nil {
		t.Fatal(err)
	}
	if out, code := e.RunOperator(gatewaytest.Binaries.Plain, nil, "backup", "--output", output); code != 1 {
		t.Fatalf("live database substituted as a backup partial: %d %s", code, out)
	}
	if gatewaytest.FileSHA256(t, e.Database) != before {
		t.Fatal("path substitution changed live authority")
	}
	unknown := filepath.Join(e.Dir, "unknown.db.partial")
	if err := os.WriteFile(unknown, []byte("unrelated file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, code := e.RunOperator(gatewaytest.Binaries.Plain, nil, "backup", "--output", filepath.Join(e.Dir, "unknown.db")); code != 1 {
		t.Fatalf("unknown temporary file was accepted: %d %s", code, out)
	}
	if data, err := os.ReadFile(unknown); err != nil || string(data) != "unrelated file" {
		t.Fatal("unrelated temporary file was changed")
	}
}

func TestNativeOperatorOwnership(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	lock, err := store.LockDeployment(e.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	before := gatewaytest.FileSHA256(t, e.Database)
	for _, tc := range []struct {
		command string
		args    []string
	}{
		{"backup", []string{"--output", filepath.Join(e.Dir, "held.db")}},
		{"migrate", nil},
		{"enrol", []string{"--admin", "root", "--permissions", "read"}},
	} {
		if out, code := e.RunOperator(gatewaytest.Binaries.Plain, nil, tc.command, tc.args...); code != 1 {
			t.Fatalf("operator entered an owned deployment: %d %s", code, out)
		}
	}
	if gatewaytest.FileSHA256(t, e.Database) != before {
		t.Fatal("ownership refusals changed the database")
	}
	if _, err := os.Stat(e.AuditLog); !os.IsNotExist(err) {
		t.Fatal("refused operator opened a second audit writer")
	}
}
