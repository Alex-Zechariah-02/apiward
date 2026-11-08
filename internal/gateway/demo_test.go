// The demo command: Fetch stack setup, start and stop with the native gateway.

package gateway

import (
	"cmp"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

// demoPortShift moves this package's demo stack above the span of the demo
// ports (9440-9605): the integration tests run the Fetch stack on the demo
// ports themselves, and the two test binaries may run at the same time.
const demoPortShift = 200

func TestNativeDemoCommands(t *testing.T) {
	offset, err := strconv.Atoi(cmp.Or(os.Getenv("EAT_PORT_OFFSET"), "0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("EAT_PORT_OFFSET", strconv.Itoa(offset+demoPortShift))
	parent := t.TempDir()
	web := filepath.Join(parent, "web")
	for _, page := range []string{"admin", "demo"} {
		dir := filepath.Join(web, page)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("owned test page"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	dir := filepath.Join(parent, "demo")
	args := []string{"setup", "-dir", dir, "-web", web, "-gateway", gatewaytest.Binaries.Plain, "-admin", "root"}
	output, code := gatewaytest.DemoCommand(t, args...)
	if code != 0 || gatewaytest.EnrolmentSecret(t, output) == "" {
		t.Fatalf("native demo setup exit %d", code)
	}
	if _, code := gatewaytest.DemoCommand(t, args...); code != 1 {
		t.Fatal("setup reused an existing directory")
	}
	data, err := os.ReadFile(filepath.Join(dir, "gateway.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeNativeFile(data); err != nil {
		t.Fatalf("generated configuration is not strict native JSON: %v", err)
	}
	for _, args := range [][]string{
		{"unknown"},
		{"token", "-dir", dir, "-subject", "has spaces"},
		{"token", "-dir", dir, "-subject", "cust-001", "-ttl", "0s"},
		{"token", "-dir", dir, "-subject", "cust-001", "-ttl", "2h"},
		{"reset", "-dir", parent},
		{"run", "-dir", dir},
		{"setup", "-dir", filepath.Join(parent, "failed"), "-web", web, "-gateway", filepath.Join(parent, "absent.exe")},
	} {
		if _, code := gatewaytest.DemoCommand(t, args...); code == 0 {
			t.Fatalf("invalid demo arguments accepted: %v", args)
		}
	}
	if _, err := os.Stat(filepath.Join(parent, "failed")); !os.IsNotExist(err) {
		t.Fatal("failed setup left its directory or signing key")
	}
	retained := `{"msg":"protected admission","admission":"ready","probe":"retained-test-record"}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "gateway.log"), []byte(retained), 0o600); err != nil {
		t.Fatal(err)
	}
	for round := range 2 {
		_, input, exited, output := gatewaytest.StartDemo(t, dir, web)
		if !strings.Contains(output.String(), "protected admission: bootstrap_locked") {
			t.Fatalf("listener startup mistaken for admission readiness: %s", output)
		}
		tokenOutput, code := gatewaytest.DemoCommand(t, "token", "-dir", dir, "-subject", "cust-001")
		if code != 0 {
			t.Fatal("demo token failed")
		}
		token := strings.SplitN(tokenOutput, "\n", 2)[0]
		e := &gatewaytest.Env{T: t, DataAddr: gatewaytest.DemoTestAddress(t, "127.0.0.2:9480"), Admin: gatewaytest.DemoTestAddress(t, "127.0.0.1:9440")}
		if code, _ := e.Get("/orders", "Authorization", "Bearer "+token); code != http.StatusServiceUnavailable {
			t.Fatalf("bootstrap data plane returned %d", code)
		}
		if _, code := gatewaytest.DemoCommand(t, "reset", "-dir", dir); code != 0 {
			t.Fatal("identified fixture reset failed")
		}
		if output, code := gatewaytest.DemoCommand(t, "events", "-dir", dir, "-last", "2"); code != 0 || !strings.Contains(output, "rotated files were not searched") {
			t.Fatal("events command did not disclose its history boundary")
		}
		input.Close()
		select {
		case err := <-exited:
			if err != nil {
				t.Fatalf("demo graceful exit: %v: %s", err, output)
			}
		case <-time.After(15 * time.Second):
			t.Fatal("demo did not reap its children")
		}
		for _, addr := range []string{"127.0.0.1:9440", "127.0.0.2:9480", "127.0.0.1:9501", "127.0.0.1:9502", "127.0.0.1:9503", "127.0.0.1:9601", "127.0.0.1:9602", "127.0.0.1:9603", "127.0.0.1:9504", "127.0.0.1:9505", "127.0.0.1:9604", "127.0.0.1:9605", "127.0.0.1:9450", "127.0.0.1:9506"} {
			addr = gatewaytest.DemoTestAddress(t, addr)
			if gatewaytest.Dialable(addr) {
				t.Fatalf("demo round %d leaked listener %s", round, addr)
			}
		}
		log, err := os.ReadFile(filepath.Join(dir, "gateway.log"))
		if err != nil || !strings.Contains(string(log), `"msg":"stopped"`) || !strings.Contains(string(log), retained) || strings.Contains(string(log), token) {
			t.Fatal("native gateway did not stop cleanly, or disclosed a token")
		}
	}
	// A gateway crash must stop the launcher and its remaining service children.
	_, input, exited, runOutput := gatewaytest.StartDemo(t, dir, web)
	for line := range strings.Lines(runOutput.String()) {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "gateway" && fields[1] == "process" {
			pid, err := strconv.Atoi(fields[2])
			if err != nil {
				t.Fatal(err)
			}
			process, err := os.FindProcess(pid)
			if err != nil {
				t.Fatal(err)
			}
			if err := process.Kill(); err != nil {
				t.Fatal(err)
			}
		}
	}
	select {
	case err := <-exited:
		if err == nil {
			t.Fatal("gateway crash was reported as a clean demonstration exit")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("gateway crash did not stop the demonstration")
	}
	input.Close()
	for _, addr := range []string{"127.0.0.1:9440", "127.0.0.2:9480", "127.0.0.1:9501", "127.0.0.1:9502", "127.0.0.1:9503", "127.0.0.1:9601", "127.0.0.1:9602", "127.0.0.1:9603", "127.0.0.1:9504", "127.0.0.1:9505", "127.0.0.1:9604", "127.0.0.1:9605", "127.0.0.1:9450", "127.0.0.1:9506"} {
		addr = gatewaytest.DemoTestAddress(t, addr)
		if gatewaytest.Dialable(addr) {
			t.Fatalf("crashed demo leaked listener %s", addr)
		}
	}
	if _, code := gatewaytest.DemoCommand(t, "run", "-dir", dir, "-gateway", filepath.Join(parent, "absent.exe"), "-services", gatewaytest.Binaries.Services, "-accounts", gatewaytest.Binaries.Accounts); code != 1 {
		t.Fatal("partial demo startup did not report a failure")
	}
	for _, addr := range []string{"127.0.0.1:9501", "127.0.0.1:9502", "127.0.0.1:9503", "127.0.0.1:9601", "127.0.0.1:9602", "127.0.0.1:9603", "127.0.0.1:9504", "127.0.0.1:9505", "127.0.0.1:9604", "127.0.0.1:9605", "127.0.0.1:9450", "127.0.0.1:9506"} {
		addr = gatewaytest.DemoTestAddress(t, addr)
		if gatewaytest.Dialable(addr) {
			t.Fatalf("partial startup leaked fixture listener %s", addr)
		}
	}
	before := gatewaytest.FileSHA256(t, filepath.Join(dir, "state.db"))
	if err := os.WriteFile(filepath.Join(dir, "caddy.json"), []byte(`{"apps":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, code := gatewaytest.DemoCommand(t, "reset", "-dir", dir); code != 1 {
		t.Fatal("stale Caddy demo was accepted")
	}
	if gatewaytest.FileSHA256(t, filepath.Join(dir, "state.db")) != before {
		t.Fatal("rejected demo operation changed SQLite state")
	}
}
