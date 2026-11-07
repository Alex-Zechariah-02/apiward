// Container tests: the same probes against Kong OSS itself, in a container on loopback, configured from the same fixture.

package migrate

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/convert/kong"
	"github.com/Alex-Zechariah-02/apiward/internal/probe"
)

// kongImage is the Kong release the decK rows are written for.
const kongImage = "kong:3.9.4"

// containers names the environment variable that enables container tests.
const containers = "APIWARD_CONTAINERS"

// startKong runs Kong in DB-less mode on the decK file, with the Admin API
// off, one worker (so local rate counters are one count) and its proxy
// published on loopback only, and returns the proxy address.
func startKong(t *testing.T, deck string) string {
	t.Helper()
	addr := freeAddr(t)
	name := "apiward-probe-" + randomKey()[:12]
	dir := filepath.Dir(deck)
	args := []string{"run", "-d", "--rm", "--name", name, "-p", addr + ":8000",
		"-e", "KONG_DATABASE=off", "-e", "KONG_DECLARATIVE_CONFIG=/kong/" + filepath.Base(deck),
		"-e", "KONG_PROXY_LISTEN=0.0.0.0:8000", "-e", "KONG_ADMIN_LISTEN=off", "-e", "KONG_NGINX_WORKER_PROCESSES=1",
		"-v", dir + ":/kong:ro", kongImage}
	if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		if t.Failed() {
			logs, _ := exec.Command("docker", "logs", "--tail", "40", name).CombinedOutput()
			t.Logf("kong logs:\n%s", logs)
		}
		exec.Command("docker", "rm", "-f", name).Run()
	})
	deadline := time.Now().Add(90 * time.Second)
	for {
		response, err := client.Get("http://" + addr + "/")
		if err == nil {
			response.Body.Close()
			return addr
		}
		if time.Now().After(deadline) {
			logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
			t.Fatalf("kong not ready: %v\n%s", err, logs)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// TestKongDocker sends the probes to Kong itself. Kong must decide as the
// reference evaluator models it (a method no route takes is Kong's 404),
// and the live gateway's differences from Kong must be ones the ledger
// predicts. It needs Docker and the Kong image, so it runs only when
// APIWARD_CONTAINERS holds "kong".
func TestKongDocker(t *testing.T) {
	if !strings.Contains(os.Getenv(containers), "kong") {
		t.Skip("container tests are off: set " + containers + "=kong to run them (needs Docker and " + kongImage + ")")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("docker not found: " + err.Error())
	}
	s, toKong, toGateway := newSigner(t), startUpstream(t), startUpstream(t)
	port := toKong.addr[strings.LastIndex(toKong.addr, ":")+1:]
	deck := kongFixture(t, "kong-probe.yaml", s, "http://host.docker.internal:"+port)
	m := migrateFile(t, kong.Format, deck, toGateway, "--decisions", decisionsFile(t, acceptCORS))
	kongRun := probeAll(t, target{format: kong.Format, addr: startKong(t, deck), up: toKong}, m.file, m.ops, s)
	modelled := reference(t, kongRoutes(t, deck).Routes, m.file, m.ops, kongRun.bursts)
	for _, p := range m.file.Probes {
		if verdict := probe.Judge(kongRun.classes[p.ID], modelled[p.ID], nil); verdict == probe.Unexpected {
			t.Errorf("%s: Kong decided %s, the reference evaluator %s", p.ID, kongRun.classes[p.ID], modelled[p.ID])
		}
	}
	gatewayRun := probeAll(t, target{format: probe.Gateway, addr: startGateway(t, m.policy, s), up: toGateway}, m.file, m.ops, s)
	compare(t, m.file, m.ledger, gatewayRun.classes, kongRun.classes)
}
