// Differential tests: Kong and OpenAPI fixtures through migrate import, probes and policy, against the live gateway.

package migrate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/convert/kong"
	"github.com/Alex-Zechariah-02/apiward/internal/exchange"
	"github.com/Alex-Zechariah-02/apiward/internal/openapi"
	"github.com/Alex-Zechariah-02/apiward/internal/probe"
)

// migration is a source file taken through the commands: the exchange
// file, its probes and the policy migrate policy wrote with --with-permits.
type migration struct {
	document map[string]any
	ledger   *exchange.Ledger
	file     *probe.File
	ops      map[string]probe.Operation
	policy   []byte
}

// migrate runs import, probes and policy on a source file; the policy's
// upstream is the recording upstream.
func migrateFile(t *testing.T, format, source string, up *upstream, extra ...string) migration {
	t.Helper()
	dir := t.TempDir()
	exchangePath, probesPath := filepath.Join(dir, "exchange.json"), filepath.Join(dir, "probes.json")
	if code, stderr := run(append([]string{"import", "--from", format, "--in", source, "--out", exchangePath,
		"--report", filepath.Join(dir, "import.json")}, extra...)...); code == openapi.ExitFailed {
		t.Fatalf("import: %s", stderr)
	}
	if code, stderr := run("probes", "--exchange", exchangePath, "--out", probesPath); code != openapi.ExitComplete {
		t.Fatalf("probes exit %d: %s", code, stderr)
	}
	p := base()
	p.Upstreams[0].Dial = up.addr
	code, stderr, policyPath, _ := migrated(t, exchangePath, p, "--with-permits")
	if code == openapi.ExitFailed {
		t.Fatalf("policy: %s", stderr)
	}
	m := migration{ops: map[string]probe.Operation{}}
	_, root, _, err := readDocument(exchangePath, "exchange")
	if err != nil {
		t.Fatal(err)
	}
	if m.document, m.ledger, err = exchange.Split(root); err != nil {
		t.Fatal(err)
	}
	ops, err := probe.Operations(m.document, m.ledger, probe.Options{MaxBodyBytes: openapi.DefaultBodyBytes})
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range ops {
		m.ops[o.ID] = o
	}
	m.file = &probe.File{}
	data, _ := os.ReadFile(probesPath)
	if err := json.Unmarshal(data, m.file); err != nil {
		t.Fatal(err)
	}
	m.policy, _ = os.ReadFile(policyPath)
	return m
}

// kongFixture writes a decK fixture of testdata with the run's issuer, key
// and upstream URL filled in.
func kongFixture(t *testing.T, name string, s *signer, upstreamURL string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	filled := strings.NewReplacer("{{issuer}}", s.issuer, "{{upstream}}", upstreamURL,
		`"{{public_key}}"`, strconv.Quote(string(s.publicPEM()))).Replace(string(data))
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(filled), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// kongRoutes reads the Kong routes behind each operation of a decK file.
func kongRoutes(t *testing.T, path string) *kong.Result {
	t.Helper()
	data, root, _, err := readDocument(path, "in")
	if err != nil {
		t.Fatal(err)
	}
	result, err := kong.Read(root, data)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// acceptCORS accepts the browser access of the Kong probe fixture, looser
// than Kong's on its routes that do not take OPTIONS.
const acceptCORS = `{"target": "$['x-apiward-migration'].items[?@.id=='kong-deck:plugin:service.shop:cors']",
	"update": {"accepted": true, "direction": "looser"}}`

// TestDifferentialKong compares the gateway running the migrated policy
// with Kong's decisions as the reference evaluator models them: every
// difference must be one its ledger item predicts.
func TestDifferentialKong(t *testing.T) {
	s, up := newSigner(t), startUpstream(t)
	deck := kongFixture(t, "kong-probe.yaml", s, "http://"+up.addr)
	m := migrateFile(t, kong.Format, deck, up, "--decisions", decisionsFile(t, acceptCORS))
	addr := startGateway(t, m.policy, s)
	run := probeAll(t, target{format: probe.Gateway, addr: addr, up: up}, m.file, m.ops, s)
	compare(t, m.file, m.ledger, run.classes, reference(t, kongRoutes(t, deck).Routes, m.file, m.ops, run.bursts))
}

// TestDifferentialOpenAPI compares the gateway running the policy imported
// from a description with what the description states; the templated
// operation's looser item is accepted by a decision.
func TestDifferentialOpenAPI(t *testing.T) {
	s, up := newSigner(t), startUpstream(t)
	source := filepath.Join("testdata", "openapi-probe.json")
	accept := decisionsFile(t, `{"target": "$['x-apiward-migration'].items[?@.id=='openapi:operation:GET /items/{id}']",
		"update": {"accepted": true, "direction": "looser"}}`)
	m := migrateFile(t, "openapi", source, up, "--decisions", accept)
	addr := startGateway(t, m.policy, s)
	run := probeAll(t, target{format: probe.Gateway, addr: addr, up: up}, m.file, m.ops, s)
	_, root, _, err := readDocument(source, "in")
	if err != nil {
		t.Fatal(err)
	}
	routes, err := openapiRoutes(root)
	if err != nil {
		t.Fatal(err)
	}
	compare(t, m.file, m.ledger, run.classes, reference(t, routes, m.file, m.ops, run.bursts))
}
