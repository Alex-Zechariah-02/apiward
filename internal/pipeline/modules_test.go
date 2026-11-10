// The module runner: fixed phase order, refusals, failures, panics and the
// record of each module's result, through the real handler and audit log.

package pipeline

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
	"github.com/Alex-Zechariah-02/apiward/module"
)

// probe is a test module: its member names what its check does.
type probe struct{ info module.Info }

var (
	ranMu sync.Mutex
	ran   []string
)

func (p probe) Info() module.Info { return p.info }

func (p probe) Compile(_ module.Operation, raw json.RawMessage) (module.Check, error) {
	var action string
	if p.info.Phase == module.Ingress {
		action = "pass"
	} else if raw == nil {
		return nil, nil
	} else if err := json.Unmarshal(raw, &action); err != nil {
		return nil, err
	}
	if action == "compile_panic" {
		panic("compile")
	}
	return probeCheck{id: p.info.ID, action: action}, nil
}

type probeCheck struct{ id, action string }

func (c probeCheck) Check(context.Context, *module.Request) module.Result {
	ranMu.Lock()
	ran = append(ran, c.id)
	ranMu.Unlock()
	switch c.action {
	case "refuse":
		return module.Refuse(http.StatusForbidden, "probe_refused")
	case "fail":
		return module.Fail("probe failed")
	case "panic":
		panic("check")
	case "zero":
		return module.Result{}
	}
	return module.Pass()
}

// Two modules per phase; registered in this test binary only.
func init() {
	for _, p := range []module.Phase{module.Ingress, module.Identity, module.Authorise, module.Traffic, module.Validate} {
		for _, suffix := range []string{"b", "a"} {
			module.Register(probe{module.Info{ID: p.String() + "_" + suffix, Phase: p, Version: "1.0.0"}})
		}
	}
}

type fixedAuthority struct{ g *compile.Generation }

func (f fixedAuthority) Current() *compile.Generation     { return f.g }
func (fixedAuthority) Expired(*compile.Generation)        {}
func (fixedAuthority) Verifier() *Verifier                { return nil }
func (fixedAuthority) Blocked() *store.BlockedAccounts    { return &store.BlockedAccounts{} }
func (fixedAuthority) Addresses() *store.BlockedAddresses { return nil }

// serve compiles a policy whose public endpoint GET /a/x has the given module
// members, sends one request and returns the answer, whether it was
// forwarded, and the request's final record.
func serve(t *testing.T, members map[string]string) (int, bool, map[string]any) {
	t.Helper()
	ranMu.Lock()
	ran = nil
	ranMu.Unlock()
	op := policy.Operation{ID: "x", API: "a", Method: "GET", Target: "/a/x", Access: "allow", Auth: "none", Modules: map[string]json.RawMessage{}}
	for id, action := range members {
		op.Modules[id], _ = json.Marshal(action)
	}
	g, err := compile.Compile(policy.Policy{
		SchemaVersion: policy.SchemaVersion, Profile: policy.ProfileCore,
		Upstreams: []policy.Upstream{{ID: "A", Dial: "127.0.0.1:9"}}, APIs: []policy.API{{ID: "a", Upstream: "A"}},
		Operations: []policy.Operation{op}, Roles: []policy.Role{{ID: "READER"}},
	}, 1, time.Time{}, policy.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.log")
	log := audit.OpenAudit(path, 1<<20, 4)
	forwarded := false
	h, err := New(Deps{Authority: fixedAuthority{g}, Audit: log, Observations: monitor.New(policy.DefaultWindow, policy.DefaultAPIs), Limiter: NewLimiter(policy.DefaultRateCounters), Clock: NewClock(), AuditTimeout: time.Second,
		Forward: func(w http.ResponseWriter, _ *http.Request) error {
			forwarded = true
			w.WriteHeader(http.StatusOK)
			return nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/a/x", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	h.ServeHTTP(rec, req)
	if err := log.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var last map[string]any
	for lines := bufio.NewScanner(file); lines.Scan(); {
		var e map[string]any
		if json.Unmarshal(lines.Bytes(), &e) == nil && e["request_id"] != nil {
			last = e
		}
	}
	return rec.Code, forwarded, last
}

// Modules run after the built-in stage of their phase, phase by phase and by
// ID within a phase; every one is recorded, and an unconfigured one reads NA.
func TestModuleOrder(t *testing.T) {
	code, forwarded, record := serve(t, map[string]string{"identity_a": "pass", "identity_b": "pass", "authorise_b": "pass", "traffic_a": "pass", "validate_a": "pass", "validate_b": "pass"})
	want := []string{"ingress_a", "ingress_b", "identity_a", "identity_b", "authorise_b", "traffic_a", "validate_a", "validate_b"}
	if code != http.StatusOK || !forwarded || !slices.Equal(ran, want) {
		t.Fatalf("answer %d, forwarded %v, ran %v, want %v", code, forwarded, ran, want)
	}
	modules, _ := record["modules"].(map[string]any)
	if record["schema"] != float64(7) || modules["authorise_a"] != "NA" || modules["traffic_b"] != "NA" || modules["identity_b"] != "PASS" || modules["ingress_a"] != "PASS" || len(modules) != 10 {
		t.Fatalf("record: %v", record)
	}
}

// A refusal answers with the module's status and code at its phase's stage;
// a failure, a panic or a zero result answers 503 and records FAIL with the
// module's ID; nothing is forwarded and later modules read NE.
func TestModuleFailures(t *testing.T) {
	for _, tc := range []struct {
		action, stage, result, errorText string
		status                           int
	}{
		{"refuse", "RBAC", "REJECT", "probe_refused", http.StatusForbidden},
		{"fail", "RBAC", "FAIL", "module authorise_a: probe failed", http.StatusServiceUnavailable},
		{"panic", "RBAC", "FAIL", "module authorise_a: panic", http.StatusServiceUnavailable},
		{"zero", "RBAC", "FAIL", "module authorise_a: no result", http.StatusServiceUnavailable},
	} {
		code, forwarded, record := serve(t, map[string]string{"authorise_a": tc.action, "authorise_b": "pass", "traffic_a": "pass"})
		stages, _ := record["stages"].(map[string]any)
		modules, _ := record["modules"].(map[string]any)
		if code != tc.status || forwarded || record["stage"] != tc.stage || stages[tc.stage] != tc.result || record["error"] != tc.errorText ||
			modules["authorise_a"] != tc.result || modules["authorise_b"] != "NE" || modules["traffic_a"] != "NE" {
			t.Errorf("%s: answer %d, forwarded %v, record %v", tc.action, code, forwarded, record)
		}
	}
	_, err := compile.Compile(policy.Policy{
		SchemaVersion: policy.SchemaVersion, Profile: policy.ProfileCore,
		Upstreams: []policy.Upstream{{ID: "A", Dial: "127.0.0.1:9"}}, APIs: []policy.API{{ID: "a", Upstream: "A"}},
		Operations: []policy.Operation{{ID: "x", API: "a", Method: "GET", Target: "/a/x", Access: "allow", Auth: "none", Modules: map[string]json.RawMessage{"validate_a": json.RawMessage(`"compile_panic"`)}}},
		Roles:      []policy.Role{{ID: "READER"}},
	}, 1, time.Time{}, policy.Limits{})
	if code := problemCode(err); code != "MODULE_FAILED operations[0].validate_a" {
		t.Errorf("panic in Compile: %v", err)
	}
}

// A member for a module this build has is read as its settings; any other
// unknown member, and a member for an Ingress module, is refused.
func TestModuleUnknownMember(t *testing.T) {
	document := func(member string) []byte {
		return []byte(`{"schema_version":4,"profile":"core","upstreams":[{"id":"A","dial":"127.0.0.1:9"}],"apis":[{"id":"a","upstream":"A"}],` +
			`"operations":[{"id":"x","api":"a","method":"GET","target":"/a/x","access":"allow","auth":"none",` + member + `}],"roles":[{"id":"READER"}],"permits":[]}`)
	}
	p, err := policy.DecodePolicy(document(`"identity_a":"pass"`), policy.Limits{})
	if err != nil || string(p.Operations[0].Modules["identity_a"]) != `"pass"` {
		t.Fatalf("registered member: %v %v", p.Operations, err)
	}
	if _, err := policy.DecodePolicy(document(`"missing_module":"pass"`), policy.Limits{}); problemCode(err) != "UNKNOWN_FIELD " {
		t.Errorf("unknown member: %v", err)
	}
	p, err = policy.DecodePolicy(document(`"ingress_a":"pass"`), policy.Limits{})
	if err == nil {
		_, err = compile.Compile(p, 1, time.Time{}, policy.Limits{})
	}
	if problemCode(err) != "UNKNOWN_FIELD operations[0].ingress_a" {
		t.Errorf("ingress member: %v", err)
	}
}

func problemCode(err error) string {
	var problem *policy.PolicyError
	if !errors.As(err, &problem) {
		return ""
	}
	return problem.Code + " " + problem.Field
}
