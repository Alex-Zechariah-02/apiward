// A gateway process serving one policy: installed by the operator command, set up through the Admin API.

package migrate

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// startGateway installs a gateway that trusts the signer, establishes a
// deny-all genesis and puts the policy on trial, as an administrator
// would, and returns its data address.
func startGateway(t *testing.T, document []byte, s *signer) string {
	t.Helper()
	gateway, _ := binaries(t)
	dir := t.TempDir()
	keyFile, configFile := filepath.Join(dir, "issuer.pem"), filepath.Join(dir, "gateway.json")
	data, adminAddr := freeAddr(t), freeAddr(t)
	config := map[string]any{"version": 1,
		"gateway": map[string]any{"database": filepath.Join(dir, "state.db"), "audit_log": filepath.Join(dir, "audit.log"),
			"admin_listen": adminAddr, "metrics_listen": freeAddr(t),
			"jwt": map[string]any{"issuer": s.issuer, "audience": s.audience,
				"keys": []any{map[string]any{"kid": signerKey, "public_key_file": keyFile}}}},
		"data": map[string]any{"listen": data, "max_body_bytes": policy.MaxBodyLimit}}
	encoded, _ := json.Marshal(config)
	for path, content := range map[string][]byte{keyFile: s.publicPEM(), configFile: encoded} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	installed, err := exec.Command(gateway, "install", "--config", configFile, "--admin", "root").CombinedOutput()
	if err != nil {
		t.Fatalf("install: %v\n%s", err, installed)
	}
	start(t, gateway, []string{"run", "--config", configFile}, func(out string) bool {
		return strings.Contains(out, `"msg":"protected admission"`) && dialable(data) && dialable(adminAddr)
	})
	a := &admin{t: t, addr: adminAddr}
	password := "pw-" + randomKey()
	a.send(http.MethodPost, "/admin/enrol", map[string]string{"name": "root", "secret": enrolment(t, string(installed)), "password": password}, http.StatusCreated)
	a.send(http.MethodPost, "/admin/session", map[string]string{"name": "root", "password": password}, http.StatusCreated)
	first := a.stage(denyAll(t, document), `"r0"`)
	a.send(http.MethodPost, "/admin/genesis", first, http.StatusOK)
	header, _ := a.send(http.MethodGet, "/admin/policy", nil, http.StatusOK)
	revision := header.Get("ETag")
	trial := a.stage(json.RawMessage(document), revision)
	trial["confirm_within_seconds"] = 300
	a.send(http.MethodPost, "/admin/provisional", trial, http.StatusOK, "If-Match", revision, "Idempotency-Key", randomKey())
	return data
}

// stage stores a policy as a candidate and returns its ID and checksum.
func (a *admin) stage(document any, revision string) map[string]any {
	a.t.Helper()
	_, reply := a.send(http.MethodPost, "/admin/candidates", map[string]any{"policy": document}, http.StatusCreated,
		"If-Match", revision, "Idempotency-Key", randomKey())
	var staged struct {
		Candidate struct {
			ID       int64  `json:"id"`
			Checksum string `json:"checksum"`
		} `json:"candidate"`
	}
	if err := json.Unmarshal(reply, &staged); err != nil {
		a.t.Fatal(err)
	}
	return map[string]any{"candidate": staged.Candidate.ID, "checksum": staged.Candidate.Checksum}
}

// denyAll is the policy with every operation denied and no permits: the
// genesis the gateway accepts as its first revision.
func denyAll(t *testing.T, document []byte) policy.Policy {
	t.Helper()
	var p policy.Policy
	if err := json.Unmarshal(document, &p); err != nil {
		t.Fatal(err)
	}
	for i := range p.Operations {
		p.Operations[i].Access = "deny"
	}
	p.Permits = []policy.Permit{}
	return p
}

// enrolment reads the secret the install command printed.
func enrolment(t *testing.T, out string) string {
	t.Helper()
	for line := range strings.Lines(out) {
		if strings.HasPrefix(line, "enrolment secret for ") {
			return strings.TrimSpace(line[strings.LastIndex(line, ": ")+2:])
		}
	}
	t.Fatalf("no enrolment secret in %q", out)
	return ""
}

func randomKey() string {
	key := make([]byte, 16)
	rand.Read(key)
	return hex.EncodeToString(key)
}
