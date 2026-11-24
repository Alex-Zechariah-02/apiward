// Bounded audit chain metrics and signed checkpoint reporting on /admin/status.

package integration

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

func scrapeMetrics(t *testing.T, addr string) string {
	t.Helper()
	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatalf("scrape /metrics: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /metrics: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/metrics status %d: %s", resp.StatusCode, body)
	}
	return string(body)
}

func metricValue(t *testing.T, text, name string) (float64, bool) {
	t.Helper()
	for line := range strings.SplitSeq(text, "\n") {
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == name {
			v, err := strconv.ParseFloat(fields[1], 64)
			if err != nil {
				t.Fatalf("parse %s=%q: %v", name, fields[1], err)
			}
			return v, true
		}
	}
	return 0, false
}

// Two scrapes around a write emit no sha256= label and no chain-head gauge,
// while gateway_audit_chain_batches_total rises with synced batches.
func TestMetricsCarryNoChainHead(t *testing.T) {
	t.Parallel()
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)

	before := scrapeMetrics(t, e.Metrics)
	if strings.Contains(before, "apiward_audit_chain_head_info") || strings.Contains(before, "sha256=") {
		t.Fatalf("first scrape exposes chain head label:\n%s", before)
	}
	batchesBefore, ok := metricValue(t, before, "gateway_audit_chain_batches_total")
	if !ok {
		t.Fatalf("gateway_audit_chain_batches_total missing in first scrape:\n%s", before)
	}
	if cpTime, ok := metricValue(t, before, "gateway_audit_last_checkpoint_timestamp_seconds"); !ok || cpTime != 0 {
		t.Fatalf("gateway_audit_last_checkpoint_timestamp_seconds = (%v, %v), want (0, true)", cpTime, ok)
	}

	if code, body := e.Get("/a/x"); code != http.StatusOK {
		t.Fatalf("GET /a/x: %d %s", code, body)
	}

	after := scrapeMetrics(t, e.Metrics)
	if strings.Contains(after, "apiward_audit_chain_head_info") || strings.Contains(after, "sha256=") {
		t.Fatalf("second scrape exposes chain head label:\n%s", after)
	}
	batchesAfter, ok := metricValue(t, after, "gateway_audit_chain_batches_total")
	if !ok {
		t.Fatalf("gateway_audit_chain_batches_total missing in second scrape:\n%s", after)
	}
	if batchesAfter <= batchesBefore {
		t.Fatalf("gateway_audit_chain_batches_total did not rise: before=%v after=%v", batchesBefore, batchesAfter)
	}
}

type statusCheckpoint struct {
	Boot      string `json:"boot"`
	SHA256    string `json:"sha256"`
	Kid       string `json:"kid"`
	Signature string `json:"signature"`
	Time      string `json:"time"`
}

func readStatusCheckpoint(t *testing.T, e *gatewaytest.Env) (*statusCheckpoint, bool) {
	t.Helper()
	code, body := e.AdminRaw(http.MethodGet, "/admin/status", "")
	if code != http.StatusOK {
		t.Fatalf("GET /admin/status: %d %s", code, body)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &raw); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	field, present := raw["audit_checkpoint"]
	if !present {
		return nil, false
	}
	if string(field) == "null" {
		return nil, true
	}
	var cp statusCheckpoint
	if err := json.Unmarshal(field, &cp); err != nil {
		t.Fatalf("decode audit_checkpoint %s: %v", field, err)
	}
	return &cp, true
}

func verifyJWKSCheckpoint(t *testing.T, adminAddr string, cp *statusCheckpoint) {
	t.Helper()
	resp, err := http.Get("http://" + adminAddr + "/.well-known/apiward/jwks.json")
	if err != nil {
		t.Fatalf("fetch JWKS: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read JWKS: %v", err)
	}
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			Kid string `json:"kid"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		t.Fatalf("decode JWKS %s: %v", body, err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(cp.Signature)
	if err != nil {
		t.Fatalf("decode checkpoint signature: %v", err)
	}
	msg := []byte("apiward audit checkpoint\n" + cp.Boot + "\n" + cp.SHA256 + "\n")
	for _, k := range set.Keys {
		if k.Kid != cp.Kid {
			continue
		}
		switch k.Kty {
		case "OKP":
			pub, err := base64.RawURLEncoding.DecodeString(k.X)
			if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
				t.Fatalf("Ed25519 checkpoint signature failed for kid %q", cp.Kid)
			}
			return
		case "EC":
			x, err1 := base64.RawURLEncoding.DecodeString(k.X)
			y, err2 := base64.RawURLEncoding.DecodeString(k.Y)
			if err1 != nil || err2 != nil || len(sig) != 64 {
				t.Fatalf("malformed EC key or signature for kid %q", cp.Kid)
			}
			pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), slices.Concat([]byte{4}, x, y))
			if err != nil {
				t.Fatalf("parse EC public key for kid %q: %v", cp.Kid, err)
			}
			sum := sha256.Sum256(msg)
			if !ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
				t.Fatalf("ES256 checkpoint signature failed for kid %q", cp.Kid)
			}
			return
		default:
			t.Fatalf("unexpected key type %q for kid %q", k.Kty, cp.Kid)
		}
	}
	t.Fatalf("kid %q not found in JWKS %s", cp.Kid, body)
}

// GET /admin/status reports audit_checkpoint as null before the first
// checkpoint and after rotation returns a signed checkpoint verifiable with
// the JWKS key named by kid.
func TestStatusCarriesAuditCheckpoint(t *testing.T) {
	t.Parallel()
	e := gatewaytest.NewEnv(t)
	e.WriteConfig(gatewaytest.ConfigOptions{Audit: map[string]any{"audit_max_bytes": 4096, "audit_max_files": 8}})
	gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)

	cp, present := readStatusCheckpoint(t, e)
	if !present {
		t.Fatal("audit_checkpoint member missing from GET /admin/status")
	}
	if cp != nil {
		t.Fatalf("audit_checkpoint before first checkpoint = %+v, want nil", cp)
	}

	for range 100 {
		if code, body := e.Get("/a/x"); code != http.StatusOK {
			t.Fatalf("GET /a/x: %d %s", code, body)
		}
		if len(gatewaytest.RotatedAudit(t, e.AuditLog)) >= 1 {
			break
		}
	}
	if len(gatewaytest.RotatedAudit(t, e.AuditLog)) == 0 {
		t.Fatal("audit log never rotated")
	}

	cp, present = readStatusCheckpoint(t, e)
	if !present || cp == nil {
		t.Fatalf("audit_checkpoint after rotation = (%v, %v), want non-nil", cp, present)
	}
	if cp.Boot == "" || len(cp.SHA256) != 64 || cp.Kid == "" || cp.Signature == "" || cp.Time == "" {
		t.Fatalf("incomplete audit_checkpoint: %+v", cp)
	}
	parsed, err := time.Parse(time.RFC3339, cp.Time)
	if err != nil {
		t.Fatalf("audit_checkpoint.time %q is not RFC 3339: %v", cp.Time, err)
	}
	verifyJWKSCheckpoint(t, e.Admin, cp)

	metrics := scrapeMetrics(t, e.Metrics)
	ts, ok := metricValue(t, metrics, "gateway_audit_last_checkpoint_timestamp_seconds")
	if !ok || int64(ts) != parsed.Unix() {
		t.Fatalf("gateway_audit_last_checkpoint_timestamp_seconds = (%v, %v), want %d", ts, ok, parsed.Unix())
	}
}
