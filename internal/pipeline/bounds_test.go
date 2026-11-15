// Exact bounds of the request path and trust checks: each limit's last
// accepted value and first refused one, which the end-to-end suites never
// reach.

package pipeline

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/issuertest"
	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

func TestTokenBounds(t *testing.T) {
	segment := func(n int) string { return strings.Repeat("a", n) }
	if !isCompactToken(segment(10)+"."+segment(10)+"."+segment(MaxTokenBytes-22)) || isCompactToken(segment(10)+"."+segment(10)+"."+segment(MaxTokenBytes-21)) {
		t.Error("a token of exactly MaxTokenBytes must pass and one byte more must not")
	}
	if _, ok := numericDate(float64(maxNumericDate)); !ok {
		t.Error("the last NumericDate was refused")
	}
	v := testVerifier(t)
	roles := make([]string, policy.MaxTokenRoles)
	for i := range roles {
		roles[i] = fmt.Sprintf("R%d", i)
	}
	if _, reason := v.verify(issuer.Token(t, claimsAt(map[string]any{"roles": roles})), fixedNow); reason != "" {
		t.Errorf("%d roles: %s", len(roles), reason)
	}
	if _, reason := v.verify(issuer.Token(t, claimsAt(map[string]any{"roles": append(roles, "EXTRA")})), fixedNow); reason != "invalid_claims" {
		t.Errorf("%d roles: %q, want invalid_claims", len(roles)+1, reason)
	}
	if _, reason := v.verify(issuer.SignRaw(`{"alg":"RS256","kid":"test a"}`, issuertest.ClaimsJSON(claimsAt(nil))), fixedNow); reason != "unsupported_header" {
		t.Errorf("kid with a space: %q, want unsupported_header", reason)
	}
}

func TestTrustBounds(t *testing.T) {
	file := keyFile(t, issuer)
	for _, value := range []string{strings.Repeat("i", maxTrustValue), "!~"} {
		if _, err := LoadVerifier(testTrust(value, value, file)); err != nil {
			t.Errorf("issuer %.10q: %v", value, err)
		}
	}
	keys := make([]VerificationKey, MaxKeys)
	for i := range keys {
		keys[i] = VerificationKey{Kid: fmt.Sprintf("k%d", i), PublicKeyFile: file}
	}
	c := testTrust(issuertest.Name, issuertest.Audience, file)
	c.Keys = keys
	if _, err := LoadVerifier(c); err != nil {
		t.Errorf("%d keys: %v", MaxKeys, err)
	}
	c.Keys = []VerificationKey{{Kid: "bad kid", PublicKeyFile: file}}
	if _, err := LoadVerifier(c); err == nil {
		t.Error("an invalid kid was accepted")
	}
	unterminated := filepath.Join(t.TempDir(), "open.pem")
	if err := os.WriteFile(unterminated, []byte("-----BEGIN PUBLIC KEY-----\nMIIB\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadVerifier(testTrust(issuertest.Name, issuertest.Audience, unterminated)); err == nil {
		t.Error("an unterminated PEM block was accepted")
	}
}

// The identity key must be one PKCS #8 ECDSA P-256 block and nothing more.
func TestSignerKeyShape(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaDER})
	for name, data := range map[string][]byte{
		"RSA key":          rsaPEM,
		"text after block": append(append([]byte{}, rsaPEM...), "more"...),
		"other block type": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: rsaDER}),
	} {
		path := filepath.Join(t.TempDir(), "identity.pem")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadSigner(path); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// The in-flight count is released after each request, and a request at the
// limit is still admitted.
func TestInFlightReleased(t *testing.T) {
	r := func() *http.Request { return httptest.NewRequest(http.MethodGet, "/a/x", nil) }
	rec, records, _ := exchange(t, setup{ops: []policy.Operation{public("GET", "/a/x")}, limits: Limits{MaxInFlight: 1}}, r(), r(), r())
	if rec.Code != http.StatusOK || len(records) != 6 {
		t.Fatalf("third request: %d, %d records", rec.Code, len(records))
	}
	for _, e := range records {
		if ms, _ := e["duration_ms"].(float64); ms < 0 || ms > 10_000 {
			t.Fatalf("duration %v ms recorded for an immediate request", e["duration_ms"])
		}
	}
}

func TestSettingBounds(t *testing.T) {
	forward := func(http.ResponseWriter, *http.Request) error { return nil }
	full := Deps{Authority: noAuthority{}, Audit: &audit.AuditLog{}, Observations: monitor.New(policy.DefaultWindow, policy.DefaultAPIs), Limiter: NewLimiter(16), Clock: NewClock(), AuditTimeout: time.Second, Forward: forward}
	for name, drop := range map[string]func(*Deps){
		"authority": func(d *Deps) { d.Authority = nil }, "audit": func(d *Deps) { d.Audit = nil },
		"observations": func(d *Deps) { d.Observations = nil }, "limiter": func(d *Deps) { d.Limiter = nil },
		"forwarder": func(d *Deps) { d.Forward = nil },
	} {
		d := full
		drop(&d)
		if _, err := New(d); err == nil {
			t.Errorf("a handler without its %s was accepted", name)
		}
	}
	for _, prefix := range []int{MinIPv6RatePrefix, 128} {
		exchangeLimits := Limits{IPv6RatePrefix: prefix}
		if _, _, recovered := exchange(t, setup{ops: []policy.Operation{public("GET", "/a/x")}, limits: exchangeLimits}, httptest.NewRequest(http.MethodGet, "/a/x", nil)); recovered != nil {
			t.Fatalf("prefix %d: %v", prefix, recovered)
		}
	}
	entries := make([]string, MaxProxies)
	for i := range entries {
		entries[i] = fmt.Sprintf("192.0.2.%d", i)
	}
	if _, err := ParseProxies(entries); err != nil {
		t.Errorf("%d proxies: %v", MaxProxies, err)
	}
	two := httptest.NewRequest(http.MethodOptions, "/a/o", nil)
	two.Header.Add("Max-Forwards", "3")
	two.Header.Add("Max-Forwards", "4")
	if rec, _, _ := exchange(t, setup{ops: []policy.Operation{public("OPTIONS", "/a/o")}}, two); rec.Code != http.StatusBadRequest {
		t.Errorf("two Max-Forwards fields: %d, want 400", rec.Code)
	}
}

// Retry-After rounds the wait up to whole seconds.
func TestRetryAfterRounding(t *testing.T) {
	l := NewLimiter(16)
	rule := quota(1, 2_000)
	key := counterKey{"op", compile.RateKeySubject, "a"}
	if l.admit(key, rule, 0) != rateAdmitted || l.admit(key, rule, 500) != rateExceeded {
		t.Fatal("setup")
	}
	// Admitted again at 4,000 ms (the counted request's bucket fully faded).
	if got := l.retryAfter(key, rule, 500); got != 4 {
		t.Fatalf("retry after %d s, want 4", got)
	}
	if got := l.retryAfter(key, rule, 3_001); got != 1 {
		t.Fatalf("retry after %d s at 999 ms before, want 1", got)
	}
}
