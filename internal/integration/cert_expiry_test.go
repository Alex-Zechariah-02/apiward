// Certificate expiry metric and alert A5 tests.

package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

// writeTestCert generates a self-signed P-256 certificate valid from 1 hour
// ago until now+validFor and writes its PEM cert and PKCS #8 key to dir.
func writeTestCert(t *testing.T, dir, prefix string, validFor time.Duration) (string, string, time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	notAfter := now.Add(validFor)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: prefix},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, prefix+".crt.pem")
	keyPath := filepath.Join(dir, prefix+".key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath, notAfter
}

func labeledMetric(t *testing.T, text, name, labels string) (float64, bool) {
	t.Helper()
	prefix := name + "{" + labels + "} "
	for line := range strings.SplitSeq(text, "\n") {
		if rest, ok := strings.CutPrefix(line, prefix); ok {
			v, err := strconv.ParseFloat(strings.TrimSpace(rest), 64)
			if err != nil {
				t.Fatalf("parsing %q: %v", line, err)
			}
			return v, true
		}
	}
	return 0, false
}

func TestCertificateExpiryMetric(t *testing.T) {
	t.Parallel()
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})

	dataCert, dataKey, dataExp := writeTestCert(t, e.Dir, "data", 30*24*time.Hour)
	upCert, upKey, upExp := writeTestCert(t, e.Dir, "upstream", 20*24*time.Hour)

	settings := e.NativeSettings()
	gatewaytest.Section(settings, "data")["tls"] = map[string]any{
		"files": map[string]any{"certificate_file": dataCert, "key_file": dataKey},
	}
	gatewaytest.Section(settings, "upstream")["tls_profiles"] = []any{
		map[string]any{"id": "partner", "client_certificate_file": upCert, "client_key_file": upKey},
	}
	e.WriteNative(settings)
	e.Start(gatewaytest.Binaries.Plain)

	metrics := scrapeMetrics(t, e.Metrics)
	wantData := float64(dataExp.Unix())
	wantUp := float64(upExp.Unix())
	if got, ok := labeledMetric(t, metrics, "gateway_tls_certificate_not_after_seconds", `role="data"`); !ok || got != wantData {
		t.Fatalf("data cert gauge = (%v, %v), want (%v, true)\n%s", got, ok, wantData, metrics)
	}
	if got, ok := labeledMetric(t, metrics, "gateway_tls_certificate_not_after_seconds", `role="upstream",profile="partner"`); !ok || got != wantUp {
		t.Fatalf("upstream cert gauge = (%v, %v), want (%v, true)\n%s", got, ok, wantUp, metrics)
	}
}

func TestAlertA5CertificateExpiry(t *testing.T) {
	t.Parallel()
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})

	dataCert, dataKey, _ := writeTestCert(t, e.Dir, "data-med", 10*24*time.Hour)
	upCert, upKey, _ := writeTestCert(t, e.Dir, "up-crit", 2*24*time.Hour)
	okCert, okKey, _ := writeTestCert(t, e.Dir, "up-ok", 60*24*time.Hour)

	settings := e.NativeSettings()
	gatewaytest.Section(settings, "data")["tls"] = map[string]any{
		"files": map[string]any{"certificate_file": dataCert, "key_file": dataKey},
	}
	gatewaytest.Section(settings, "upstream")["tls_profiles"] = []any{
		map[string]any{"id": "expiring", "client_certificate_file": upCert, "client_key_file": upKey},
		map[string]any{"id": "healthy", "client_certificate_file": okCert, "client_key_file": okKey},
	}
	e.WriteNative(settings)
	e.Start(gatewaytest.Binaries.Plain)

	admin := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
	code, body, _ := e.As(admin, http.MethodGet, "/admin/alerts", "")
	if code != http.StatusOK {
		t.Fatalf("GET /admin/alerts: %d %s", code, body)
	}
	resp := fromJSON[struct {
		Rules  string `json:"rules"`
		Alerts []struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
			Object   string `json:"object"`
			Message  string `json:"message"`
		} `json:"alerts"`
	}](t, body)
	if resp.Rules != "checks-0.8" {
		t.Fatalf("rules = %q, want checks-0.8", resp.Rules)
	}
	var foundData, foundUp bool
	for _, a := range resp.Alerts {
		if a.ID != "A5" {
			continue
		}
		if strings.Contains(a.Object, "data") && a.Severity == "medium" {
			foundData = true
		}
		if strings.Contains(a.Object, "expiring") && a.Severity == "critical" {
			foundUp = true
		}
		if strings.Contains(a.Object, "healthy") {
			t.Fatalf("unexpected A5 alert for healthy 60-day cert: %+v", a)
		}
	}
	if !foundData || !foundUp {
		t.Fatalf("missing A5 alerts (data=%v, expiring=%v): %+v", foundData, foundUp, resp.Alerts)
	}
}
