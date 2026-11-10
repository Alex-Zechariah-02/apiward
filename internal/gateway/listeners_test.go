// The data listener's TLS from files, the redirect listener, listening on
// every interface and the health endpoints. Certificates are generated here.

package gateway

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// writeCertificate writes a self-signed certificate for host and its PKCS #8
// key, mode 0600, and returns the certificate.
func writeCertificate(t *testing.T, certFile, keyFile, host string, serial int64) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: host},
		IPAddresses: []net.IP{net.ParseIP(host)}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
	if os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600) != nil ||
		os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0o600) != nil {
		t.Fatal("writing the certificate files")
	}
	certificate, _ := x509.ParseCertificate(der)
	return certificate
}

// The data listener serves TLS from files: the upstream learns the request
// came over https, a failed reload keeps the served certificate and is
// recorded, a good one replaces it, and readiness reflects the gateway.
func TestDataListenerTLSFiles(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
	host, _, _ := net.SplitHostPort(e.DataAddr)
	certFile, keyFile := filepath.Join(e.Dir, "data.crt"), filepath.Join(e.Dir, "data.key")
	first := writeCertificate(t, certFile, keyFile, host, 1)
	settings := e.NativeSettings()
	gatewaytest.Section(settings, "data")["tls"] = map[string]any{"files": map[string]any{"certificate_file": certFile, "key_file": keyFile}}
	e.WriteNative(settings)
	cfg, err := loadNativeConfig(e.Config)
	if err != nil {
		t.Fatal(err)
	}
	g, err := startNative(cfg, slog.New(slog.NewJSONHandler(&gatewaytest.LogBuffer{}, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.stop() })

	served := func() *x509.Certificate {
		t.Helper()
		roots := x509.NewCertPool()
		for _, c := range []*x509.Certificate{first, g.certificate.current.Load().Leaf} {
			roots.AddCert(c)
		}
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, NextProtos: []string{"h2", "http/1.1"}}}}
		reply, err := client.Get("https://" + e.DataAddr + "/a/x")
		if err != nil {
			t.Fatal(err)
		}
		defer reply.Body.Close()
		if reply.StatusCode != http.StatusOK || reply.TLS.NegotiatedProtocol != "http/1.1" {
			t.Fatalf("%d over %q", reply.StatusCode, reply.TLS.NegotiatedProtocol)
		}
		return reply.TLS.PeerCertificates[0]
	}
	if served().SerialNumber.Int64() != 1 {
		t.Fatal("not the configured certificate")
	}
	if receipts := e.A.Receipts(); len(receipts) != 1 || receipts[0].Headers.Get("X-Forwarded-Proto") != "https" {
		t.Fatalf("upstream receipts %+v", receipts)
	}
	if err := os.WriteFile(keyFile, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	g.certificate.reload()
	if served().SerialNumber.Int64() != 1 {
		t.Fatal("a failed reload replaced the certificate")
	}
	writeCertificate(t, certFile, keyFile, host, 2)
	g.certificate.reload()
	if served().SerialNumber.Int64() != 2 {
		t.Fatal("a good reload kept the old certificate")
	}
	reply, err := http.Get("http://" + cfg.metricsListen + "/readyz")
	if err != nil || reply.StatusCode != http.StatusOK {
		t.Fatalf("readyz: %v %v", reply, err)
	}
	reply.Body.Close()
	if err := g.stop(); err != nil {
		t.Fatal(err)
	}
	if log, _ := os.ReadFile(e.AuditLog); !strings.Contains(string(log), `"tls.reload_failed"`) {
		t.Fatal("the failed reload was not recorded")
	}
}

// The redirect answers 308 to the configured origin whatever the client
// names as host, keeps the path and query, and counts its answers.
func TestRedirectListener(t *testing.T) {
	observed := monitor.New(policy.DefaultWindow, policy.DefaultAPIs)
	h := redirect("https://api.example.com", observed)
	for target, want := range map[string]string{
		"/orders?id=7":          "https://api.example.com/orders?id=7",
		"http://evil.example/x": "https://api.example.com/x",
		"//evil.example/x":      "https://api.example.com//evil.example/x",
	} {
		r := httptest.NewRequest(http.MethodPost, target, strings.NewReader("body"))
		r.Host = "evil.example"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusPermanentRedirect || w.Header().Get("Location") != want || w.Header().Get("Content-Length") != "0" || w.Header().Get("Connection") != "close" {
			t.Errorf("%s: %d %v", target, w.Code, w.Header())
		}
	}
	metrics := httptest.NewRecorder()
	monitor.Metrics(observed, func() (int64, int, int) { return 0, 0, 0 }).ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metrics.Body.String(), "gateway_redirects_total 3\n") {
		t.Fatalf("metrics:\n%s", metrics.Body.String())
	}
}

// Health answers carry fixed bodies; other paths still reach the metrics.
func TestHealthEndpoints(t *testing.T) {
	metrics := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "metrics") })
	for _, ok := range []bool{true, false} {
		h := health(metrics, func() bool { return ok })
		for path, want := range map[string]string{"/livez": "ok\n", "/readyz": map[bool]string{true: "ok\n", false: "unavailable\n"}[ok], "/metrics": "metrics"} {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
			if w.Body.String() != want {
				t.Errorf("ready %v %s: %d %q", ok, path, w.Code, w.Body.String())
			}
		}
	}
	if got := loopbackForm("0.0.0.0:9450"); got != "127.0.0.1:9450" {
		t.Errorf("loopback form %s", got)
	}
	if got := loopbackForm("[::]:9450"); got != "[::1]:9450" {
		t.Errorf("loopback form %s", got)
	}
}

// Every interface and the network-wide metrics listener are deliberate
// switches; ACME is not available.
func TestListenAllInterfaces(t *testing.T) {
	dir := t.TempDir()
	set := func(section, name string, value any) func(map[string]any) {
		return func(s map[string]any) { gatewaytest.Section(s, section)[name] = value }
	}
	both := func(changes ...func(map[string]any)) func(map[string]any) {
		return func(s map[string]any) {
			for _, change := range changes {
				change(s)
			}
		}
	}
	tlsFiles := set("data", "tls", map[string]any{"files": map[string]any{"certificate_file": filepath.Join(dir, "c.pem"), "key_file": filepath.Join(dir, "k.pem")}})
	for name, tc := range map[string]struct {
		change func(map[string]any)
		ok     bool
	}{
		"all interfaces without the switch": {set("data", "listen", "0.0.0.0:9480"), false},
		"all interfaces with the switch":    {both(set("data", "listen", "0.0.0.0:9480"), set("data", "listen_all_interfaces", true)), true},
		"network metrics without switch":    {set("gateway", "metrics_listen", "0.0.0.0:9450"), false},
		"network metrics with switch":       {both(set("gateway", "metrics_listen", "0.0.0.0:9450"), set("gateway", "metrics_listen_any", true)), true},
		"redirect without TLS":              {set("data", "redirect_http", map[string]any{"listen": "127.0.0.2:9080", "origin": "https://api.example.com"}), false},
		"redirect origin with a path":       {both(tlsFiles, set("data", "redirect_http", map[string]any{"listen": "127.0.0.2:9080", "origin": "https://api.example.com/x"})), false},
		"redirect with TLS":                 {both(tlsFiles, set("data", "redirect_http", map[string]any{"listen": "127.0.0.2:9080", "origin": "https://api.example.com"})), true},
		"ACME":                              {set("data", "tls", map[string]any{"acme": map[string]any{"domains": []string{"api.example.com"}}}), false},
	} {
		_, err := parseConfig(configDocument(t, dir, tc.change))
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}
