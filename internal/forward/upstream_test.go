// Forwarding to version 5 upstreams: the connect-time address check, TLS
// with CA pins and client certificates, and the Host header choice. Every
// certificate and key is generated here, at test time.

package forward

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// issuer signs test certificates.
type issuer struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newIssuer(t *testing.T) issuer {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return issuer{cert, key}
}

// leaf issues a certificate for the IP or DNS names given, for a server or a
// client, and writes its chain and PKCS #8 key to files mode 0600 in dir.
func (i issuer) leaf(t *testing.T, dir, name string, client bool, ips []net.IP, dns ...string) (certFile, keyFile string, pair tls.Certificate) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	usage := x509.ExtKeyUsageServerAuth
	if client {
		usage = x509.ExtKeyUsageClientAuth
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		IPAddresses: ips, DNSNames: dns, ExtKeyUsage: []x509.ExtKeyUsage{usage}, KeyUsage: x509.KeyUsageDigitalSignature,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, i.cert, &key.PublicKey, i.key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	certFile, keyFile = filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
	if os.WriteFile(certFile, certPEM, 0o600) != nil || os.WriteFile(keyFile, keyPEM, 0o600) != nil {
		t.Fatal("writing test certificate files")
	}
	pair, _ = tls.X509KeyPair(certPEM, keyPEM)
	return certFile, keyFile, pair
}

func (i issuer) file(t *testing.T, dir string) string {
	path := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: i.cert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// send forwards GET /x to the upstream u through a proxy using network n and
// returns the gateway's failure reason ("" when forwarded) and the status.
func send(t *testing.T, n *Network, u policy.Upstream, host string) (string, int) {
	t.Helper()
	proxy, err := NewUpstreamProxy(bounds, testPool, func() *Network { return n }, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Host = host
	rec := httptest.NewRecorder()
	if err := proxy.Forward(rec, r.WithContext(Bind(context.Background(), destination(t, u)))); err != nil {
		status, _ := ForwardFailure(err)
		return FailureReason(err), status
	}
	return "", rec.Code
}

// destination is where a policy with the one public operation GET /x on u
// sends that request.
func destination(t *testing.T, u policy.Upstream) compile.Destination {
	t.Helper()
	p := policy.Policy{SchemaVersion: policy.LatestSchemaVersion, Profile: policy.ProfileCore,
		Upstreams:  []policy.Upstream{u},
		APIs:       []policy.API{{ID: "api", Upstream: u.ID}},
		Operations: []policy.Operation{{ID: "op", API: "api", Method: "GET", Target: "/x", Access: "allow", Auth: "none"}}}
	g, err := compile.Compile(p, 1, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	_, rule := g.Match("/x", "GET", compile.Inbound{})
	d, ok := rule.Destination("/x")
	if !ok {
		t.Fatal("no destination")
	}
	return d
}

// An address is checked when the connection is made, not only at compile: a
// public address the operator no longer allows is refused before connecting.
func TestUpstreamConnectCheck(t *testing.T) {
	public, _ := LoadNetwork(true, nil, 0)
	g, err := compile.Compile(policy.Policy{SchemaVersion: policy.LatestSchemaVersion, Profile: policy.ProfileCore,
		Upstreams: []policy.Upstream{{ID: "u", URL: "http://192.0.2.10:9"}}}, 1, time.Time{})
	if err != nil || g.CheckNetwork(public) != nil {
		t.Fatalf("a public literal with the switch on: %v", err)
	}
	reason, status := send(t, closed(), policy.Upstream{ID: "u", URL: "http://192.0.2.10:9"}, "shop.example")
	if reason != "destination_refused" || status != http.StatusBadGateway {
		t.Fatalf("got %q %d", reason, status)
	}
}

// https upstreams are verified against the profile's CA pin for the URL's
// host, and present the profile's client certificate.
func TestUpstreamTLS(t *testing.T) {
	dir, ca := t.TempDir(), newIssuer(t)
	loopback := []net.IP{net.IPv4(127, 0, 0, 1)}
	_, _, serverPair := ca.leaf(t, dir, "server", false, loopback)
	_, _, otherPair := ca.leaf(t, dir, "other", false, nil, "other.test")
	clientCert, clientKey, _ := ca.leaf(t, dir, "gateway", true, nil)
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	var received atomic.Int64
	var host atomic.Value
	start := func(pair tls.Certificate) string {
		s := httptest.NewUnstartedServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			received.Add(1)
			host.Store(r.Host)
		}))
		s.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
		s.StartTLS()
		t.Cleanup(s.Close)
		return s.Listener.Addr().String()
	}
	good, wrongName := start(serverPair), start(otherPair)
	n, err := LoadNetwork(false, []ProfileSettings{
		{ID: "full", CAFile: ca.file(t, dir), ClientCertificateFile: clientCert, ClientKeyFile: clientKey},
		{ID: "pin", CAFile: ca.file(t, dir)},
		{ID: "system"},
	}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if reason, status := send(t, n, policy.Upstream{ID: "u", URL: "https://" + good, TLS: "full"}, "shop.example"); reason != "" || status != http.StatusOK || received.Load() != 1 || host.Load() != good {
		t.Fatalf("pinned with client certificate: %q %d, received %d, Host %v", reason, status, received.Load(), host.Load())
	}
	for _, tc := range []struct{ name, url, profile, want string }{
		{"untrusted (system roots)", "https://" + good, "system", "certificate_invalid"},
		{"wrong name", "https://" + wrongName, "full", "certificate_invalid"},
	} {
		if reason, status := send(t, n, policy.Upstream{ID: "u", URL: tc.url, TLS: tc.profile}, "shop.example"); reason != tc.want || status != http.StatusBadGateway {
			t.Errorf("%s: %q %d", tc.name, reason, status)
		}
	}
	// Without a client certificate the upstream refuses the connection; with
	// TLS 1.3 the client learns it only after its handshake has finished.
	if _, status := send(t, n, policy.Upstream{ID: "u", URL: "https://" + good, TLS: "pin"}, "shop.example"); status != http.StatusBadGateway {
		t.Errorf("no client certificate: %d", status)
	}
	if received.Load() != 1 {
		t.Fatalf("refused connections reached the upstream: %d requests", received.Load())
	}

	// Key material is checked before any profile is used.
	for name, s := range map[string]ProfileSettings{
		"relative path":     {ID: "p", CAFile: "ca.crt"},
		"key without chain": {ID: "p", ClientKeyFile: clientKey},
		"mismatched pair":   {ID: "p", ClientCertificateFile: clientCert, ClientKeyFile: filepath.Join(dir, "server.key")},
		"bad identifier":    {ID: "bad id"},
	} {
		if _, err := LoadNetwork(false, []ProfileSettings{s}, 0); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(clientKey, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadNetwork(false, []ProfileSettings{{ID: "p", ClientCertificateFile: clientCert, ClientKeyFile: clientKey}}, 0); err == nil {
			t.Error("a key readable by others loaded")
		}
	}
}

// Over http the upstream receives the client's Host unless the policy asks
// for the upstream's own.
func TestUpstreamHostHeader(t *testing.T) {
	var host atomic.Value
	s := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { host.Store(r.Host) }))
	t.Cleanup(s.Close)
	addr := s.Listener.Addr().String()
	for mode, want := range map[string]string{"": "shop.example", "inbound": "shop.example", "upstream": addr} {
		if reason, status := send(t, closed(), policy.Upstream{ID: "u", URL: "http://" + addr, Host: mode}, "shop.example"); reason != "" || status != http.StatusOK || host.Load() != want {
			t.Errorf("host %q: %q %d, Host %v, want %s", mode, reason, status, host.Load(), want)
		}
	}
}
