// The data plane's transport beyond plain HTTP: TLS from certificate files,
// the HTTP-to-HTTPS redirect listener, listening on every interface, and the
// health endpoints served beside the metrics.

package gateway

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/forward"
	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
)

// expiryWarning is how close to its expiry the data listener's certificate
// is reported: certificates are usually renewed about 30 days ahead, so 14
// days left means renewal has failed.
const expiryWarning = 14 * 24 * time.Hour

// certificateFiles names a certificate chain and its private key.
type certificateFiles struct {
	CertificateFile string `json:"certificate_file"`
	KeyFile         string `json:"key_file"`
}

// dataTLS is the data listener's TLS; certificate files are its only source.
type dataTLS struct {
	Files *certificateFiles `json:"files"`
}

// redirectSettings is the HTTP listener that sends every client to origin.
type redirectSettings struct {
	Listen string `json:"listen"`
	Origin string `json:"origin"`
}

// checkTransport checks the data listener's TLS and redirect settings.
func checkTransport(d dataSettings, others ...string) error {
	if d.TLS != nil {
		f := d.TLS.Files
		if f == nil {
			return errors.New("data.tls must hold files")
		}
		if !filepath.IsAbs(f.CertificateFile) || !filepath.IsAbs(f.KeyFile) {
			return errors.New("data.tls.files.certificate_file and key_file must be absolute paths")
		}
	}
	r := d.RedirectHTTP
	if r == nil {
		return nil
	}
	if d.TLS == nil {
		return errors.New("data.redirect_http needs data.tls: it sends clients to an https origin")
	}
	addr, err := netip.ParseAddrPort(r.Listen)
	if err != nil || addr.Port() == 0 || (addr.Addr().Unmap().IsUnspecified() && !d.ListenAllInterfaces) {
		return errors.New("data.redirect_http.listen must be a literal IP address with a port (all interfaces only with data.listen_all_interfaces)")
	}
	for _, other := range append(others, d.Listen) {
		if r.Listen == other {
			return errors.New("data.redirect_http.listen must differ from every other listener")
		}
	}
	origin, err := url.Parse(r.Origin)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" || r.Origin != origin.String() {
		return errors.New("data.redirect_http.origin must be an https origin such as https://api.example.com, with no path")
	}
	return nil
}

// servingCertificate is the data listener's certificate. A reload replaces
// it only with a certificate that loaded and is valid; otherwise the current
// one stays and the failure is recorded.
type servingCertificate struct {
	files   certificateFiles
	current atomic.Pointer[tls.Certificate]
	audit   *audit.AuditLog // set once the controller has opened the log
	logger  *slog.Logger
	mu      sync.Mutex // serialises reloads
}

func loadServing(files certificateFiles, now time.Time) (*tls.Certificate, error) {
	c, err := forward.LoadCertificate(files.CertificateFile, files.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("data.tls: %w", err)
	}
	if now.Before(c.Leaf.NotBefore) || !now.Before(c.Leaf.NotAfter) {
		return nil, errors.New("data.tls: the certificate is not valid now")
	}
	return c, nil
}

// openCertificate loads the data listener's certificate, or returns nil when
// the listener is plain HTTP.
func openCertificate(t *dataTLS, logger *slog.Logger) (*servingCertificate, error) {
	if t == nil {
		return nil, nil
	}
	c, err := loadServing(*t.Files, time.Now())
	if err != nil {
		return nil, classify(ErrConfig, err)
	}
	s := &servingCertificate{files: *t.Files, logger: logger}
	s.current.Store(c)
	return s, nil
}

// reload reads the certificate files again.
func (s *servingCertificate) reload() {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := loadServing(s.files, time.Now())
	if err != nil {
		s.logger.Error("data listener certificate not reloaded; the current one stays", "error", err)
		s.audit.Record(audit.Event{Kind: "tls.reload_failed"})
		return
	}
	s.current.Store(c)
	s.logger.Info("data listener certificate reloaded", "expires", c.Leaf.NotAfter)
}

// valid reports whether the current certificate is valid at now.
func (s *servingCertificate) valid(now time.Time) bool {
	leaf := s.current.Load().Leaf
	return !now.Before(leaf.NotBefore) && now.Before(leaf.NotAfter)
}

// watchExpiry records tls.certificate_expiring at once and then daily while
// the certificate is within expiryWarning of its expiry, until done closes.
func (s *servingCertificate) watchExpiry(done <-chan struct{}) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		if leaf := s.current.Load().Leaf; time.Until(leaf.NotAfter) < expiryWarning {
			s.audit.Record(audit.Event{Kind: "tls.certificate_expiring", Expires: leaf.NotAfter})
		}
		select {
		case <-done:
			return
		case <-ticker.C:
		}
	}
}

// config is the data listener's TLS: 1.2 or later, HTTP/1.1 only, the
// current certificate for every handshake.
func (s *servingCertificate) config() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return s.current.Load(), nil
		},
	}
}

// redirect answers every request with 308 to origin plus the request's path
// and query. The target host comes only from origin; the body is never read,
// and the connection closes after the answer.
func redirect(origin string, observed *monitor.Observations) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed.Redirected()
		w.Header().Set("Connection", "close")
		w.Header().Set("Content-Length", "0")
		target := r.URL.RequestURI()
		if target == "" || target[0] != '/' {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Location", origin+target)
		w.WriteHeader(http.StatusPermanentRedirect)
	})
}

// redirectServer serves the redirect with short limits: it reads only
// request headers.
func redirectServer(origin string, observed *monitor.Observations) *http.Server {
	return &http.Server{Handler: redirect(origin, observed), ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, MaxHeaderBytes: defaultHeaderBytes}
}

// listenRedirect binds the redirect listener; nil when there is none.
func listenRedirect(r *redirectSettings) (net.Listener, error) {
	if r == nil {
		return nil, nil
	}
	listener, err := net.Listen("tcp", r.Listen)
	if err != nil {
		return nil, classify(ErrListen, fmt.Errorf("redirect listener: %w", err))
	}
	return listener, nil
}

// closeListeners closes the listeners bound so far; an optional one that
// was not configured is nil and skipped.
func closeListeners(listeners ...net.Listener) {
	for _, l := range listeners {
		if l != nil {
			l.Close()
		}
	}
}

// checkHealth runs the health command: it asks the configured metrics
// listener whether the gateway is ready and exits 0 only on 200. Container
// health checks use it, since minimal images have no HTTP client.
func checkHealth(configPath string) int {
	cfg, err := loadNativeConfig(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gateway:", err)
		return exitFailed
	}
	client := &http.Client{Timeout: 5 * time.Second}
	reply, err := client.Get("http://" + loopbackForm(cfg.metricsListen) + "/readyz")
	if err != nil {
		fmt.Fprintln(os.Stderr, "gateway: not ready:", err)
		return exitFailed
	}
	reply.Body.Close()
	if reply.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "gateway: not ready:", reply.Status)
		return exitFailed
	}
	return 0
}

// health serves GET /livez and GET /readyz beside the metrics. Their bodies
// are fixed, so they disclose nothing but the answer.
func health(metrics http.Handler, ready func() bool) http.Handler {
	answer := func(w http.ResponseWriter, ok bool) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if !ok {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, "unavailable\n")
			return
		}
		fmt.Fprint(w, "ok\n")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) { answer(w, true) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) { answer(w, ready()) })
	mux.Handle("/", metrics)
	return mux
}

// loopbackForm is the address a local health check dials for a listener:
// the loopback address of its family when it listens on every interface.
func loopbackForm(listen string) string {
	addr := netip.MustParseAddrPort(listen) // checked with the configuration
	ip := addr.Addr().Unmap()
	switch {
	case !ip.IsUnspecified():
		return listen
	case ip.Is4():
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), addr.Port()).String()
	}
	return netip.AddrPortFrom(netip.IPv6Loopback(), addr.Port()).String()
}
