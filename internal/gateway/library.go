// What the standalone binary and an embedding host program both run: the
// checked settings, the opened deployment (controller, enforcement handler,
// metrics server), its listeners and the classified errors of the gateway's
// lifecycle. The data-plane server limits are in server.go.

package gateway

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/admin"
	"github.com/Alex-Zechariah-02/apiward/internal/adminui"
	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/connections"
	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/forward"
	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
	"github.com/Alex-Zechariah-02/apiward/internal/operator"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// Kinds of lifecycle failure. Every error returned while loading, opening,
// starting or stopping a gateway matches exactly one of them with errors.Is;
// its text is the underlying error's, unchanged.
var (
	ErrConfig     = errors.New("configuration invalid")
	ErrLocked     = errors.New("deployment held by another process")
	ErrStorage    = errors.New("database or audit log unusable")
	ErrListen     = errors.New("listener unavailable")
	ErrStarted    = errors.New("already started")
	ErrStopped    = errors.New("stopped")
	ErrIncomplete = errors.New("stop incomplete")
)

// classified is an error with its kind; its text is the error's own.
type classified struct{ kind, err error }

func (c classified) Error() string   { return c.err.Error() }
func (c classified) Unwrap() []error { return []error{c.kind, c.err} }

// classify gives err its kind, unless err already has one: the first
// classification, closest to the cause, is kept.
func classify(kind, err error) error {
	if _, done := errors.AsType[classified](err); done {
		return err
	}
	return classified{kind: kind, err: err}
}

// Settings is a configuration file checked as the run command checks it.
// Only LoadSettings makes one; the zero value is refused.
type Settings struct{ native *nativeConfig }

// LoadSettings reads and checks the configuration file at path, including
// the files it names. Its errors are ErrConfig.
func LoadSettings(path string) (Settings, error) {
	cfg, err := loadChecked(path)
	if err != nil {
		return Settings{}, classify(ErrConfig, err)
	}
	cfg.reloaded = new(atomic.Pointer[audit.Event])
	cfg.controller.ReloadKeys = cfg.reloadKeys
	cfg.controller.Reloaded = cfg.reloadedRecord
	return Settings{native: &cfg}, nil
}

// loadChecked reads the configuration file at path and the files it names,
// checked as the run command checks them.
func loadChecked(path string) (nativeConfig, error) {
	cfg, err := loadNativeConfig(path)
	if err == nil {
		err = cfg.requireIdentity()
	}
	if err == nil {
		err = operator.CheckPaths(cfg.source.path, operatorConfig(cfg), "run", nil)
	}
	return cfg, err
}

// deployment is an opened gateway that serves nothing yet.
type deployment struct {
	config      nativeConfig
	controller  *controller.Controller
	enforcement *pipeline.Handler
	// limiter holds the rate counters. They belong to the process, not to a
	// generation, so publication never resets them; a restart does.
	limiter *pipeline.Limiter
	// ui reads the dashboard files; nil when none are configured.
	ui      fs.FS
	logger  *slog.Logger
	metrics *http.Server
	// health serves /livez and /readyz alone; nil when gateway.health_listen
	// is unset. healthListen is its bound address for the start log.
	health       *http.Server
	healthListen string
	// certificate is the data listener's; nil when it serves plain HTTP.
	certificate *servingCertificate
	upstreams   upstreams
	// draining is set when a stop begins: /readyz answers 503 from then on,
	// while the listeners still serve for the stop's delay.
	draining atomic.Bool
}

// openDeployment opens cfg's deployment and builds its handlers; it binds no
// listener. When it returns an error, everything it opened is released.
func openDeployment(cfg nativeConfig, logger *slog.Logger) (*deployment, error) {
	certificate, err := openCertificate(cfg.tls, logger)
	if err != nil {
		return nil, err
	}
	warnSettings(cfg, logger)
	if certificate != nil {
		cfg.controller.ReloadCertificate = certificate.reload
	}
	c, ui, err := openController(cfg.controller, cfg.adminUI, logger)
	if err != nil {
		return nil, err
	}
	if certificate != nil {
		certificate.audit = c.Audit()
	}
	proxy, err := forward.NewUpstreamProxy(cfg.upstream, cfg.pool, c.Network, logger)
	if err != nil {
		return nil, errors.Join(classify(ErrConfig, err), c.Stop())
	}
	// A log that cannot be opened refuses every admission and every change
	// for as long as the process runs; a running gateway could only report it.
	if c.Audit().OpenErr() != nil {
		return nil, errors.Join(classify(ErrStorage, fmt.Errorf("audit log: %w", c.Audit().OpenErr())), c.Stop())
	}
	limiter := pipeline.NewLimiter(c.Settings().Limits.RateCounters)
	enforcement, err := newHandler(c, limiter, cfg.limits, proxy.Forward, cfg.signer)
	if err != nil {
		return nil, errors.Join(classify(ErrConfig, err), c.Stop())
	}
	d := &deployment{
		config:      cfg,
		controller:  c,
		enforcement: enforcement,
		limiter:     limiter,
		ui:          ui,
		logger:      logger,
		certificate: certificate,
		upstreams:   proxy,
	}
	readyFn := func() bool { return !d.draining.Load() && ready(c, certificate) }
	d.metrics = auxiliaryServer(health(monitor.Metrics(c.Observations(), func() []monitor.Gauge { return gauges(c, proxy) }), readyFn))
	if cfg.healthListen != "" {
		d.health = auxiliaryServer(health(http.NotFoundHandler(), readyFn))
	}
	return d, nil
}

// auxiliaryServer returns an HTTP server with the bounds shared by the
// metrics and health listeners: 5 s bounds a stuck scraper without failing a
// slow one; 30 s idle keeps a scraper's connection between 15 s scrapes.
func auxiliaryServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    defaultHeaderBytes,
	}
}

// openController checks cfg, reads the dashboard files in ui (none when
// empty) and opens the controller's deployment. Its errors are classified:
// ErrConfig for the settings and the dashboard files, ErrLocked when another
// process holds the deployment, ErrStorage when the database cannot be
// opened. The files are read before the database is opened, so a wrong
// directory changes nothing.
func openController(cfg controller.Config, ui string, logger *slog.Logger) (*controller.Controller, fs.FS, error) {
	c, err := controller.Prepare(cfg, logger)
	if err != nil {
		return nil, nil, classify(ErrConfig, err)
	}
	files, source, err := dashboardFiles(ui, adminui.Files)
	if err != nil {
		return nil, nil, classify(ErrConfig, err)
	}
	logger.Info("dashboard files", "source", source)
	if err := c.Open(); err != nil {
		if errors.Is(err, store.ErrHeld) {
			return nil, nil, classify(ErrLocked, err)
		}
		return nil, nil, classify(ErrStorage, err)
	}
	return c, files, nil
}

// listen binds the metrics address, and the health address when one is
// configured, and starts the Admin API. It returns the capped metrics
// listener and the optional capped health listener (nil when unset), served
// by d.metrics and d.health respectively. plain is true when the gateway
// serves the data plane itself, over plain HTTP; hostServed when a host
// program serves it (library mode). On an error none stays bound; the
// caller releases the deployment.
func (d *deployment) listen(plain, hostServed bool) (metrics, health net.Listener, err error) {
	metrics, err = net.Listen("tcp", d.config.metricsListen)
	if err != nil {
		return nil, nil, classify(ErrListen, fmt.Errorf("metrics listener: %w", err))
	}
	metrics = connections.Cap(metrics, connections.Auxiliary, d.controller.Observations().Refuser("metrics"))
	if d.config.healthListen != "" {
		health, err = net.Listen("tcp", d.config.healthListen)
		if err != nil {
			metrics.Close()
			return nil, nil, classify(ErrListen, fmt.Errorf("health listener: %w", err))
		}
		d.healthListen = health.Addr().String()
		health = connections.Cap(health, connections.Auxiliary, d.controller.Observations().Refuser("health"))
	}
	var ui http.Handler // nil when no files are configured: the routes stay unregistered
	if d.ui != nil {
		ui = dashboard(d.ui)
	}
	if err := d.controller.Start(admin.New(admin.Deps{Control: d.controller, Limiter: d.limiter, UI: ui, Plain: plain, HostServed: hostServed, Logger: d.logger, JWKS: d.config.signer.JWKS()}).Handler()); err != nil {
		closeListeners(metrics, health)
		return nil, nil, classify(ErrListen, fmt.Errorf("admin listener: %w", err))
	}
	// Every listener is bound by now: the native data listener before this.
	recordStart(d.controller, d.config)
	return metrics, health, nil
}

// logAdmission reports whether protected requests are admitted: listening
// does not mean they are, as the deployment may be in bootstrap or recovery,
// without usable authority, or without its audit log.
func (d *deployment) logAdmission(logger *slog.Logger) {
	attrs := []any{"admission", d.controller.Admission()}
	if current := d.controller.Current(); current != nil {
		attrs = append(attrs, "generation", current.ID, "revision", current.Revision)
	}
	logger.Info("protected admission", attrs...)
}

// newHandler returns the enforcement handler for the policy c publishes,
// counting rates in limiter, within limits (a zero member selects its
// default). forward is called only for admitted requests, each carrying an
// identity assertion when signer is set.
func newHandler(c *controller.Controller, limiter *pipeline.Limiter, limits pipeline.Limits, forward pipeline.Forward, signer *pipeline.Signer) (*pipeline.Handler, error) {
	d := pipeline.Deps{Limiter: limiter, Clock: pipeline.NewClock(), Limits: limits, Forward: forward, Signer: signer}
	// A nil controller leaves its dependencies unset, which pipeline.New refuses.
	if c != nil {
		d.Authority, d.Audit, d.Observations = c, c.Audit(), c.Observations()
		d.AuditTimeout = c.Settings().AuditTimeout
	}
	return pipeline.New(d)
}

// ready reports whether the gateway can admit requests: the controller is in
// normal mode with a published policy, the security log has not failed, and
// the data listener's certificate, if any, is valid now.
func ready(c *controller.Controller, certificate *servingCertificate) bool {
	if c.State() != store.ModeNormal || c.Current() == nil || c.Audit().Failed() {
		return false
	}
	return certificate == nil || certificate.valid(time.Now())
}

// gauges are the controller's figures with the upstream pool's and the
// auxiliary listeners'.
func gauges(c *controller.Controller, proxy interface{ Stats() forward.Stats }) []monitor.Gauge {
	pool := proxy.Stats()
	return append(c.Gauges(),
		monitor.Gauge{Name: "gateway_upstream_connections_idle", Value: pool.Idle},
		monitor.Gauge{Name: "gateway_upstream_dials_total", Value: pool.Dials, Counter: true},
		monitor.Gauge{Name: "gateway_upstream_reuses_total", Value: pool.Reuses, Counter: true},
		monitor.Gauge{Name: "gateway_listener_failures_total", Value: auxiliaryFailures.Load(), Counter: true},
	)
}
