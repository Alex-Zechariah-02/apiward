// What the standalone binary and an embedding host program both run: the
// checked settings, the opened deployment (controller, enforcement handler,
// metrics server), its listeners, the data-plane server limits and the
// classified errors of the gateway's lifecycle.

package gateway

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/admin"
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
	cfg, err := loadNativeConfig(path)
	if err == nil {
		err = operator.CheckPaths(path, operatorConfig(cfg.controller), "run", nil)
	}
	if err != nil {
		return Settings{}, classify(ErrConfig, err)
	}
	return Settings{native: &cfg}, nil
}

// ServerSettings are the configured limits of the server that runs the data
// plane. Header size and the timeouts bound slow and oversized clients; the
// gateway cannot enforce them on a server it does not own.
type ServerSettings struct {
	MaxHeaderBytes    int
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
}

// Apply sets the limits on server, replacing its own values for them.
func (s ServerSettings) Apply(server *http.Server) {
	server.MaxHeaderBytes = s.MaxHeaderBytes
	server.ReadHeaderTimeout = s.ReadHeaderTimeout
	server.ReadTimeout = s.ReadTimeout
	server.WriteTimeout = s.WriteTimeout
	server.IdleTimeout = s.IdleTimeout
}

func (cfg nativeConfig) server() ServerSettings {
	return ServerSettings{
		MaxHeaderBytes:    cfg.headerLimit,
		ReadHeaderTimeout: cfg.readHeaderTimeout,
		ReadTimeout:       cfg.readTimeout,
		WriteTimeout:      cfg.writeTimeout,
		IdleTimeout:       cfg.idleTimeout,
	}
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
	ui     fs.FS
	logger *slog.Logger
	// handler is the data plane: enforcement, and the website when one is
	// configured.
	handler http.Handler
	metrics *http.Server
}

// openDeployment opens cfg's deployment and builds its handlers; it binds no
// listener. When it returns an error, everything it opened is released.
func openDeployment(cfg nativeConfig, logger *slog.Logger) (*deployment, error) {
	proxy, err := forward.NewUpstreamProxy(cfg.upstream, logger)
	if err != nil {
		return nil, classify(ErrConfig, err)
	}
	c, ui, err := openController(cfg.controller, cfg.adminUI, logger)
	if err != nil {
		return nil, err
	}
	// A log that cannot be opened refuses every admission and every change
	// for as long as the process runs; a running gateway could only report it.
	if c.Audit().OpenErr() != nil {
		return nil, errors.Join(classify(ErrStorage, fmt.Errorf("audit log: %w", c.Audit().OpenErr())), c.Stop())
	}
	limiter := pipeline.NewLimiter()
	enforcement, err := newHandler(c, limiter, cfg.maxBodyBytes, proxy.Forward)
	if err != nil {
		return nil, errors.Join(classify(ErrConfig, err), c.Stop())
	}
	return &deployment{
		config:      cfg,
		controller:  c,
		enforcement: enforcement,
		limiter:     limiter,
		ui:          ui,
		logger:      logger,
		handler:     dataPlane(enforcement, cfg.website),
		metrics: &http.Server{
			Handler:           monitor.Metrics(c.Observations(), c.Gauges),
			ReadHeaderTimeout: 5 * time.Second,
			WriteTimeout:      5 * time.Second,
			IdleTimeout:       30 * time.Second,
			MaxHeaderBytes:    defaultHeaderBytes,
		},
	}, nil
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
	var files fs.FS
	if ui != "" {
		if files, err = frontendFiles("admin_ui", ui); err != nil {
			return nil, nil, classify(ErrConfig, err)
		}
	}
	if err := c.Open(); err != nil {
		if errors.Is(err, store.ErrHeld) {
			return nil, nil, classify(ErrLocked, err)
		}
		return nil, nil, classify(ErrStorage, err)
	}
	return c, files, nil
}

// listen binds the metrics address and starts the Admin API. plain is true
// when the gateway serves the data plane itself, over plain HTTP. On an
// error neither stays bound; the caller releases the deployment.
func (d *deployment) listen(plain bool) (net.Listener, error) {
	metrics, err := net.Listen("tcp", d.config.metricsListen)
	if err != nil {
		return nil, classify(ErrListen, fmt.Errorf("metrics listener: %w", err))
	}
	var ui http.Handler // nil when no files are configured: the routes stay unregistered
	if d.ui != nil {
		ui = dashboard(d.ui)
	}
	if err := d.controller.Start(admin.New(admin.Deps{Control: d.controller, Limiter: d.limiter, UI: ui, Plain: plain, Logger: d.logger}).Handler()); err != nil {
		metrics.Close()
		return nil, classify(ErrListen, fmt.Errorf("admin listener: %w", err))
	}
	return metrics, nil
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
// counting rates in limiter. A maxBodyBytes of zero or less selects the
// default ceiling. forward is called only for admitted requests.
func newHandler(c *controller.Controller, limiter *pipeline.Limiter, maxBodyBytes int64, forward pipeline.Forward) (*pipeline.Handler, error) {
	d := pipeline.Deps{Limiter: limiter, Clock: pipeline.NewClock(), MaxBodyBytes: maxBodyBytes, Forward: forward}
	// A nil controller leaves its dependencies unset, which pipeline.New refuses.
	if c != nil {
		d.Authority, d.Audit, d.Observations = c, c.Audit(), c.Observations()
		d.AuditTimeout = c.Settings().AuditTimeout
	}
	return pipeline.New(d)
}
