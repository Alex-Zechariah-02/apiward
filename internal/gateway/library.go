// What the standalone binary and an embedding host program both run: the
// checked settings, the opened deployment (controller, enforcement handler,
// metrics server), its listeners, the data-plane server limits and the
// classified errors of the gateway's lifecycle.

package gateway

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/forward"
	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
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
		err = operatorPaths(path, cfg.controller, "run", nil)
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
	controller  *Controller
	enforcement *pipeline.Handler
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
	c, err := NewController(cfg.controller, logger)
	if err != nil {
		return nil, err
	}
	// A log that cannot be opened refuses every admission and every change
	// for as long as the process runs; a running gateway could only report it.
	if c.audit.OpenErr() != nil {
		return nil, errors.Join(classify(ErrStorage, fmt.Errorf("audit log: %w", c.audit.OpenErr())), c.Stop())
	}
	enforcement, err := newHandler(c, cfg.maxBodyBytes, proxy.Forward)
	if err != nil {
		return nil, errors.Join(classify(ErrConfig, err), c.Stop())
	}
	return &deployment{
		config:      cfg,
		controller:  c,
		enforcement: enforcement,
		handler:     dataPlane(enforcement, cfg.website),
		metrics: &http.Server{
			Handler:           monitor.Metrics(c.observations, c.gauges),
			ReadHeaderTimeout: 5 * time.Second,
			WriteTimeout:      5 * time.Second,
			IdleTimeout:       30 * time.Second,
			MaxHeaderBytes:    defaultHeaderBytes,
		},
	}, nil
}

// listen binds the metrics address and starts the Admin API. On an error
// neither stays bound; the caller releases the deployment.
func (d *deployment) listen() (net.Listener, error) {
	metrics, err := net.Listen("tcp", d.config.metricsListen)
	if err != nil {
		return nil, classify(ErrListen, fmt.Errorf("metrics listener: %w", err))
	}
	if err := d.controller.Start(); err != nil {
		metrics.Close()
		return nil, classify(ErrListen, fmt.Errorf("admin listener: %w", err))
	}
	return metrics, nil
}

// logAdmission reports whether protected requests are admitted: listening
// does not mean they are, as the deployment may be in bootstrap or recovery,
// without usable authority, or without its audit log.
func (d *deployment) logAdmission(logger *slog.Logger) {
	attrs := []any{"admission", d.controller.admission()}
	if current := d.controller.Current(); current != nil {
		attrs = append(attrs, "generation", current.ID, "revision", current.Revision)
	}
	logger.Info("protected admission", attrs...)
}

// newHandler returns the enforcement handler for the policy c publishes. A
// maxBodyBytes of zero or less selects the default ceiling. forward is called
// only for admitted requests.
func newHandler(c *Controller, maxBodyBytes int64, forward pipeline.Forward) (*pipeline.Handler, error) {
	d := pipeline.Deps{MaxBodyBytes: maxBodyBytes, Forward: forward}
	// A nil controller leaves every dependency unset, which newPipeline refuses.
	if c != nil {
		d.Authority, d.Audit, d.Observations = c, c.audit, c.observations
		d.Limiter, d.Clock, d.AuditTimeout = c.limiter, c.clock, c.config.AuditTimeout
	}
	return pipeline.New(d)
}
