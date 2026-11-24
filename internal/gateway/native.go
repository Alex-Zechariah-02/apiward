// The native gateway: the controller, its enforcement handler and the native
// proxy, served by the project's own net/http data-plane server. Its command
// line is in command.go.

package gateway

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/connections"
	"github.com/Alex-Zechariah-02/apiward/internal/controller"
)

// Exit statuses of the native run command.
const (
	exitStopped    = 0 // stopped gracefully and completely
	exitFailed     = 1 // could not start, or the data plane failed
	exitForced     = 2 // a second signal ended the graceful stop
	exitIncomplete = 3 // the graceful stop did not complete
)

// runNative starts the gateway, serves until the first interrupt or
// termination signal, then stops it gracefully. A second signal forces the
// process to exit at once.
func runNative(configPath string, logger *slog.Logger) int {
	// Signals are taken before startup, so one that arrives while the
	// gateway is starting stops it gracefully once it has started.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	// SIGHUP reloads the data listener's certificate (no effect on Windows);
	// one pending signal is enough, as a reload reads the files as they are.
	hangups := make(chan os.Signal, 1)
	signal.Notify(hangups, syscall.SIGHUP)
	defer signal.Stop(hangups)

	settings, err := LoadSettings(configPath)
	if err != nil {
		logger.Error("configuration refused", "error", err)
		return exitFailed
	}
	g, err := startNative(*settings.native, logger)
	if err != nil {
		logger.Error("startup failed", "error", err)
		return exitFailed
	}

	status := exitStopped
	for running := true; running; {
		select {
		case <-hangups:
			if g.certificate != nil {
				g.certificate.reload()
			}
		case sig := <-signals:
			logger.Info("stopping", "signal", sig.String())
			running = false
		// The data plane is the gateway: without it the process stops
		// rather than serve the Admin API alone.
		case err := <-g.served:
			logger.Error("the data listener failed; stopping", "error", err)
			status, running = exitFailed, false
		}
	}
	go func() {
		<-signals
		logger.Error("forced exit: a second signal arrived before the graceful stop completed")
		os.Exit(exitForced)
	}()
	if err := g.stop(); err != nil {
		logger.Error("stop incomplete", "error", err)
		return exitIncomplete
	}
	logger.Info("stopped")
	return status
}

// nativeGateway is one running native gateway.
type nativeGateway struct {
	controller *controller.Controller
	data       *http.Server
	metrics    *http.Server
	health     *http.Server // nil without a health listener
	redirect   *http.Server // nil without a redirect listener
	// certificate is the data listener's; nil when it serves plain HTTP.
	certificate *servingCertificate
	upstreams   upstreams
	// served receives the data-plane server's Serve result; done closes when
	// the stop begins.
	served chan error
	done   chan struct{}
	stop   func() error
	// draining makes /readyz answer 503; set for delay before the
	// listeners stop, all of which then share grace.
	draining *atomic.Bool
	grace    time.Duration
	delay    time.Duration
}

// startNative opens the deployment for cfg and serves it: the controller with
// its Admin API, and the data plane. Nothing listens before the controller
// holds the database and has published, or refused to publish, the effective
// policy, and the data-plane address is bound before the Admin API starts, so
// a failure leaves nothing served. When it returns an error, everything it
// acquired is released.
func startNative(cfg nativeConfig, logger *slog.Logger) (*nativeGateway, error) {
	d, err := openDeployment(cfg, logger)
	if err != nil {
		return nil, err
	}
	c := d.controller
	listener, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		return nil, errors.Join(classify(ErrListen, fmt.Errorf("data listener: %w", err)), c.Stop())
	}
	redirectListener, err := listenRedirect(cfg.redirect)
	if err != nil {
		listener.Close()
		return nil, errors.Join(err, c.Stop())
	}
	metricsListener, healthListener, err := d.listen(d.certificate == nil, false)
	if err != nil {
		closeListeners(listener, redirectListener)
		return nil, errors.Join(err, c.Stop())
	}
	listener = connections.CapPerAddress(listener, cfg.maxConnections, cfg.perAddress, c.Observations().ConnectionRefused)
	if redirectListener != nil {
		// The redirect listener faces the same clients as the data listener.
		redirectListener = connections.Cap(redirectListener, cfg.maxConnections, c.Observations().Refuser("redirect"))
	}
	server := cfg.server()
	server.countError = c.Observations().HTTP2Error
	// HTTP/2 only over TLS, negotiated by ALPN: a plain listener serves
	// HTTP/1 alone, so a client cannot start HTTP/2 by prior knowledge.
	server.HTTP2 = server.HTTP2 && d.certificate != nil
	if d.certificate != nil {
		listener = tls.NewListener(listener, d.certificate.config(server.HTTP2))
	}
	// #nosec G112 -- server.Apply below sets the header and other timeouts
	data := &http.Server{
		Handler: d.enforcement,
		// "OPTIONS *" reaches enforcement, which refuses every target that
		// is not in origin form, instead of being answered by net/http.
		DisableGeneralOptionsHandler: true,
		ErrorLog:                     slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	server.Apply(data)
	g := &nativeGateway{controller: c, data: data, metrics: d.metrics, health: d.health, certificate: d.certificate, upstreams: d.upstreams, served: make(chan error, 1), done: make(chan struct{}),
		draining: &d.draining, grace: d.config.shutdownGrace, delay: d.config.shutdownDelay}
	// A second stop, from a signal or the run loop, returns the first's result.
	g.stop = sync.OnceValue(g.shutdown)
	go func() { g.served <- g.data.Serve(listener) }()
	go serveAuxiliary("metrics", g.metrics, metricsListener, logger)
	if healthListener != nil {
		go serveAuxiliary("health", g.health, healthListener, logger)
	}
	if redirectListener != nil {
		g.redirect = redirectServer(cfg.redirect.Origin, c.Observations(), server)
		go serveAuxiliary("redirect", g.redirect, redirectListener, logger)
	}
	if g.certificate != nil {
		go g.certificate.watchExpiry(g.done)
	}

	transport := "http"
	if g.certificate != nil {
		transport = "https"
	}
	logger.Info("listening", "data", listener.Addr().String(), "transport", transport, "http2", server.HTTP2, "admin", cfg.controller.AdminListen, "metrics", metricsListener.Addr().String(), "health", d.healthListen)
	d.logAdmission(logger)
	return g, nil
}
