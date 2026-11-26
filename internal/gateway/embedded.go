// The gateway embedded in a host program: the host serves the data plane on
// its own server, the gateway keeps everything else (Admin API, metrics,
// database, audit log, start and stop). Opened, then started once, then
// stopped once; requests are admitted only while started.

package gateway

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
)

type embedState uint8

const (
	embedOpened embedState = iota
	embedStarted
	embedStopped
)

// Embedded is one gateway whose data plane a host program serves. Its
// methods are safe for concurrent use.
type Embedded struct {
	deployment *deployment
	logger     *slog.Logger
	calls      calls

	mu    sync.Mutex
	state embedState

	stopOnce sync.Once
	stopErr  error
}

// OpenEmbedded opens the deployment settings name, as the run command would,
// without binding any listener. Until Start, every request is refused with
// 503 gateway_unavailable and recorded.
func OpenEmbedded(settings Settings, logger *slog.Logger) (*Embedded, error) {
	if settings.native == nil {
		return nil, classify(ErrConfig, errors.New("the settings were not loaded"))
	}
	if logger == nil {
		return nil, classify(ErrConfig, errors.New("a logger is required"))
	}
	if unapplied := hostIgnored(settings.native.file.Data); len(unapplied) > 0 {
		return nil, classify(ErrConfig, fmt.Errorf("the host program serves the data plane, so these settings would not apply: %s", strings.Join(unapplied, ", ")))
	}
	d, err := openDeployment(*settings.native, logger)
	if err != nil {
		return nil, err
	}
	d.enforcement.Hold(true)
	return &Embedded{deployment: d, logger: logger, calls: calls{idle: make(chan struct{}, 1)}}, nil
}

// Start binds the metrics listener, starts the Admin API and then admits
// requests. It succeeds at most once (ErrStarted), never after Stop began
// (ErrStopped); when it fails otherwise (ErrListen), the gateway is stopped
// and released.
func (e *Embedded) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	switch e.state {
	case embedStopped:
		return classify(ErrStopped, errors.New("the gateway was stopped"))
	case embedStarted:
		return classify(ErrStarted, errors.New("the gateway was already started"))
	}
	metricsListener, healthListener, err := e.deployment.listen(false, true)
	if err != nil {
		e.state = embedStopped
		ctx, cancel := context.WithTimeout(context.Background(), controller.ShutdownWait)
		defer cancel()
		return errors.Join(err, e.stop(ctx))
	}
	e.state = embedStarted
	go serveAuxiliary("metrics", e.deployment.metrics, metricsListener, e.logger)
	if healthListener != nil {
		go serveAuxiliary("health", e.deployment.health, healthListener, e.logger)
	}
	e.deployment.enforcement.Hold(false)
	e.logger.Info("listening", "metrics", metricsListener.Addr().String(), "health", e.deployment.healthListen, "admin", e.deployment.config.controller.AdminListen,
		"data", "served by the host program; data.listen is not bound")
	e.deployment.logAdmission(e.logger)
	return nil
}

// ServeHTTP runs the data plane: the full request pipeline for every request.
// Once Stop has waited for the calls in progress, a later call is refused
// 503 before it reaches the pipeline, whose audit log is closing.
func (e *Embedded) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !e.calls.enter() {
		pipeline.WriteJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "gateway_unavailable"})
		return
	}
	defer e.calls.leave()
	e.deployment.enforcement.ServeHTTP(w, r)
}

// Server returns the host's data-plane server with the configured header
// size, timeouts and protocols already set, serving handler (nil: the
// gateway itself); its HTTP/2 protocol errors are counted in the gateway's
// metrics. The host sets only its address or listener and TLS, so it cannot
// forget the bounds that stop slow and oversized clients.
func (e *Embedded) Server(handler http.Handler) *http.Server {
	if handler == nil {
		handler = e
	}
	s := e.deployment.config.server()
	s.countError = e.deployment.controller.Observations().HTTP2Error
	server := &http.Server{Handler: handler} // #nosec G112 -- Apply sets the header and other timeouts
	s.Apply(server)
	return server
}

// hostIgnored names the data-plane settings that only the gateway's own
// listener applies: a host program's server has its own TLS, connection
// limit and addresses. data.listen stays required and is never bound.
func hostIgnored(d dataSettings) []string {
	var names []string
	for _, s := range []struct {
		name string
		set  bool
	}{
		{"data.tls", d.TLS != nil},
		{"data.redirect_http", d.RedirectHTTP != nil},
		{"data.max_connections", d.MaxConnections != nil},
		{"data.max_connections_per_address", d.MaxConnectionsPerAddress != nil},
		{"data.listen_all_interfaces", d.ListenAllInterfaces},
	} {
		if s.set {
			names = append(names, s.name)
		}
	}
	return names
}

// Stop ends admission (later requests are refused with 503), stops the
// metrics listener, waits for ServeHTTP calls in progress, then stops the
// Admin API, writes the queued audit events and closes the database. ctx
// bounds the waits. It runs once; every call returns the first call's
// result, nil only when every step completed, else ErrIncomplete. It also
// releases a gateway that was never started.
func (e *Embedded) Stop(ctx context.Context) error {
	e.mu.Lock()
	e.state = embedStopped
	e.mu.Unlock()
	return e.stop(ctx)
}

func (e *Embedded) stop(ctx context.Context) error {
	e.stopOnce.Do(func() { e.stopErr = e.shutdown(ctx) })
	return e.stopErr
}

func (e *Embedded) shutdown(ctx context.Context) error {
	c := e.deployment.controller
	c.BeginStop()
	var errs []error
	if e.deployment.health != nil {
		if err := e.deployment.health.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("health listener shutdown: %w", err), e.deployment.health.Close())
		}
	}
	if err := e.deployment.metrics.Shutdown(ctx); err != nil {
		errs = append(errs, fmt.Errorf("metrics listener shutdown: %w", err), e.deployment.metrics.Close())
	}
	// Requests write audit events until they return, so they finish before
	// the audit log closes; one still running when ctx ends is counted lost.
	if err := e.calls.wait(ctx); err != nil {
		errs = append(errs, fmt.Errorf("requests in progress: %w", err))
	}
	e.deployment.upstreams.Close()
	errs = append(errs, c.StopWithin(ctx))
	if err := errors.Join(errs...); err != nil {
		return classify(ErrIncomplete, err)
	}
	return nil
}

type callsState int32

const (
	callsOpen callsState = iota
	callsDraining
	callsClosed
)

// calls counts ServeHTTP calls in progress so that Stop can wait for them.
type calls struct {
	active atomic.Int64
	state  atomic.Int32  // callsState: open -> draining -> closed
	idle   chan struct{} // buffered; signalled when active reaches zero once draining
}

// enter counts a call in, or refuses it once the calls are closed. A call
// that counted itself before closed was set is one wait still waits for.
func (q *calls) enter() bool {
	q.active.Add(1)
	if callsState(q.state.Load()) == callsClosed {
		q.leave()
		return false
	}
	return true
}

func (q *calls) leave() {
	if q.active.Add(-1) == 0 && callsState(q.state.Load()) != callsOpen {
		select {
		case q.idle <- struct{}{}:
		default:
		}
	}
}

// wait returns once no call is in progress and no later call can enter, or
// ctx's error. A call that entered after draining began is refused by the
// pipeline; wait waits for it too, then closes the calls and waits again for
// any that counted itself in before seeing them closed.
func (q *calls) wait(ctx context.Context) error {
	q.state.CompareAndSwap(int32(callsOpen), int32(callsDraining))
	if err := q.drain(ctx); err != nil {
		return err
	}
	q.state.CompareAndSwap(int32(callsDraining), int32(callsClosed))
	return q.drain(ctx)
}

// drain waits until no call is counted in, or ctx ends.
func (q *calls) drain(ctx context.Context) error {
	// No bound of its own: Stop's caller sets it through ctx.
	for q.active.Load() != 0 {
		select {
		case <-q.idle:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}
