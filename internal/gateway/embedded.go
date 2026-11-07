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
	"sync"
	"sync/atomic"
)

// Embedded is one gateway whose data plane a host program serves. Its
// methods are safe for concurrent use.
type Embedded struct {
	deployment *deployment
	logger     *slog.Logger
	calls      calls

	mu       sync.Mutex
	started  bool
	stopping bool

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
	d, err := openDeployment(*settings.native, logger)
	if err != nil {
		return nil, err
	}
	d.enforcement.held.Store(true)
	return &Embedded{deployment: d, logger: logger, calls: calls{idle: make(chan struct{}, 1)}}, nil
}

// Start binds the metrics listener, starts the Admin API and then admits
// requests. It succeeds at most once (ErrStarted), never after Stop began
// (ErrStopped); when it fails otherwise (ErrListen), the gateway is stopped
// and released.
func (e *Embedded) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	switch {
	case e.stopping:
		return classify(ErrStopped, errors.New("the gateway was stopped"))
	case e.started:
		return classify(ErrStarted, errors.New("the gateway was already started"))
	}
	metrics, err := e.deployment.listen()
	if err != nil {
		e.stopping = true
		ctx, cancel := context.WithTimeout(context.Background(), adminShutdownWait)
		defer cancel()
		return errors.Join(err, e.stop(ctx))
	}
	e.started = true
	go func() {
		if err := e.deployment.metrics.Serve(metrics); !errors.Is(err, http.ErrServerClosed) {
			e.logger.Error("metrics listener failed", "error", err)
		}
	}()
	e.deployment.enforcement.held.Store(false)
	e.logger.Info("listening", "metrics", metrics.Addr().String(), "admin", e.deployment.config.controller.AdminListen,
		"data", "served by the host program; data.listen is not bound")
	e.deployment.logAdmission(e.logger)
	return nil
}

// ServeHTTP runs the data plane: the full request pipeline, and the website
// when one is configured.
func (e *Embedded) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.calls.enter()
	defer e.calls.leave()
	e.deployment.handler.ServeHTTP(w, r)
}

// ServerSettings returns the configured limits for the host's server.
func (e *Embedded) ServerSettings() ServerSettings { return e.deployment.config.server() }

// Stop ends admission (later requests are refused with 503), stops the
// metrics listener, waits for ServeHTTP calls in progress, then stops the
// Admin API, writes the queued audit events and closes the database. ctx
// bounds the waits. It runs once; every call returns the first call's
// result, nil only when every step completed, else ErrIncomplete. It also
// releases a gateway that was never started.
func (e *Embedded) Stop(ctx context.Context) error {
	e.mu.Lock()
	e.stopping = true
	e.mu.Unlock()
	return e.stop(ctx)
}

func (e *Embedded) stop(ctx context.Context) error {
	e.stopOnce.Do(func() { e.stopErr = e.shutdown(ctx) })
	return e.stopErr
}

func (e *Embedded) shutdown(ctx context.Context) error {
	c := e.deployment.controller
	c.beginStop()
	var errs []error
	if err := e.deployment.metrics.Shutdown(ctx); err != nil {
		errs = append(errs, fmt.Errorf("metrics listener shutdown: %w", err), e.deployment.metrics.Close())
	}
	// Requests write audit events until they return, so they finish before
	// the audit log closes; one still running when ctx ends is counted lost.
	if err := e.calls.wait(ctx); err != nil {
		errs = append(errs, fmt.Errorf("requests in progress: %w", err))
	}
	errs = append(errs, c.stopWithin(ctx))
	if err := errors.Join(errs...); err != nil {
		return classify(ErrIncomplete, err)
	}
	return nil
}

// calls counts ServeHTTP calls in progress so that Stop can wait for them.
type calls struct {
	active   atomic.Int64
	draining atomic.Bool
	idle     chan struct{} // buffered; signalled when active reaches zero while draining
}

func (q *calls) enter() { q.active.Add(1) }

func (q *calls) leave() {
	if q.active.Add(-1) == 0 && q.draining.Load() {
		select {
		case q.idle <- struct{}{}:
		default:
		}
	}
}

// wait returns once no call is in progress, or ctx's error. A call may enter
// after draining began (it is refused); wait then waits for it too.
func (q *calls) wait(ctx context.Context) error {
	q.draining.Store(true)
	for q.active.Load() != 0 {
		select {
		case <-q.idle:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}
