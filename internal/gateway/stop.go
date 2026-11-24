// Stopping the native gateway: listeners first, then the upstream
// connections, then the controller with its audit log and database.

package gateway

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// upstreams is the upstream proxy as a deployment owns it: its idle
// connections close when the deployment stops.
type upstreams interface{ Close() }

// shutdown stops the gateway gracefully. /readyz answers 503 first, for the
// configured delay while every listener still serves, so a load balancer
// stops sending requests; then the data and redirect listeners stop accepting
// connections and their requests in progress finish while the published policy
// stays in force, admission ends, the health and metrics listeners stop, the
// idle upstream connections close, then the controller stops its Admin API the
// same way, writes the audit events queued until then and closes the
// database. Requests in progress on every listener share one wait of grace;
// the audit drain keeps its own AuditDrainWait. It returns nil only when
// every step completed.
func (g *nativeGateway) shutdown() error {
	g.draining.Store(true)
	time.Sleep(g.delay)
	close(g.done)
	ctx, cancel := context.WithTimeout(context.Background(), g.grace)
	defer cancel()
	// Close the data listener before withdrawing the policy so no client
	// meets an open data socket answering 503 during shutdown.
	if g.dataListener != nil {
		g.dataListener.Close()
	}
	// Drain the data server while BeginStop marks the controller stopping so
	// /admin/status and /admin/health report stopping during the drain.
	dataErr := make(chan error, 1)
	go func() {
		if err := g.data.Shutdown(ctx); err != nil {
			// Requests still running are cut off; their clients see their
			// connections close.
			dataErr <- errors.Join(fmt.Errorf("data listener shutdown: %w", err), g.data.Close())
			return
		}
		dataErr <- nil
	}()
	g.controller.BeginStop()
	var errs []error
	if err := <-dataErr; err != nil {
		errs = append(errs, err)
	}
	if g.redirect != nil {
		if err := g.redirect.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("redirect listener shutdown: %w", err), g.redirect.Close())
		}
	}
	// The health and metrics listeners stop after the data plane drained,
	// so /readyz keeps answering 503 throughout the drain; the controller
	// stops last so no listener answers after the database and audit log close.
	if g.health != nil {
		if err := g.health.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("health listener shutdown: %w", err), g.health.Close())
		}
	}
	if err := g.metrics.Shutdown(ctx); err != nil {
		errs = append(errs, fmt.Errorf("metrics listener shutdown: %w", err), g.metrics.Close())
	}
	g.upstreams.Close()
	errs = append(errs, g.controller.StopWithin(ctx))
	return errors.Join(errs...)
}
