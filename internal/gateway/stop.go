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
// stops sending requests; then admission ends, the data plane stops
// accepting connections and its requests in progress finish, the idle
// upstream connections close, then the controller stops its Admin API the
// same way, writes the audit events queued until then and closes the
// database. Requests in progress on every listener share one wait of grace;
// the audit drain keeps its own AuditDrainWait. It returns nil only when
// every step completed.
func (g *nativeGateway) shutdown() error {
	g.draining.Store(true)
	time.Sleep(g.delay)
	g.controller.BeginStop()
	close(g.done)
	ctx, cancel := context.WithTimeout(context.Background(), g.grace)
	defer cancel()
	var errs []error
	if g.redirect != nil {
		if err := g.redirect.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("redirect listener shutdown: %w", err), g.redirect.Close())
		}
	}
	if err := g.metrics.Shutdown(ctx); err != nil {
		errs = append(errs, fmt.Errorf("metrics listener shutdown: %w", err), g.metrics.Close())
	}
	if err := g.data.Shutdown(ctx); err != nil {
		// Requests still running are cut off; their clients see their
		// connections close.
		errs = append(errs, fmt.Errorf("data listener shutdown: %w", err), g.data.Close())
	}
	g.upstreams.Close()
	errs = append(errs, g.controller.StopWithin(ctx))
	return errors.Join(errs...)
}
