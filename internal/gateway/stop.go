// Stopping the native gateway: listeners first, then the upstream
// connections, then the controller with its audit log and database.

package gateway

import (
	"context"
	"errors"
	"fmt"

	"github.com/Alex-Zechariah-02/apiward/internal/controller"
)

// upstreams is the upstream proxy as a deployment owns it: its idle
// connections close when the deployment stops.
type upstreams interface{ Close() }

// shutdown stops the gateway gracefully: admission ends first, then the data
// plane stops accepting connections and its requests in progress finish, the
// idle upstream connections close, then the controller stops its Admin API
// the same way, writes the audit events queued until then and closes the
// database. Requests in progress on
// both listeners share one wait of ShutdownWait; the audit drain has its
// own auditDrainWait. It returns nil only when every step completed.
func (g *nativeGateway) shutdown() error {
	g.controller.BeginStop()
	close(g.done)
	ctx, cancel := context.WithTimeout(context.Background(), controller.ShutdownWait)
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
