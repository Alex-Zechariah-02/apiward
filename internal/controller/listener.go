// The Admin API listener, which the controller starts and stops under its lock.

package controller

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/connections"
)

// startAdmin serves handler, the Admin API, on its loopback listener, which is
// separate from the data plane, so client traffic can never reach it. The
// caller holds c.mu.
func (c *Controller) startAdmin(handler http.Handler) error {
	listener, err := net.Listen("tcp", c.config.AdminListen)
	if err != nil {
		return err
	}
	listener = connections.Cap(listener, connections.Auxiliary, c.observations.Refuser("admin"))
	c.admin = &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	go func(admin *http.Server) {
		if err := admin.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			c.logger.Error("admin listener stopped", "error", err)
		}
	}(c.admin)
	return nil
}

// stopAdmin stops a started Admin API server (nil: none was started). It
// waits until ctx is done for requests in progress; if any remain, it closes
// their connections and reports the incomplete shutdown.
func stopAdmin(ctx context.Context, admin *http.Server) error {
	if admin == nil {
		return nil
	}
	if err := admin.Shutdown(ctx); err != nil {
		return errors.Join(fmt.Errorf("admin listener shutdown: %w", err), admin.Close())
	}
	return nil
}
