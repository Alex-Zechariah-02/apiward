// The HTTP-to-HTTPS redirect listener, and how the auxiliary listeners
// (redirect, metrics and health) are served: a failure of one stops only it.

package gateway

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"

	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
)

// redirectSettings is the HTTP listener that sends every client to origin.
type redirectSettings struct {
	Listen string `json:"listen"`
	Origin string `json:"origin"`
}

// redirect answers every request with 308 to origin plus the request's path
// and query, and counts each 308. The target host comes only from origin; the
// body is never read, and the connection closes after the answer. A target
// not in origin form, such as "OPTIONS *", is answered 400, uncounted.
func redirect(origin string, observed *monitor.Observations) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		w.Header().Set("Content-Length", "0")
		target := r.URL.RequestURI()
		if target == "" || target[0] != '/' {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Location", origin+target)
		w.WriteHeader(http.StatusPermanentRedirect)
		observed.Redirected()
	})
}

// redirectServer serves the redirect with the data listener's header and
// write timeouts and header limit: it reads only request headers.
func redirectServer(origin string, observed *monitor.Observations, data ServerSettings) *http.Server {
	s := &http.Server{
		Handler:                      redirect(origin, observed),
		DisableGeneralOptionsHandler: true,
		ReadHeaderTimeout:            data.ReadHeaderTimeout,
		WriteTimeout:                 data.WriteTimeout,
		MaxHeaderBytes:               data.MaxHeaderBytes,
	}
	return s
}

// serveAuxiliary serves an auxiliary listener (metrics and health, or the
// redirect). Its failure stops only that listener and is logged: the data
// plane keeps serving, and a stopped health listener fails its probes.
func serveAuxiliary(name string, server *http.Server, l net.Listener, logger *slog.Logger) {
	if err := server.Serve(l); !errors.Is(err, http.ErrServerClosed) {
		logger.Error("listener stopped; the data plane keeps serving", "listener", name, "error", err)
	}
}

// listenRedirect binds the redirect listener; nil when there is none.
func listenRedirect(r *redirectSettings) (net.Listener, error) {
	if r == nil {
		return nil, nil
	}
	listener, err := net.Listen("tcp", r.Listen)
	if err != nil {
		return nil, classify(ErrListen, fmt.Errorf("redirect listener: %w", err))
	}
	return listener, nil
}
