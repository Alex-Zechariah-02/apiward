// Command embed is a small host program that runs the gateway inside
// itself: it serves its own page at / and mounts the gateway at /api/, so
// every API request passes the gateway's checks before it reaches the
// upstream the policy binds. It uses only the module's public packages.
//
//	embed -config gateway.json -listen 127.0.0.1:8080
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Alex-Zechariah-02/apiward"
)

// stopWait bounds the host's and the gateway's graceful stop.
const stopWait = 30 * time.Second

func main() {
	config := flag.String("config", "", "gateway configuration file")
	listen := flag.String("listen", "127.0.0.1:8080", "address of the host's server")
	flag.Parse()
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		logger.Error("listen", "error", err)
		os.Exit(1)
	}
	if err := run(ctx, *config, listener, logger); err != nil {
		logger.Error("stopped with an error", "error", err)
		os.Exit(1)
	}
}

// run serves the host's routes on listener until ctx ends, then stops the
// host's server first, so no new request reaches the gateway, and the
// gateway after it. listener is closed when run returns.
func run(ctx context.Context, config string, listener net.Listener, logger *slog.Logger) error {
	defer listener.Close()
	cfg, err := apiward.LoadConfig(config)
	if err != nil {
		return err
	}
	gw, err := apiward.New(cfg, logger)
	if err != nil {
		return err
	}
	if err := gw.Start(); err != nil {
		return err
	}
	mux := http.NewServeMux()
	// Policy targets are the paths below /api: /items here is /api/items.
	mux.Handle("/api/", http.StripPrefix("/api", gw))
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Host page. The API is served under /api/.")
	})
	server := &http.Server{Handler: mux}
	gw.ServerSettings().Apply(server)

	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	var failed error
	select {
	case <-ctx.Done():
	case failed = <-served:
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), stopWait)
	defer cancel()
	if err := server.Shutdown(stopCtx); err != nil {
		failed = errors.Join(failed, err)
	}
	return errors.Join(failed, gw.Stop(stopCtx))
}
