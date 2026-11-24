// Graceful shutdown ordering of the native gateway's listeners and policy.

package gateway

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

// Shutdown closes the data listener before withdrawing the published policy,
// so requests never meet an open data socket answering 503 while an auxiliary
// listener is still draining.
func TestShutdownClosesDataBeforePolicy(t *testing.T) {
	t.Parallel()
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
	e.WriteNative(e.NativeSettings())
	cfg, err := loadNativeConfig(e.Config)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewJSONHandler(&gatewaytest.LogBuffer{}, nil))
	d, err := openDeployment(cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	inMetrics, releaseMetrics := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(releaseMetrics) })
	t.Cleanup(release)
	baseMetrics := d.metrics.Handler
	d.metrics.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metrics" {
			close(inMetrics)
			<-releaseMetrics
		}
		baseMetrics.ServeHTTP(w, r)
	})
	dataListener, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		d.controller.Stop()
		t.Fatal(err)
	}
	metricsListener, healthListener, err := d.listen(true, false)
	if err != nil {
		dataListener.Close()
		d.controller.Stop()
		t.Fatal(err)
	}
	dataServer := &http.Server{Handler: d.enforcement}
	g := &nativeGateway{
		controller: d.controller, data: dataServer, dataListener: dataListener, metrics: d.metrics, health: d.health,
		upstreams: d.upstreams, served: make(chan error, 1), done: make(chan struct{}),
		draining: &d.draining, grace: 5 * time.Second,
	}
	g.stop = sync.OnceValue(g.shutdown)
	t.Cleanup(func() {
		release()
		g.stop()
	})
	go func() { g.served <- g.data.Serve(dataListener) }()
	go serveAuxiliary("metrics", g.metrics, metricsListener, logger)
	if healthListener != nil {
		go serveAuxiliary("health", g.health, healthListener, logger)
	}

	metricsDone := make(chan struct{})
	go func() {
		defer close(metricsDone)
		resp, err := http.Get("http://" + metricsListener.Addr().String() + "/metrics")
		if err == nil {
			resp.Body.Close()
		}
	}()
	<-inMetrics

	stopped := make(chan error, 1)
	go func() { stopped <- g.stop() }()
	gatewaytest.WaitFor(t, time.Now().Add(5*time.Second), "shutdown starts draining", g.draining.Load)

	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: time.Second}
	closed := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get("http://" + dataListener.Addr().String() + "/a/x")
		if err != nil {
			closed = true
			break
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusServiceUnavailable {
			t.Fatalf("data listener answered 503 while still open during shutdown: %s", body)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !closed {
		t.Fatal("data listener stayed open while metrics drained")
	}
	release()
	<-metricsDone
	if err := <-stopped; err != nil {
		t.Fatalf("stop: %v", err)
	}
}
