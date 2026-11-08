// The native gateway's start and stop release every resource it holds.

package gateway

import (
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// The native gateway owned in this process releases everything it acquired:
// after a stop, and after a start that fails part way. Concurrent stops share
// one result.
func TestNativeStartAndStopRelease(t *testing.T) {
	const dataServer = "gateway.startNative.func"
	e := gatewaytest.NewEnv(t)
	provisional := e.Policy(e.A, true)
	gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{Provisional: &provisional, Deadline: time.Now().Add(time.Hour)})
	e.WriteNative(e.NativeSettings())
	cfg, err := loadNativeConfig(e.Config)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewJSONHandler(&gatewaytest.LogBuffer{}, nil))
	writers, admins, servers := goroutines(auditWriter), goroutines(adminServer), goroutines(dataServer)

	g, err := startNative(cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	if code, body := e.Get("/b/x"); code != http.StatusOK || body != "B ok" {
		t.Fatalf("provisional generation: %d %q", code, body)
	}
	errs := make([]error, 3)
	var wg sync.WaitGroup
	for i := range errs {
		wg.Go(func() { errs[i] = g.stop() })
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatalf("stop: %v", err)
		}
	}
	if err := <-g.served; !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("data-plane Serve returned %v", err)
	}
	assertNativeReleased(t, e, writers, admins, servers)

	for name, addr := range map[string]string{"data": e.DataAddr, "admin": e.Admin} {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		if g, err := startNative(cfg, logger); err == nil || !strings.Contains(err.Error(), name+" listener") {
			if g != nil {
				g.stop()
			}
			t.Fatalf("start with the %s address in use: %v", name, err)
		}
		l.Close()
		assertNativeReleased(t, e, writers, admins, servers)
	}
}

// assertNativeReleased fails unless no native gateway of e's deployment holds
// anything: its goroutines ended, its listeners closed and its database lock
// free.
func assertNativeReleased(t *testing.T, e *gatewaytest.Env, writers, admins, servers int) {
	t.Helper()
	waitGoroutines(t, auditWriter, writers)
	waitGoroutines(t, adminServer, admins)
	waitGoroutines(t, "gateway.startNative.func", servers)
	if gatewaytest.Dialable(e.DataAddr) || gatewaytest.Dialable(e.Admin) || gatewaytest.Dialable(e.Metrics) {
		t.Fatal("a listener is still open")
	}
	st, err := store.OpenStore(e.Database)
	if err != nil {
		t.Fatalf("the database is still held: %v", err)
	}
	st.Close()
}
