// The gateway embedded in a host program: lifecycle, draining, prefix
// mounting and the host's server settings.

package gateway

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// openEmbedded opens e's seeded deployment as an embedded gateway.
func openEmbedded(e *gatewaytest.Env) *Embedded {
	e.T.Helper()
	gatewaytest.Seed(e.T, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
	settings, err := LoadSettings(e.Config)
	if err != nil {
		e.T.Fatal(err)
	}
	lib, err := OpenEmbedded(settings, slog.New(slog.NewJSONHandler(&gatewaytest.LogBuffer{}, nil)))
	if err != nil {
		e.T.Fatal(err)
	}
	e.T.Cleanup(func() { lib.Stop(context.Background()) })
	return lib
}

// auditRecord returns the record of kind for request id, or nil.
func auditRecord(e *gatewaytest.Env, id, kind string) map[string]any {
	e.T.Helper()
	match := func(ev map[string]any) bool { return ev["request_id"] == id && ev["kind"] == kind }
	events := e.EventsWhen(func(events []map[string]any) bool { return slices.ContainsFunc(events, match) })
	if i := slices.IndexFunc(events, match); i >= 0 {
		return events[i]
	}
	return nil
}

// Before Start and from Stop on, the handler refuses and records; Start and
// Stop each happen once; Stop waits for requests in progress before the
// audit log closes, and releases the deployment.
func TestLibraryLifecycle(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	lib := openEmbedded(e)
	host := httptest.NewServer(lib)
	defer host.Close()

	early := httptest.NewRecorder()
	lib.ServeHTTP(early, httptest.NewRequest(http.MethodGet, "/a/x", nil))
	if early.Code != http.StatusServiceUnavailable || e.A.Count() != 0 {
		t.Fatalf("before Start: %d, %d forwarded", early.Code, e.A.Count())
	}
	if err := lib.Start(); err != nil {
		t.Fatal(err)
	}
	if ev := auditRecord(e, early.Header().Get("X-Request-Id"), "request.rejected"); ev == nil || ev["stage"] != "CAPTURE" {
		t.Fatalf("refusal before Start recorded as %v", ev)
	}
	if err := lib.Start(); !errors.Is(err, ErrStarted) {
		t.Fatalf("second Start: %v", err)
	}

	held, release := make(chan struct{}), make(chan struct{})
	e.A.Handle = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/a/held" {
			return false
		}
		close(held)
		<-release
		return false
	}
	answer := make(chan *http.Response, 1)
	go func() {
		resp, err := http.Get(host.URL + "/a/held")
		if err != nil {
			t.Error(err)
		}
		answer <- resp
	}()
	<-held
	stopped := make(chan error, 1)
	go func() { stopped <- lib.Stop(context.Background()) }()
	gatewaytest.WaitFor(t, time.Now().Add(5*time.Second), "refusals once Stop began", func() bool {
		resp, err := http.Get(host.URL + "/a/x")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusServiceUnavailable
	})
	select {
	case err := <-stopped:
		t.Fatalf("Stop returned while a request was in progress: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	resp := <-answer
	if resp == nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("request admitted before Stop: %v", resp)
	}
	resp.Body.Close()
	if err := <-stopped; err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if ev := auditRecord(e, resp.Header.Get("X-Request-Id"), "request.forwarded"); ev == nil || ev["status"] != float64(http.StatusOK) {
		t.Fatalf("drained request recorded as %v", ev)
	}
	if err := lib.Start(); !errors.Is(err, ErrStopped) {
		t.Fatalf("Start after Stop: %v", err)
	}
	st, err := store.OpenStore(e.Database)
	if err != nil {
		t.Fatalf("the database is still held: %v", err)
	}
	st.Close()
}

// Mounted under a prefix, the path checked, recorded and forwarded is the
// stripped path, and encodings refused at the root stay refused.
func TestPrefixMount(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	lib := openEmbedded(e)
	if err := lib.Start(); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/", http.StripPrefix("/api", lib))
	host := httptest.NewServer(mux)
	defer host.Close()

	resp, err := http.Get(host.URL + "/api/a/%41")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	got := e.A.Receipts()
	if resp.StatusCode != http.StatusOK || len(got) != 1 || got[0].Path != "/a/A" {
		t.Fatalf("prefixed request: %d, receipts %+v", resp.StatusCode, got)
	}
	if ev := auditRecord(e, resp.Header.Get("X-Request-Id"), "request.forwarded"); ev == nil || ev["path"] != "/a/A" {
		t.Fatalf("prefixed request recorded as %v", ev)
	}
	resp, err = http.Get(host.URL + "/api/a%2Fx")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || e.A.Count() != 1 {
		t.Fatalf("encoded slash under the prefix: %d, %d forwarded", resp.StatusCode, e.A.Count())
	}
}

// The host's server takes the configured data-plane limits.
func TestServerSettings(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	settings := e.NativeSettings()
	data := gatewaytest.Section(settings, "data")
	data["max_header_bytes"] = 32768
	data["read_header_timeout"] = "3s"
	data["read_timeout"] = "7s"
	data["write_timeout"] = "11s"
	data["idle_timeout"] = "13s"
	e.WriteNative(settings)
	lib := openEmbedded(e)
	var server http.Server
	lib.ServerSettings().Apply(&server)
	if server.MaxHeaderBytes != 32768 || server.ReadHeaderTimeout != 3*time.Second || server.ReadTimeout != 7*time.Second ||
		server.WriteTimeout != 11*time.Second || server.IdleTimeout != 13*time.Second {
		t.Fatalf("applied settings: header bytes %d, timeouts %s %s %s %s", server.MaxHeaderBytes,
			server.ReadHeaderTimeout, server.ReadTimeout, server.WriteTimeout, server.IdleTimeout)
	}
	if !server.Protocols.HTTP1() || !server.Protocols.HTTP2() || server.Protocols.UnencryptedHTTP2() ||
		server.HTTP2.MaxConcurrentStreams != maxStreams || server.HTTP2.MaxReceiveBufferPerConnection != receiveBuffer {
		t.Fatalf("applied protocols %v, HTTP/2 settings %+v", server.Protocols, server.HTTP2)
	}

	// With HTTP/2 off, the host serves HTTP/1 only.
	data["http2"] = false
	e.WriteNative(settings)
	cfg, err := loadNativeConfig(e.Config)
	if err != nil {
		t.Fatal(err)
	}
	server = http.Server{}
	cfg.server().Apply(&server)
	if server.Protocols.HTTP2() {
		t.Fatalf("data.http2 false still serves HTTP/2: %v", server.Protocols)
	}
}

// kinds counts the lifecycle kinds err matches; each error has exactly one.
func kinds(err error) []error {
	var matched []error
	for _, kind := range []error{ErrConfig, ErrLocked, ErrStorage, ErrListen, ErrStarted, ErrStopped, ErrIncomplete} {
		if errors.Is(err, kind) {
			matched = append(matched, kind)
		}
	}
	return matched
}

// Each refusal while loading, opening and starting has one kind, and a
// failed Start releases the deployment.
func TestLibraryErrors(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	logger := slog.New(slog.NewJSONHandler(&gatewaytest.LogBuffer{}, nil))
	if _, err := OpenEmbedded(Settings{}, logger); !slices.Equal(kinds(err), []error{ErrConfig}) {
		t.Fatalf("zero settings: %v", err)
	}
	e.WriteNativeFile([]byte(`{"version": 1}`))
	if _, err := LoadSettings(e.Config); !slices.Equal(kinds(err), []error{ErrConfig}) {
		t.Fatalf("incomplete file: %v", err)
	}
	e.WriteNative(e.NativeSettings())
	first := openEmbedded(e)
	settings, err := LoadSettings(e.Config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenEmbedded(settings, nil); !slices.Equal(kinds(err), []error{ErrConfig}) {
		t.Fatalf("no logger: %v", err)
	}
	if _, err := OpenEmbedded(settings, logger); !slices.Equal(kinds(err), []error{ErrLocked}) {
		t.Fatalf("second gateway for one deployment: %v", err)
	}
	busy, err := net.Listen("tcp", e.Admin)
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	if err := first.Start(); !slices.Equal(kinds(err), []error{ErrListen}) {
		t.Fatalf("Start with the admin address in use: %v", err)
	}
	if err := first.Start(); !slices.Equal(kinds(err), []error{ErrStopped}) {
		t.Fatalf("Start after a failed Start: %v", err)
	}
	if gatewaytest.Dialable(e.Metrics) {
		t.Fatal("the metrics listener stayed open")
	}
	st, err := store.OpenStore(e.Database)
	if err != nil {
		t.Fatalf("the database is still held: %v", err)
	}
	st.Close()
}
