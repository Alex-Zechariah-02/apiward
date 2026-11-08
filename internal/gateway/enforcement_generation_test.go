// Enforcement and captured generations.

package gateway

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
)

// publishOnRead is a request body that publishes a new generation when the
// handler first reads it, between the capture and the later stages.
type publishOnRead struct {
	data    *strings.Reader
	publish func()
	once    sync.Once
}

func (b *publishOnRead) Read(p []byte) (int, error) {
	b.once.Do(b.publish)
	return b.data.Read(p)
}

func (b *publishOnRead) Close() error { return nil }

// A request is decided by the one generation it captured, even when another
// is published while it is in progress: the body schema, the binding and the
// metadata all come from it. The next request uses the new generation.
func TestEnforcementUsesCapturedGeneration(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	c, h, f := serveEnforcement(e, e.Policy(e.A, false), 0)
	captured := c.Current()

	// The next generation sends API a to B and requires the member "x".
	next := e.Policy(e.B, false)
	next.Operations[1].Body = gatewaytest.JSONBody(1024, `{"type":"object","additionalProperties":true,"required":["x"],"properties":{"x":{"type":"integer"}}}`)
	var published controller.Outcome
	body := &publishOnRead{data: strings.NewReader(`{"n":1}`), publish: func() {
		var status int
		published, status = c.Publish(context.Background(), "test", controller.Change{ID: "during-request", Expected: 1, Policy: gatewaytest.MustJSON(next)})
		if status != http.StatusOK {
			t.Errorf("publication during the request: %d %+v", status, published)
		}
	}}
	req := httptest.NewRequest(http.MethodPost, "/a/item", body)
	req.ContentLength = int64(body.data.Len())
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || published.Revision != 2 || c.Current().ID != published.Generation {
		t.Fatalf("request during publication: %d %s; published %+v", rec.Code, rec.Body, published)
	}
	got := f.handed()
	if len(got) != 1 || got[0].dial != e.A.Addr || got[0].header.Get("X-Gateway-Generation") != captured.ID {
		t.Fatalf("handed %+v, want upstream A under %s", got, captured.ID)
	}
	if ev := eventOf(e, got[0].header.Get("X-Request-Id"), 2); ev["generation"] != captured.ID || ev["upstream"] != "A" {
		t.Fatalf("outcome event %v", ev)
	}

	if code, body := e.Request(http.MethodPost, "/a/item", "application/json", `{"n":1}`); code != http.StatusBadRequest {
		t.Fatalf("body refused by the new schema: %d %s", code, body)
	}
	if code, _ := e.Request(http.MethodPost, "/a/item", "application/json", `{"x":1}`); code != http.StatusOK {
		t.Fatalf("body valid under the new schema: %d", code)
	}
	got = f.handed()
	if len(got) != 2 || got[1].dial != e.B.Addr || got[1].header.Get("X-Gateway-Generation") != published.Generation {
		t.Fatalf("handed %+v, want upstream B under %s", got[1:], published.Generation)
	}
	e.AssertReceipts(0, 0, 0)
}

// Without a usable generation nothing is admitted: none published, one past
// its deadline as a late timer would leave it (the controller then withdraws
// it rather than serve it), and a stopped controller.
func TestEnforcementWithoutUsableGeneration(t *testing.T) {
	t.Run("none published", func(t *testing.T) {
		e := gatewaytest.NewEnv(t)
		c, _ := own(e, controllerConfig(e))
		f := &memoryForwarder{}
		h, err := newHandler(c, pipeline.NewLimiter(), 0, f.forward)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/a/x", nil))
		if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "gateway_unavailable") || len(f.handed()) != 0 {
			t.Fatalf("without authority: %d %s", rec.Code, rec.Body)
		}
	})

	t.Run("past its deadline", func(t *testing.T) {
		e := gatewaytest.NewEnv(t)
		policy := e.Policy(e.A, false)
		gatewaytest.Seed(t, e.Database, policy, gatewaytest.SeedOptions{})
		c, _ := own(e, controllerConfig(e))
		stale, err := compile.Compile(policy, 1, time.Now().Add(-time.Second))
		if err != nil {
			t.Fatal(err)
		}
		f := serveAuthority(e, c, fixedAuthority{Controller: c, generation: stale})
		resp, body := e.Exchange(http.MethodGet, "/a/x", "", "", "")
		_, id := gatewaytest.RequestID(resp, body)
		if resp.StatusCode != http.StatusServiceUnavailable || len(f.handed()) != 0 {
			t.Fatalf("expired generation: %d %s", resp.StatusCode, body)
		}
		if ev := eventOf(e, id, 1); ev["stage"] != "CAPTURE" || ev["error"] != "gateway_unavailable" {
			t.Fatalf("refusal event %v", ev)
		}
		e.AssertReceipts(0, 0, 0)
	})

	t.Run("controller stopped", func(t *testing.T) {
		e := gatewaytest.NewEnv(t)
		c, _, f := serveEnforcement(e, e.Policy(e.A, false), 0)
		if code, _ := e.Get("/a/x"); code != http.StatusOK {
			t.Fatalf("before Stop: %d", code)
		}
		if err := c.Stop(); err != nil {
			t.Fatal(err)
		}
		if code, body := e.Get("/a/x"); code != http.StatusServiceUnavailable || !strings.Contains(body, "gateway_unavailable") {
			t.Fatalf("after Stop: %d %s", code, body)
		}
		if n := len(f.handed()); n != 1 {
			t.Fatalf("%d requests handed on, want 1", n)
		}
	})
}

// Concurrent requests during repeated publications: every request handed on
// carries the generation it was admitted under, its binding is that
// generation's upstream, and its outcome event names the same generation.
func TestEnforcementGenerationsUnderConcurrency(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	toA, toB := e.Policy(e.A, false), e.Policy(e.B, false)
	c, _, f := serveEnforcement(e, toA, 0)
	var dials sync.Map // generation ID -> the dial of API a in it
	dials.Store(c.Current().ID, e.A.Addr)

	done := make(chan struct{})
	published := 0
	var wg sync.WaitGroup
	wg.Go(func() {
		expected := int64(1)
		for i := 0; ; i++ {
			select {
			case <-done:
				return
			default:
			}
			policy, dial := toB, e.B.Addr
			if i%2 == 1 {
				policy, dial = toA, e.A.Addr
			}
			outcome, status := c.Publish(context.Background(), "test", controller.Change{ID: fmt.Sprintf("concurrent-%d", i), Expected: expected, Policy: gatewaytest.MustJSON(policy)})
			if status != http.StatusOK {
				t.Errorf("publication %d: %d %+v", i, status, outcome)
				return
			}
			dials.Store(outcome.Generation, dial)
			expected = outcome.Revision
			published++
		}
	})
	var clients sync.WaitGroup
	for range 8 {
		clients.Go(func() {
			for range 50 {
				if code, body := e.Get("/a/x"); code != http.StatusOK {
					t.Errorf("request: %d %s", code, body)
				}
			}
		})
	}
	clients.Wait()
	close(done)
	wg.Wait()

	got := f.handed()
	if len(got) != 400 {
		t.Fatalf("%d requests handed on, want 400", len(got))
	}
	outcomes := map[string]string{} // request ID -> generation of its outcome event
	for _, ev := range e.EventsWhen(func(events []map[string]any) bool { return gatewaytest.CountKind(events, "request.forwarded") == 400 }) {
		if ev["kind"] == "request.forwarded" {
			outcomes[ev["request_id"].(string)], _ = ev["generation"].(string)
		}
	}
	seen := map[string]bool{}
	for _, h := range got {
		generation := h.header.Get("X-Gateway-Generation")
		dial, known := dials.Load(generation)
		if !known || h.dial != dial || outcomes[h.header.Get("X-Request-Id")] != generation {
			t.Fatalf("request under %s bound to %s (want %v), outcome event under %s",
				generation, h.dial, dial, outcomes[h.header.Get("X-Request-Id")])
		}
		seen[generation] = true
	}
	t.Logf("%d publications, %d generations seen by requests", published, len(seen))
	e.AssertReceipts(0, 0, 0)
}
