// Repeated generation swaps under load, with the gateway's memory reported.

package integration

import (
	"fmt"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

func TestRepeatedSwapsUnderLoad(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Fault)

	// Every generation maps /a/* to exactly one receiver.
	destination := map[string]string{e.Status().Generation: "A"}

	stop := make(chan struct{})
	var requests, failures atomic.Int64
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			client := &http.Client{Timeout: 10 * time.Second}
			for {
				select {
				case <-stop:
					return
				default:
				}
				resp, err := client.Get("http://" + e.DataAddr + "/a/x")
				if err != nil {
					failures.Add(1)
					continue
				}
				resp.Body.Close()
				requests.Add(1)
				if resp.StatusCode != http.StatusOK {
					failures.Add(1)
				}
			}
		})
	}

	before := workingSet(t, e.Process.Process.Pid)
	revision := int64(1)
	const swaps = 200
	for i := range swaps {
		target := e.A
		if i%2 == 0 {
			target = e.B
		}
		outcome, code := e.Publish(controller.Change{ID: fmt.Sprintf("swap-%d", i), Expected: revision, Policy: gatewaytest.MustJSON(e.Policy(target, i%3 == 0))})
		if code != http.StatusOK {
			t.Fatalf("swap %d: %d %+v", i, code, outcome)
		}
		destination[outcome.Generation] = target.Name
		revision = outcome.Revision
	}
	close(stop)
	wg.Wait()
	after := workingSet(t, e.Process.Process.Pid)

	checked := 0
	for _, rc := range []*gatewaytest.Receiver{e.A, e.B} {
		for _, r := range rc.Receipts() {
			if destination[r.Generation] != rc.Name {
				t.Fatalf("receipt at %s under generation %s, which binds /a/* to %q", rc.Name, r.Generation, destination[r.Generation])
			}
			checked++
		}
	}
	if e.C.Count() != 0 {
		t.Fatal("decoy receiver was reached")
	}

	// Matching, binding, forwarding and the event used one generation.
	events := e.EventsWhen(func(events []map[string]any) bool {
		return gatewaytest.CountKind(events, "request.forwarded") >= checked
	})
	byRequest := map[string]map[string]any{}
	for _, ev := range events {
		if ev["kind"] == "request.forwarded" {
			byRequest[ev["request_id"].(string)] = ev
		}
	}
	for _, rc := range []*gatewaytest.Receiver{e.A, e.B} {
		for _, r := range rc.Receipts() {
			ev := byRequest[r.RequestID]
			if ev == nil || ev["generation"] != r.Generation || ev["upstream"] != rc.Name {
				t.Fatalf("receipt at %s under %s, event %v", rc.Name, r.Generation, ev)
			}
		}
	}
	t.Logf("%d swaps, %d requests (%d non-200 or transport errors), %d receipts checked; working set %s -> %s",
		swaps, requests.Load(), failures.Load(), checked, before, after)
	if failures.Load() != 0 {
		t.Fatalf("%d requests failed during swaps", failures.Load())
	}
}

// workingSet reports the process's working set as shown by tasklist.
func workingSet(t *testing.T, pid int) string {
	t.Helper()
	out, err := exec.Command("tasklist", "/FI", "PID eq "+strconv.Itoa(pid), "/FO", "CSV", "/NH").Output()
	if err != nil {
		return "unavailable"
	}
	fields := strings.Split(strings.TrimSpace(string(out)), "\",\"")
	return strings.Trim(fields[len(fields)-1], "\"")
}
