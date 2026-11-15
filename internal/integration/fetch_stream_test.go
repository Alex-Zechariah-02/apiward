// Fetch live event stream heartbeats.

package integration

import (
	"bufio"
	"net/http"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

func openEventStream(t *testing.T, e *gatewaytest.Env, admin gatewaytest.AdminSession, client *http.Client) *http.Response {
	t.Helper()
	request, _ := http.NewRequest("GET", "http://"+e.Admin+"/admin/events/stream", nil)
	header := admin.Headers(e)
	for i := 0; i < len(header); i += 2 {
		request.Header.Set(header[i], header[i+1])
	}
	request.Header.Set("Accept", "text/event-stream")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 {
		response.Body.Close()
		t.Fatalf("stream: %d", response.StatusCode)
	}
	t.Cleanup(func() { response.Body.Close() })
	return response
}

func TestFetchStreamHeartbeat(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.Policy(e.A, true), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	admin := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
	// Two heartbeats, each about 15 s after the one before, show a repeating
	// heartbeat; the client allows 5 s more than two intervals.
	last := time.Now()
	response := openEventStream(t, e, admin, &http.Client{Timeout: 35 * time.Second})
	scanner := bufio.NewScanner(response.Body)
	beats := 0
	for scanner.Scan() {
		if scanner.Text() != ": heartbeat" {
			continue
		}
		if elapsed := time.Since(last); elapsed < 14*time.Second {
			t.Fatalf("heartbeat %d arrived too early: %v", beats+1, elapsed)
		}
		last = time.Now()
		if beats++; beats == 2 {
			return
		}
	}
	t.Fatalf("%d of 2 heartbeats 15 s apart: %v", beats, scanner.Err())
}
