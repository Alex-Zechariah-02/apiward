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
	start := time.Now()
	response := openEventStream(t, e, admin, &http.Client{Timeout: 20 * time.Second})
	scanner := bufio.NewScanner(response.Body)
	for scanner.Scan() {
		if scanner.Text() == ": heartbeat" {
			if elapsed := time.Since(start); elapsed < 14*time.Second {
				t.Fatalf("heartbeat arrived too early: %v", elapsed)
			}
			return
		}
	}
	t.Fatalf("no 15-second comment: %v", scanner.Err())
}
