// HTTP/2 request bodies: the streams of one connection read their bodies one
// at a time, so a connection buffers at most one body, as over HTTP/1.1.

package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
)

// serveHTTP2 serves h over TLS with HTTP/2 and the gateway's server limits,
// and returns its address and a client that multiplexes on one connection.
func serveHTTP2(t *testing.T, h http.Handler) (string, *http.Client) {
	t.Helper()
	server := httptest.NewUnstartedServer(h)
	ServerSettings{MaxHeaderBytes: 1 << 20, HTTP2: true}.Apply(server.Config)
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	return server.URL, server.Client()
}

// upload posts body with the declared length and sends the status, or 0
// when no answer came, to the returned channel.
func upload(t *testing.T, client *http.Client, url string, body io.Reader, length int64) <-chan int {
	done := make(chan int, 1)
	go func() {
		req, err := http.NewRequest(http.MethodPost, url+"/a/item", body)
		if err != nil {
			done <- 0
			return
		}
		req.ContentLength = length
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Error(err)
			done <- 0
			return
		}
		resp.Body.Close()
		if resp.ProtoMajor != 2 {
			t.Errorf("served over %s, want HTTP/2", resp.Proto)
		}
		done <- resp.StatusCode
	}()
	return done
}

func TestHTTP2BodiesTakeTurns(t *testing.T) {
	t.Parallel()
	e := gatewaytest.NewEnv(t)
	_, h, _ := serveEnforcement(e, e.Policy(e.A, true), pipeline.Limits{})
	url, client := serveHTTP2(t, h)
	reader, writer := io.Pipe()
	defer writer.Close()
	slow := upload(t, client, url, reader, 2)
	if _, err := writer.Write([]byte("{")); err != nil {
		t.Fatal(err)
	}
	// Until the slow stream holds the connection's turn, a second upload may
	// still go first; once it does, the next one waits.
	for attempt := 1; ; attempt++ {
		quick := upload(t, client, url, strings.NewReader("{}"), 2)
		select {
		case status := <-quick:
			if attempt == 20 {
				t.Fatalf("a second body on the connection was read while the first was arriving (%d)", status)
			}
			continue
		case <-time.After(300 * time.Millisecond):
		}
		if _, err := writer.Write([]byte("}")); err != nil {
			t.Fatal(err)
		}
		writer.Close()
		if status := <-slow; status == 0 {
			t.Fatal("the slow upload got no answer")
		}
		if status := <-quick; status == 0 {
			t.Fatal("the waiting upload got no answer")
		}
		return
	}
}
