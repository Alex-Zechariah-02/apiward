// Upstream fast-fail: ejection after repeated connection failures, one probe
// after the ejection time, and reset once the endpoint answers.

package forward

import (
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

func TestEjectionAfterConnectFailures(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close() // connections to it are now refused
	_, send := forwarder(t, closed(), PoolSettings{EjectAfter: 2}, policy.Upstream{ID: "u", Dial: address}, http.MethodGet)
	for i := range 2 {
		if reason := send(); reason != "not_sent" {
			t.Fatalf("failure %d: %q, want not_sent", i+1, reason)
		}
	}
	if reason := send(); reason != "upstream_ejected" {
		t.Fatalf("after 2 failures: %q, want upstream_ejected", reason)
	}

	// Until the first ejection (1 s) ends every request is refused at once;
	// then one probe is sent, the endpoint answers, and it is no longer
	// ejected.
	listener, err = net.Listen("tcp", address)
	if err != nil {
		t.Skipf("cannot listen on %s again: %v", address, err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	deadline := time.Now().Add(ejectFirst + 5*time.Second)
	for reason := send(); reason != ""; reason = send() {
		if reason != "upstream_ejected" || time.Now().After(deadline) {
			t.Fatalf("waiting for the probe: %q", reason)
		}
		time.Sleep(20 * time.Millisecond)
	}
	for i := range 3 {
		if reason := send(); reason != "" {
			t.Fatalf("request %d after the endpoint recovered: %q", i+1, reason)
		}
	}
}

func TestEjectionDoublesAndProbesOnce(t *testing.T) {
	e := newEjector(1)
	now := time.Unix(0, 0)
	e.result("a", false, 0, now)
	if ok, _ := e.admit("a", now.Add(999*time.Millisecond)); ok {
		t.Fatal("admitted during the first ejection")
	}
	probeAt := now.Add(time.Second)
	ok, token := e.admit("a", probeAt)
	if !ok || token == 0 {
		t.Fatal("after the ejection time, want one probe with a token")
	}
	if again, _ := e.admit("a", probeAt); again {
		t.Fatal("after the ejection time, want exactly one probe")
	}
	e.result("a", false, token, probeAt)
	if ok, _ := e.admit("a", probeAt.Add(1999*time.Millisecond)); ok {
		t.Fatal("a failed probe must eject for twice as long")
	}
	ok, token = e.admit("a", probeAt.Add(2*time.Second))
	if !ok || token == 0 {
		t.Fatal("a failed probe must allow a probe after twice as long")
	}
	e.settle("a", token, true) // the probe's client went away
	ok, token = e.admit("a", probeAt.Add(2*time.Second))
	if !ok {
		t.Fatal("a probe whose client left must pass its turn on")
	}
	e.result("a", true, token, probeAt.Add(2*time.Second))
	if ok, _ := e.admit("a", probeAt.Add(2*time.Second)); !ok || len(e.states) != 0 {
		t.Fatal("a connection must reset the endpoint")
	}
}

func TestStaleRequestDoesNotDisruptActiveProbe(t *testing.T) {
	e := newEjector(1)
	now := time.Unix(0, 0)
	// Stale request admitted before ejection; then endpoint ejects and a probe starts.
	ok, stale := e.admit("a", now)
	if !ok || stale != 0 {
		t.Fatal("initial request not admitted as non-probe")
	}
	e.result("a", false, 0, now)
	probeAt := now.Add(time.Second)
	ok, active := e.admit("a", probeAt)
	if !ok || active == 0 {
		t.Fatal("probe not admitted")
	}
	// Stale request's client cancels or fails while probe is still in flight.
	e.settle("a", stale, true)
	if again, _ := e.admit("a", probeAt); again {
		t.Fatal("stale cancel released another request's active probe")
	}
	e.result("a", false, stale, probeAt)
	if e.states["a"].probe != active {
		t.Fatal("stale failure disturbed active probe")
	}
}

func TestStaleConnectionCannotCompleteAnotherProbe(t *testing.T) {
	t.Parallel()
	e := newEjector(1)
	now := time.Unix(0, 0)
	allowed, stale := e.admit("a", now)
	if !allowed {
		t.Fatal("initial connection attempt was refused")
	}
	e.result("a", false, stale, now)
	probeAt := now.Add(ejectFirst)
	allowed, active := e.admit("a", probeAt)
	if !allowed || active == 0 {
		t.Fatal("recovery probe was not admitted")
	}
	e.result("a", true, stale, probeAt)
	if allowed, _ := e.admit("a", probeAt); allowed {
		t.Fatal("a stale successful connection cleared the active recovery probe")
	}
	e.result("a", true, active, probeAt)
	if allowed, _ := e.admit("a", probeAt); !allowed {
		t.Fatal("the owning successful probe did not restore normal admission")
	}
}

func TestCompletedProbeCannotChangeLaterEjection(t *testing.T) {
	t.Parallel()
	e := newEjector(1)
	now := time.Unix(0, 0)
	e.result("a", false, 0, now)
	firstAt := now.Add(ejectFirst)
	allowed, first := e.admit("a", firstAt)
	if !allowed || first == 0 {
		t.Fatal("first probe was not admitted")
	}
	e.result("a", false, first, firstAt)
	e.result("a", true, first, firstAt)
	if allowed, _ := e.admit("a", firstAt); allowed {
		t.Fatal("completed probe cleared the next ejection")
	}
	secondAt := firstAt.Add(2 * ejectFirst)
	allowed, second := e.admit("a", secondAt)
	if !allowed || second == 0 || second == first {
		t.Fatal("second probe has no distinct ownership")
	}
	e.result("a", true, second, secondAt)
	e.result("a", false, first, secondAt)
	if allowed, token := e.admit("a", secondAt); !allowed || token != 0 {
		t.Fatal("an old failed probe recreated ejection after successful recovery")
	}
}
