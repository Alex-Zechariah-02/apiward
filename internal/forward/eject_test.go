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
	_, send := forwarder(t, closed(), PoolSettings{EjectAfter: 2}, policy.Upstream{ID: "u", Dial: address})
	for i := range 2 {
		if reason := send(); reason != "not_sent" {
			t.Fatalf("failure %d: %q, want not_sent", i+1, reason)
		}
	}
	started := time.Now()
	if reason := send(); reason != "upstream_ejected" || time.Since(started) > 100*time.Millisecond {
		t.Fatalf("after 2 failures: %q in %v, want an immediate upstream_ejected", reason, time.Since(started))
	}

	// After the first ejection (1 s) one probe is sent; the endpoint now
	// answers, so it is no longer ejected.
	listener, err = net.Listen("tcp", address)
	if err != nil {
		t.Skipf("cannot listen on %s again: %v", address, err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	time.Sleep(ejectFirst + 100*time.Millisecond)
	for i := range 3 {
		if reason := send(); reason != "" {
			t.Fatalf("request %d after the endpoint recovered: %q", i+1, reason)
		}
	}
}

func TestEjectionDoublesAndProbesOnce(t *testing.T) {
	e := newEjector(1)
	now := time.Unix(0, 0)
	e.result("a", false, now)
	if e.admit("a", now.Add(999*time.Millisecond)) {
		t.Fatal("admitted during the first ejection")
	}
	probe := now.Add(time.Second)
	if !e.admit("a", probe) || e.admit("a", probe) {
		t.Fatal("after the ejection time, want exactly one probe")
	}
	e.result("a", false, probe)
	if e.admit("a", probe.Add(1999*time.Millisecond)) || !e.admit("a", probe.Add(2*time.Second)) {
		t.Fatal("a failed probe must eject for twice as long")
	}
	e.settle("a", false, true) // the probe's client went away
	if !e.admit("a", probe.Add(2*time.Second)) {
		t.Fatal("a probe whose client left must pass its turn on")
	}
	e.result("a", true, probe.Add(2*time.Second))
	if !e.admit("a", probe.Add(2*time.Second)) || len(e.states) != 0 {
		t.Fatal("a connection must reset the endpoint")
	}
}
