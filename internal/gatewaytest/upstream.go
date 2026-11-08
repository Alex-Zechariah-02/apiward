// Upstream receivers: loopback servers that record every request a
// deployment forwards to them.

package gatewaytest

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
)

// Receipt is what an upstream actually received.
type Receipt struct {
	Method        string
	Target        string // raw request-target as received
	Path          string // decoded path
	Host          string // Host as received
	RequestID     string
	Generation    string
	Authorization bool
	Headers       http.Header
	Body          string
	Trailer       http.Header // request trailers, known once the body is read
}

// Receiver is an owned upstream that records every request it receives.
// handle, when set, may take over the response; it returns true if it did.
type Receiver struct {
	Name   string
	Addr   string
	Server *http.Server
	mu     sync.Mutex
	got    []Receipt
	Handle func(w http.ResponseWriter, r *http.Request) bool
}

// NewReceiver starts a receiver on a free loopback port until the test ends.
func NewReceiver(t *testing.T, name string) *Receiver {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rc := &Receiver{Name: name, Addr: listener.Addr().String()}
	rc.Server = &http.Server{Handler: http.HandlerFunc(rc.serve)}
	go rc.Server.Serve(listener)
	t.Cleanup(func() { rc.Server.Close() })
	return rc
}

func (rc *Receiver) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	rc.mu.Lock()
	rc.got = append(rc.got, Receipt{
		Method:        r.Method,
		Target:        r.RequestURI,
		Path:          r.URL.Path,
		Host:          r.Host,
		RequestID:     r.Header.Get("X-Request-Id"),
		Generation:    r.Header.Get("X-Gateway-Generation"),
		Authorization: r.Header.Get("Authorization") != "",
		Headers:       r.Header.Clone(),
		Body:          string(body),
		Trailer:       r.Trailer.Clone(),
	})
	handle := rc.Handle
	rc.mu.Unlock()
	if handle != nil && handle(w, r) {
		return
	}
	fmt.Fprintf(w, "%s ok", rc.Name)
}

// Receipts is a copy of every request the receiver has recorded.
func (rc *Receiver) Receipts() []Receipt {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return append([]Receipt(nil), rc.got...)
}

// Count is the number of requests the receiver has recorded.
func (rc *Receiver) Count() int { return len(rc.Receipts()) }

func (rc *Receiver) reset() {
	rc.mu.Lock()
	rc.got = nil
	rc.mu.Unlock()
}

// AssertReceipts checks every receiver, not only the intended one.
func (e *Env) AssertReceipts(a, b, c int) {
	e.T.Helper()
	if got := [3]int{e.A.Count(), e.B.Count(), e.C.Count()}; got != [3]int{a, b, c} {
		e.T.Fatalf("receipts A,B,C = %v, want %v", got, [3]int{a, b, c})
	}
}

// ResetReceivers forgets every receipt of the three receivers.
func (e *Env) ResetReceivers() {
	e.A.reset()
	e.B.reset()
	e.C.reset()
}
