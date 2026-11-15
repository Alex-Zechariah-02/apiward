// Request-path behaviour through the real handler and audit log: forwarder
// panics, Max-Forwards, request-target forms, trusted proxies, Retry-After,
// the assertion bound and the recorded method bound.

package pipeline

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// setup is what one exchange runs with: the public operations of API "a",
// the handler limits, an optional signer and the forwarder.
type setup struct {
	ops     []policy.Operation
	limits  Limits
	signer  *Signer
	forward Forward
}

// public is a public operation of API "a".
func public(method, target string) policy.Operation {
	return policy.Operation{ID: strings.ToLower(method), API: "a", Method: method, Target: target, Access: "allow", Auth: "none"}
}

// exchange sends each request through one handler and returns the last
// answer, the request records written and what the last request panicked
// with, if anything.
func exchange(t *testing.T, s setup, requests ...*http.Request) (*httptest.ResponseRecorder, []map[string]any, any) {
	t.Helper()
	g, err := compile.Compile(policy.Policy{
		SchemaVersion: policy.SchemaVersion, Profile: policy.ProfileCore,
		Upstreams: []policy.Upstream{{ID: "A", Dial: "127.0.0.1:9"}}, APIs: []policy.API{{ID: "a", Upstream: "A"}},
		Operations: s.ops,
	}, 1, time.Time{}, policy.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.log")
	log := audit.OpenAudit(path, audit.Settings{MaxBytes: 1 << 20, MaxFiles: 2})
	if s.forward == nil {
		s.forward = func(w http.ResponseWriter, _ *http.Request) error {
			w.WriteHeader(http.StatusOK)
			return nil
		}
	}
	h, err := New(Deps{Authority: fixedAuthority{g}, Audit: log, Observations: monitor.New(policy.DefaultWindow, policy.DefaultAPIs), Limiter: NewLimiter(policy.DefaultRateCounters), Clock: NewClock(), AuditTimeout: time.Second, Limits: s.limits, Signer: s.signer, Forward: s.forward})
	if err != nil {
		t.Fatal(err)
	}
	var rec *httptest.ResponseRecorder
	var recovered any
	for _, r := range requests {
		rec = httptest.NewRecorder()
		func() {
			defer func() { recovered = recover() }()
			h.ServeHTTP(rec, r)
		}()
	}
	if err := log.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var records []map[string]any
	for lines := bufio.NewScanner(file); lines.Scan(); {
		var e map[string]any
		if json.Unmarshal(lines.Bytes(), &e) == nil && e["request_id"] != nil {
			records = append(records, e)
		}
	}
	return rec, records, recovered
}

// quick reports whether a record's duration is that of an immediate request;
// a zero duration is left out of the record.
func quick(e map[string]any) bool {
	ms, _ := e["duration_ms"].(float64)
	return ms >= 0 && ms < 10_000
}

// last is the final record, or an empty one.
func last(records []map[string]any) map[string]any {
	if len(records) == 0 {
		return map[string]any{}
	}
	return records[len(records)-1]
}

// A panic in the forwarder before anything was sent is answered 500 and
// recorded as the gateway's failure; after a response started, the
// connection is aborted. The forwarder's own abort stays an upstream failure.
func TestForwarderPanic(t *testing.T) {
	cases := []struct {
		name            string
		forward         Forward
		status          int
		decision, error string
		aborted         bool
	}{
		{"before writing", func(http.ResponseWriter, *http.Request) error { panic("broken forwarder") }, http.StatusInternalServerError, "failed", "internal_error", false},
		{"after writing", func(w http.ResponseWriter, _ *http.Request) error {
			w.WriteHeader(http.StatusOK)
			panic("broken forwarder")
		}, http.StatusOK, "failed", "internal_error", true},
		{"forwarder abort", func(w http.ResponseWriter, _ *http.Request) error {
			w.WriteHeader(http.StatusOK)
			panic(http.ErrAbortHandler)
		}, http.StatusOK, "upstream_failure", "upstream_incomplete", true},
	}
	for _, tc := range cases {
		rec, records, recovered := exchange(t, setup{ops: []policy.Operation{public("GET", "/a/x")}, forward: tc.forward}, httptest.NewRequest(http.MethodGet, "/a/x", nil))
		e := last(records)
		if (recovered == http.ErrAbortHandler) != tc.aborted || rec.Code != tc.status || e["kind"] != "request.forwarded" || e["decision"] != tc.decision || e["error"] != tc.error || e["status"] != float64(tc.status) {
			t.Errorf("%s: answer %d, panic %v, record %v", tc.name, rec.Code, recovered, e)
		}
		if !tc.aborted && rec.Body.String() != `{"error":"internal_error","request_id":"`+rec.Header().Get("X-Request-Id")+"\"}\n" {
			t.Errorf("%s: body %q", tc.name, rec.Body)
		}
	}
}

// OPTIONS with Max-Forwards 0 is answered by the gateway with the target's
// methods; a larger value is decremented; anything else is refused. Other
// methods forward the field unchanged.
func TestMaxForwards(t *testing.T) {
	var seen string
	s := setup{ops: []policy.Operation{public("GET", "/a/x"), public("OPTIONS", "/a/o")}, forward: func(w http.ResponseWriter, r *http.Request) error {
		seen = r.Header.Get("Max-Forwards")
		w.WriteHeader(http.StatusOK)
		return nil
	}}
	request := func(method, target, value string) *http.Request {
		r := httptest.NewRequest(method, target, nil)
		r.Header.Set("Max-Forwards", value)
		return r
	}
	rec, records, _ := exchange(t, s, request(http.MethodOptions, "/a/x", "0"))
	if e := last(records); rec.Code != http.StatusNoContent || !strings.Contains(rec.Header().Get("Allow"), "GET") || e["kind"] != "request.preflight" || e["error"] != "max_forwards" || !quick(e) {
		t.Fatalf("Max-Forwards 0: %d %v %v", rec.Code, rec.Header(), e)
	}
	for _, tc := range []struct{ method, target, value, want string }{{"OPTIONS", "/a/o", "5", "4"}, {"OPTIONS", "/a/o", "1", "0"}, {"GET", "/a/x", "0", "0"}} {
		seen = ""
		if rec, _, _ := exchange(t, s, request(tc.method, tc.target, tc.value)); rec.Code != http.StatusOK || seen != tc.want {
			t.Errorf("%s %s: %d, forwarded %q, want %q", tc.method, tc.value, rec.Code, seen, tc.want)
		}
	}
	for _, value := range []string{"x", "-1", "+2", "1, 2", ""} {
		rec, records, _ := exchange(t, s, request(http.MethodOptions, "/a/o", value))
		if e := last(records); rec.Code != http.StatusBadRequest || e["reason"] != "max_forwards" {
			t.Errorf("%q: %d %v", value, rec.Code, e)
		}
	}
}

// An absolute-form target is accepted with its host taken from the target;
// credentials or another scheme are refused. Upgrade is ignored in an
// HTTP/1.0 request and refused in HTTP/1.1.
func TestTargetForms(t *testing.T) {
	var host, upgrade string
	s := setup{ops: []policy.Operation{public("GET", "/a/x")}, forward: func(w http.ResponseWriter, r *http.Request) error {
		host, upgrade = r.Host, r.Header.Get("Upgrade")
		w.WriteHeader(http.StatusOK)
		return nil
	}}
	absolute := httptest.NewRequest(http.MethodGet, "http://shop.test/a/x", nil)
	absolute.Header.Set("Host", "other.test")
	if rec, _, _ := exchange(t, s, absolute); rec.Code != http.StatusOK || host != "shop.test" {
		t.Fatalf("absolute form: %d, host %q", rec.Code, host)
	}
	for _, target := range []string{"http://user@shop.test/a/x", "ftp://shop.test/a/x"} {
		if rec, _, _ := exchange(t, s, httptest.NewRequest(http.MethodGet, target, nil)); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", target, rec.Code)
		}
	}
	old := httptest.NewRequest(http.MethodGet, "/a/x", nil)
	old.Proto, old.ProtoMinor = "HTTP/1.0", 0
	old.Header.Set("Upgrade", "websocket")
	if rec, _, _ := exchange(t, s, old); rec.Code != http.StatusOK || upgrade != "" {
		t.Fatalf("HTTP/1.0 with Upgrade: %d, forwarded %q", rec.Code, upgrade)
	}
	current := httptest.NewRequest(http.MethodGet, "/a/x", nil)
	current.Header.Set("Upgrade", "websocket")
	if rec, _, _ := exchange(t, s, current); rec.Code != http.StatusBadRequest {
		t.Fatalf("HTTP/1.1 with Upgrade: %d, want 400", rec.Code)
	}
}

// Only a trusted proxy names the client, as the rightmost untrusted entry of
// X-Forwarded-For.
func TestTrustedProxies(t *testing.T) {
	proxies, err := ParseProxies([]string{"10.0.0.0/8", "::ffff:192.0.2.7"})
	if err != nil || len(proxies) != 2 || proxies[1] != netip.MustParsePrefix("192.0.2.7/32") {
		t.Fatalf("parse: %v %v", proxies, err)
	}
	s := setup{ops: []policy.Operation{public("GET", "/a/x")}, limits: Limits{TrustedProxies: proxies}}
	for _, tc := range []struct{ peer, header, client string }{
		{"10.0.0.5:1", "198.51.100.1, 203.0.113.9, 10.0.0.7", "203.0.113.9"},
		{"10.0.0.5:1", "10.1.1.1", "10.1.1.1"},
		{"10.0.0.5:1", "203.0.113.9, junk", "10.0.0.5"},
		{"10.0.0.5:1", "", "10.0.0.5"},
		{"198.51.100.2:1", "203.0.113.9", "198.51.100.2"},
	} {
		r := httptest.NewRequest(http.MethodGet, "/a/x", nil)
		r.RemoteAddr = tc.peer
		if tc.header != "" {
			r.Header.Set("X-Forwarded-For", tc.header)
		}
		if _, records, _ := exchange(t, s, r); last(records)["client_address"] != tc.client {
			t.Errorf("peer %s, %q: client %v, want %s", tc.peer, tc.header, last(records)["client_address"], tc.client)
		}
	}
	many := make([]string, MaxProxies+1)
	for i := range many {
		many[i] = "192.0.2." + strconv.Itoa(i)
	}
	for _, refused := range [][]string{{"10.0.0.1/8"}, {"fe80::1%eth0"}, {"proxy.test"}, many} {
		if _, err := ParseProxies(refused); err == nil {
			t.Errorf("%v accepted", refused[0])
		}
	}
}

// A rate refusal says when to retry.
func TestRetryAfter(t *testing.T) {
	op := public("GET", "/a/x")
	op.Rate = &policy.RateRule{Algorithm: compile.RateAlgorithm, Count: 2, WindowSeconds: 60, Key: compile.RateKeyAddress}
	r := func() *http.Request { return httptest.NewRequest(http.MethodGet, "/a/x", nil) }
	rec, _, _ := exchange(t, setup{ops: []policy.Operation{op}}, r(), r(), r())
	seconds, err := strconv.Atoi(rec.Header().Get("Retry-After"))
	// Two requests counted in the current minute: the next is admitted only
	// after this bucket has become the previous one and faded by half.
	if rec.Code != http.StatusTooManyRequests || err != nil || seconds < 30 || seconds > 120 {
		t.Fatalf("answer %d, Retry-After %q", rec.Code, rec.Header().Get("Retry-After"))
	}
}

// An assertion longer than an upstream accepts is never sent.
func TestAssertionBound(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := newSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	var sent string
	s := setup{ops: []policy.Operation{public("GET", "/a/*")}, signer: signer, forward: func(w http.ResponseWriter, r *http.Request) error {
		sent = r.Header.Get(AssertionHeader)
		w.WriteHeader(http.StatusOK)
		return nil
	}}
	if rec, _, _ := exchange(t, s, httptest.NewRequest(http.MethodGet, "/a/short", nil)); rec.Code != http.StatusOK || sent == "" || len(sent) > MaxAssertionBytes {
		t.Fatalf("short path: %d, assertion of %d bytes", rec.Code, len(sent))
	}
	sent = ""
	rec, records, _ := exchange(t, s, httptest.NewRequest(http.MethodGet, "/a/"+strings.Repeat("x", MaxAssertionBytes), nil))
	if e := last(records); rec.Code != http.StatusBadRequest || sent != "" || e["reason"] != "assertion_too_large" || e["stage"] != "BIND" {
		t.Fatalf("long path: %d, sent %d bytes, record %v", rec.Code, len(sent), e)
	}
}

// A path of exactly the logged bound is kept whole and not marked as cut.
func TestPathAtLogBound(t *testing.T) {
	path := "/a/" + strings.Repeat("p", audit.MaxLoggedPath-3)
	_, records, _ := exchange(t, setup{ops: []policy.Operation{public("GET", "/a/*")}}, httptest.NewRequest(http.MethodGet, path, nil))
	if e := last(records); e["path"] != path || e["path_truncated"] != nil {
		t.Fatalf("record %v", e)
	}
}

// A recorded method is cut to the logged bound.
func TestLongMethodRecord(t *testing.T) {
	_, records, _ := exchange(t, setup{ops: []policy.Operation{public("GET", "/a/x")}}, httptest.NewRequest(strings.Repeat("M", 40), "/a/x", nil))
	if e := last(records); e["method"] != strings.Repeat("M", audit.MaxLoggedMethod) || e["path_truncated"] != nil || !quick(e) {
		t.Fatalf("record %v", e)
	}
}
