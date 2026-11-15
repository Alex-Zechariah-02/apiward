// Sign-in throttling: per name and per client address, with attempts in
// progress counted.

package admin

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestThrottle(t *testing.T) {
	now := time.Now()
	from := func(address string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/admin/session", nil)
		r.RemoteAddr = address + ":40000"
		return r
	}
	local := from("127.0.0.1")
	fail := func(t *testing.T, th *throttle, name string, r *http.Request, times int) {
		t.Helper()
		for range times {
			try, reason := th.begin(name, r, now)
			if reason != "" {
				t.Fatalf("attempt on %s refused early: %s", name, reason)
			}
			try.failed(now)
		}
	}

	// A name that does not exist locks like one that does, so the answers
	// never show which names exist.
	t.Run("unknown names lock", func(t *testing.T) {
		th := newThrottle()
		fail(t, th, "nobody", local, maxNameFailures)
		if _, reason := th.begin("nobody", local, now); reason != "locked" {
			t.Fatalf("after %d failures: %q", maxNameFailures, reason)
		}
		if _, reason := th.begin("nobody", local, now.Add(lockoutPeriod)); reason != "" {
			t.Fatalf("after the lockout: %q", reason)
		}
	})

	// Attempts still being checked count, so parallel guesses cannot all
	// pass the check before the first failure is counted.
	t.Run("attempts in progress count", func(t *testing.T) {
		th := newThrottle()
		var open []attempt
		for range maxNameFailures {
			try, reason := th.begin("alice", local, now)
			if reason != "" {
				t.Fatalf("attempt refused early: %s", reason)
			}
			open = append(open, try)
		}
		if _, reason := th.begin("alice", local, now); reason != "locked" {
			t.Fatalf("attempt beyond those in progress: %q", reason)
		}
		for _, try := range open {
			try.abandoned()
		}
		if _, reason := th.begin("alice", local, now); reason != "" {
			t.Fatalf("after the attempts were abandoned: %q", reason)
		}
	})

	// A verified password clears the name's failures.
	t.Run("success clears the name", func(t *testing.T) {
		th := newThrottle()
		fail(t, th, "alice", local, maxNameFailures-1)
		try, reason := th.begin("alice", local, now)
		if reason != "" {
			t.Fatalf("attempt refused: %s", reason)
		}
		try.succeeded()
		fail(t, th, "alice", local, maxNameFailures-1)
		if _, reason := th.begin("alice", local, now); reason != "" {
			t.Fatalf("failures before the success still count: %q", reason)
		}
	})

	// Failures from one address stop that address only.
	t.Run("one address cannot lock out another", func(t *testing.T) {
		th := newThrottle()
		for i := range maxSourceFailures {
			fail(t, th, fmt.Sprintf("name-%d", i), local, 1)
		}
		if _, reason := th.begin("alice", local, now); reason != "throttled" {
			t.Fatalf("address after %d failures: %q", maxSourceFailures, reason)
		}
		if _, reason := th.begin("alice", from("127.0.0.2"), now); reason != "" {
			t.Fatalf("another address: %q", reason)
		}
	})
}
