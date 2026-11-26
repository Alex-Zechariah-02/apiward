// Session table bounds: one administrator's cap ends that administrator's
// oldest session, others keep theirs, and only live sessions are counted.

package session

import (
	"testing"
	"time"
)

func TestPerAdminCap(t *testing.T) {
	start := time.Unix(1000, 0)
	s := New(time.Hour, 8*time.Hour, 2)
	first, _, _ := s.Create("alice", 1, start)
	second, _, _ := s.Create("alice", 1, start.Add(time.Second))
	bob, _, _ := s.Create("bob", 1, start.Add(2*time.Second))
	held, reason := s.Lookup(first, start.Add(3*time.Second))
	if reason != "" || s.Count(start.Add(3*time.Second)) != 3 {
		t.Fatalf("setup: %q", reason)
	}
	closed := held.Closed()
	third, _, err := s.Create("alice", 1, start.Add(4*time.Second))
	if err != nil {
		t.Fatalf("sign-in at the cap: %v", err)
	}
	now := start.Add(5 * time.Second)
	if _, reason := s.Lookup(first, now); reason != "no_session" {
		t.Fatalf("oldest session: %q, want ended", reason)
	}
	select {
	case <-closed:
	default:
		t.Fatal("the ended session was not closed for its readers")
	}
	for _, token := range []string{second, third, bob} {
		if _, reason := s.Lookup(token, now); reason != "" {
			t.Fatalf("a newer or another administrator's session ended: %q", reason)
		}
	}
	if n := s.Count(now); n != 3 {
		t.Fatalf("%d sessions, want 3", n)
	}
}

func TestGlobalBound(t *testing.T) {
	now := time.Unix(1000, 0)
	s := New(time.Hour, 8*time.Hour, 1)
	for i := range Max {
		if _, _, err := s.Create(string(rune('a'+i%26))+string(rune('a'+i/26%26))+string(rune('a'+i/676)), 1, now); err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
	}
	if _, _, err := s.Create("another", 1, now); err != ErrFull {
		t.Fatalf("past the global bound: %v, want ErrFull", err)
	}
	// An administrator at its own limit replaces its oldest session, so a
	// full table does not refuse it.
	if _, _, err := s.Create("aaa", 1, now); err != nil {
		t.Fatalf("an administrator at its own limit in a full table: %v", err)
	}
}

// Count reports live sessions only, and ending them closes them.
func TestCountLive(t *testing.T) {
	start := time.Unix(1000, 0)
	s := New(time.Minute, 8*time.Hour, 8)
	token, _, _ := s.Create("alice", 1, start)
	held, _ := s.Lookup(token, start)
	s.Create("bob", 1, start.Add(30*time.Second))
	if n := s.Count(start.Add(30 * time.Second)); n != 2 {
		t.Fatalf("%d live sessions, want 2", n)
	}
	if n := s.Count(start.Add(70 * time.Second)); n != 1 {
		t.Fatalf("%d sessions after alice's idle end, want 1", n)
	}
	select {
	case <-held.Closed():
	default:
		t.Fatal("an ended session counted out was not closed")
	}
}
