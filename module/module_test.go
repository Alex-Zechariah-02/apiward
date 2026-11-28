// Registration rules and failure reasons.

package module

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"strings"
	"testing"
)

type named string

func (n named) Info() Info                                      { return Info{ID: string(n), Phase: Traffic} }
func (named) Compile(Operation, json.RawMessage) (Check, error) { return nil, nil }

// A build with an invalid, reserved or repeated module ID never starts.
func TestRegisterRefuses(t *testing.T) {
	const child = "register-refusals"
	if flag.Arg(0) == child {
		checkRegister(t)
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	if deadline, ok := t.Deadline(); ok {
		bounded, cancel := context.WithDeadline(ctx, deadline)
		defer cancel()
		ctx = bounded
	}
	cmd := exec.CommandContext(ctx, exe, "-test.run=^"+t.Name()+"$", "--", child)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("registration subprocess: %v\n%s", err, output)
	}
}

func checkRegister(t *testing.T) {
	t.Helper()
	Register(named("taken"))
	for _, id := range []string{"", "Upper", "has-dash", "target", "taken"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Register(%q) did not panic", id)
				}
			}()
			Register(named(id))
		}()
	}
	if got := Registered(); len(got) != 1 || got[0].ID != "taken" {
		t.Fatalf("registered: %v", got)
	}
}

// A failure reason is recorded only when it is a short printable phrase.
func TestFailReason(t *testing.T) {
	for _, tc := range []struct{ reason, want string }{
		{"store unavailable", "store unavailable"},
		{strings.Repeat("r", maxReason), strings.Repeat("r", maxReason)},
		{"", "invalid failure reason"},
		{strings.Repeat("r", maxReason+1), "invalid failure reason"},
		{"line\nbreak", "invalid failure reason"},
		{"caf\xc3\xa9", "invalid failure reason"},
	} {
		if got := Fail(tc.reason); !got.Failed() || got.Reason() != tc.want {
			t.Errorf("Fail(%q): %q, want %q", tc.reason, got.Reason(), tc.want)
		}
	}
}
