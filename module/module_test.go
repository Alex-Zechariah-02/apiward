// Registration rules and the bounded table.

package module

import (
	"encoding/json"
	"testing"
)

type named string

func (n named) Info() Info                                      { return Info{ID: string(n), Phase: Traffic} }
func (named) Compile(Operation, json.RawMessage) (Check, error) { return nil, nil }

// A build with an invalid, reserved or repeated module ID never starts.
func TestRegisterRefuses(t *testing.T) {
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

// A full table refuses a new key and keeps updating the keys it holds.
func TestTableBound(t *testing.T) {
	table := NewTable[string, int](1)
	add := func(_ int, _ bool) int { return 1 }
	if !table.Update("a", add) || table.Update("b", add) || !table.Update("a", add) || table.Len() != 1 {
		t.Fatalf("bounded table: len %d", table.Len())
	}
}
