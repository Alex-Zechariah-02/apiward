// Offline checks decide as the gateway's request handler does.

package policy

import (
	"errors"
	"slices"
	"testing"
)

func TestCheck(t *testing.T) {
	p := Policy{
		SchemaVersion: SchemaVersion,
		Profile:       ProfileCore,
		Upstreams:     []Upstream{{ID: "shop", Dial: "127.0.0.1:9000"}},
		APIs:          []API{{ID: "shop", Upstream: "shop"}},
		Operations: []Operation{
			{ID: "list-items", API: "shop", Method: "GET", Target: "/items/*", Access: "allow", Auth: "none"},
			{ID: "add-item", API: "shop", Method: "POST", Target: "/items", Access: "allow", Auth: "required"},
		},
		Roles:   []Role{{ID: "staff"}},
		Permits: []Permit{{Role: "staff", Operation: "add-item"}},
	}
	allowed, err := Check(p, Request{Method: "GET", Path: "/items/42"})
	if err != nil || !allowed.Allowed || allowed.Forwarded != "/items/42" || allowed.Operation != "list-items" {
		t.Fatalf("public read: %+v, %v", allowed, err)
	}
	refused, err := Check(p, Request{Method: "POST", Path: "/items", Roles: []string{"guest"}})
	if err != nil || refused.Allowed || refused.Check != "role" || !slices.Contains(refused.NotChecked, "token") {
		t.Fatalf("write without the role: %+v, %v", refused, err)
	}
	granted, err := Check(p, Request{Method: "POST", Path: "/items", Roles: []string{"staff"}})
	if err != nil || !granted.Allowed {
		t.Fatalf("write with the role: %+v, %v", granted, err)
	}
	if _, err := Check(p, Request{Method: "GET", Path: "/items/%2e%2e"}); err == nil {
		t.Fatal("a path the handler refuses was checked")
	}
	p.SchemaVersion = LatestSchemaVersion + 1
	if _, err := Check(p, Request{Method: "GET", Path: "/items/42"}); !errors.As(err, new(*PolicyError)) {
		t.Fatalf("unsupported schema: %v", err)
	}
}
