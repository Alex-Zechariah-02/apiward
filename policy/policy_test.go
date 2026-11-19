// Offline checks decide as the gateway's request handler does, for a policy
// written with the package's vocabulary constants.

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
			{ID: "list-items", API: "shop", Method: "GET", Target: "/items/*", Access: AccessAllow, Auth: AuthNone,
				Rate: &RateRule{Algorithm: SlidingWindow, Count: 60, WindowSeconds: 60, Key: KeyClientAddress}},
			{ID: "add-item", API: "shop", Method: "POST", Target: "/items", Access: AccessAllow, Auth: AuthRequired,
				Rate: &RateRule{Algorithm: SlidingWindow, Count: 10, WindowSeconds: 60, Key: KeySubject}},
			{ID: "drop-items", API: "shop", Method: "DELETE", Target: "/items", Access: AccessDeny, Auth: AuthRequired},
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
	denied, err := Check(p, Request{Method: "DELETE", Path: "/items", Roles: []string{"staff"}})
	if err != nil || denied.Allowed {
		t.Fatalf("denied operation: %+v, %v", denied, err)
	}
	if _, err := Check(p, Request{Method: "GET", Path: "/items/%2e%2e"}); err == nil {
		t.Fatal("a path the handler refuses was checked")
	}
	p.SchemaVersion = LatestSchemaVersion + 1
	if _, err := Check(p, Request{Method: "GET", Path: "/items/42"}); !errors.As(err, new(*PolicyError)) {
		t.Fatalf("unsupported schema: %v", err)
	}
}
