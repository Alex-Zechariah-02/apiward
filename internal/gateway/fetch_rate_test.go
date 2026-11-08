// Fetch rate rules keyed by client address: compilation.

package gateway

import (
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

func TestFetchRateKeyCompilation(t *testing.T) {
	for _, tc := range []struct{ auth, key, code string }{
		{"none", "client_address", ""}, {"required", "client_address", ""}, {"required", "subject", ""},
		{"none", "subject", "INVALID_VALUE"}, {"required", "X-Forwarded-For", "UNSUPPORTED_FEATURE"},
		{"none", "", "UNSUPPORTED_FEATURE"},
	} {
		p := policy.Policy{
			SchemaVersion: policy.SchemaVersion, Profile: "core",
			Upstreams: []policy.Upstream{{ID: "u", Dial: "127.0.0.1:10501"}},
			APIs:      []policy.API{{ID: "inventory", Upstream: "u"}},
			Operations: []policy.Operation{{ID: "search", API: "inventory", Method: "GET", Target: "/inventory/search", Access: "allow", Auth: tc.auth,
				Rate: &policy.RateRule{Algorithm: "sliding-window", Count: 2, WindowSeconds: 60, Key: tc.key}}},
		}
		_, err := compile.Compile(p, 1, time.Time{})
		if code := errorCode(err); code != tc.code {
			t.Errorf("auth=%s key=%q: %v, want %q", tc.auth, tc.key, err, tc.code)
		}
	}
}
