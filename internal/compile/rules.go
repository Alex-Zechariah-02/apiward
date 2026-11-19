// Rate and header rules compiled into a generation.

package compile

import (
	"net/http"
	"strings"

	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

const (
	RateAlgorithm  = "sliding-window"
	RateKeySubject = "subject"
	RateKeyAddress = "client_address"
	// MaxRateCount is far above any per-account rate a small team's API
	// serves, so it refuses only a mistyped count, not a real limit.
	MaxRateCount = 1_000_000
	// MaxRateWindowSec is one day: a longer window is a quota, which the
	// sliding-window limiter does not keep across restarts.
	MaxRateWindowSec = 86_400
	// SweepInterval is how many admissions pass between removals of expired
	// counters: often enough to bound memory, rarely enough to cost little.
	SweepInterval = 1024
)

// RateRule is a compiled rate rule: at most count requests per window
// milliseconds for each verified subject or each direct client address.
type RateRule struct {
	count  int64
	window int64 // milliseconds
}

// stricter reports whether r allows fewer requests per unit of time than
// other; at an equal rate the longer window is stricter.
func (r *RateRule) stricter(other *RateRule) bool {
	mine, theirs := r.count*other.window, other.count*r.window
	return mine < theirs || mine == theirs && r.window > other.window
}

func CompileRate(rule policy.RateRule, field string) (*RateRule, error) {
	if rule.Algorithm != RateAlgorithm {
		return nil, policy.Invalid("UNSUPPORTED_FEATURE", "%s.algorithm", field)
	}
	if rule.Key != RateKeySubject && rule.Key != RateKeyAddress {
		return nil, policy.Invalid("UNSUPPORTED_FEATURE", "%s.key", field)
	}
	if rule.Count < 1 || rule.Count > MaxRateCount {
		return nil, policy.Invalid("INVALID_VALUE", "%s.count", field)
	}
	if rule.WindowSeconds < 1 || rule.WindowSeconds > MaxRateWindowSec {
		return nil, policy.Invalid("INVALID_VALUE", "%s.window_seconds", field)
	}
	return &RateRule{count: rule.Count, window: rule.WindowSeconds * 1000}, nil
}

// IsGatewayHeader reports whether only the gateway may set the named header.
func IsGatewayHeader(name string) bool {
	name = http.CanonicalHeaderKey(name)
	return name == "X-Request-Id" || strings.HasPrefix(name, "X-Gateway-")
}
