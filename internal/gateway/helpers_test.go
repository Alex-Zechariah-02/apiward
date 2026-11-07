// Helpers shared by several test files of the package.

package gateway

import (
	"fmt"

	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// quota compiles a per-subject sliding-window rate rule of count requests per
// window milliseconds, which must be whole seconds, through the compiler.
func quota(count, window int64) *compile.RateRule {
	rule, err := compile.CompileRate(policy.RateRule{Algorithm: compile.RateAlgorithm, Count: count, WindowSeconds: window / 1000, Key: compile.RateKeySubject}, "rate")
	if err != nil || window%1000 != 0 {
		panic(fmt.Sprintf("quota(%d, %d): %v", count, window, err))
	}
	return rule
}

// testTrust trusts one issuer and audience with the single key "test-a" read
// from file.
func testTrust(issuer, audience, file string) pipeline.TrustConfig {
	return pipeline.TrustConfig{Issuer: issuer, Audience: audience, Keys: []pipeline.VerificationKey{{Kid: "test-a", PublicKeyFile: file}}}
}
