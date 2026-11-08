// The harness's copy of the gateway's process contract: binary-driven tests
// check exit codes and write configuration files through the harness
// constants, so these must equal the values the gateway itself uses.

package gateway

import (
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

func TestHarnessContract(t *testing.T) {
	values := []struct {
		name            string
		harness, native int
	}{
		{"exit code: stopped", gatewaytest.ExitStopped, exitStopped},
		{"exit code: failed", gatewaytest.ExitFailed, exitFailed},
		{"exit code: forced", gatewaytest.ExitForced, exitForced},
		{"exit code: incomplete", gatewaytest.ExitIncomplete, exitIncomplete},
		{"configuration version", gatewaytest.ConfigVersion, nativeConfigVersion},
	}
	for _, v := range values {
		if v.harness != v.native {
			t.Errorf("%s: harness %d, gateway %d", v.name, v.harness, v.native)
		}
	}
}
