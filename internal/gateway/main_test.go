// The test binary's entry point: the harness builds the gateway programs the
// tests run.

package gateway

import (
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

func TestMain(m *testing.M) { gatewaytest.Main(m, 20000, 23999) }
