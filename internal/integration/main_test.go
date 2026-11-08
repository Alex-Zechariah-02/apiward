// Package integration tests the gateway end to end: each test runs the real
// gateway binary, and the fixture and demo programs, as separate processes
// through the gatewaytest harness, and checks what the processes, the Admin
// API, the upstreams and the files show.
package integration

import (
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

func TestMain(m *testing.M) { gatewaytest.Main(m, 24000, 29999) }
