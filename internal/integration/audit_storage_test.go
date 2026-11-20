// The security log's storage under a full disk: the reserve file keeps
// records saved, so admission continues.

package integration

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

// The disk is full until the reserve file is deleted (the fault): each write
// that meets it releases the reserve and is written again, the archiver
// makes the reserve again, and no request is refused for the security log.
func TestReserveKeepsAdmission(t *testing.T) {
	t.Parallel()
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Fault, "GATEWAY_FAULT=audit-full-reserve")
	refused := 0
	for range 60 {
		if code, _ := e.Get("/a/x"); code != http.StatusOK {
			refused++
		}
	}
	if refused != 0 {
		t.Fatalf("%d of 60 requests refused with a full disk and a reserve", refused)
	}
	if !strings.Contains(e.Output.String(), "audit reserve released") {
		t.Fatalf("the reserve was never released\n%s", e.Output)
	}
	e.AssertReceipts(60, 0, 0)
}
