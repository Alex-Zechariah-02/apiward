// Test port issue: a port returns to the pool when the test that took it
// ends.

package gatewaytest

import (
	"fmt"
	"testing"
)

// usePorts sets the port block of this process for one test and restores
// the previous block when it ends.
func usePorts(t *testing.T, first, last int) {
	issuedPorts.Lock()
	before, seen := [2]int{issuedPorts.first, issuedPorts.last}, issuedPorts.seen
	issuedPorts.first, issuedPorts.last, issuedPorts.seen = first, last, map[int]bool{}
	issuedPorts.Unlock()
	t.Cleanup(func() {
		issuedPorts.Lock()
		defer issuedPorts.Unlock()
		issuedPorts.first, issuedPorts.last, issuedPorts.seen = before[0], before[1], seen
	})
}

func TestFreeAddrReusesReleasedPorts(t *testing.T) {
	usePorts(t, 30000, 30009)
	for i := range 15 {
		t.Run(fmt.Sprintf("draw-%d", i), func(t *testing.T) {
			FreeAddr(t)
		})
	}
}
