// Loopback addresses for test listeners: free ports below the ephemeral
// ranges, and addresses for checks on other interfaces.

package gatewaytest

import (
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"testing"
)

// issuedPorts are the ports FreeAddr has returned in this test process, from
// the block first-last that the package's TestMain gave Main.
var issuedPorts = struct {
	sync.Mutex
	first, last int
	seen        map[int]bool
}{seen: map[int]bool{}}

// FreeAddr returns a loopback address that was free when checked, for a
// gateway to bind later. Ports come from the package's block of 20000-29999,
// below the ranges Linux (32768-60999) and Windows (49152-65535) give to
// outgoing connections, so a connection the tests open cannot take the port
// in the meantime. Test packages run at the same time, so each has its own
// block, and no port is returned twice.
func FreeAddr(t testing.TB) string {
	t.Helper()
	issuedPorts.Lock()
	defer issuedPorts.Unlock()
	first, last := issuedPorts.first, issuedPorts.last
	if first == 0 {
		t.Fatal("no port block: the package's TestMain must call Main")
	}
	for range 1000 {
		port := first + rand.IntN(last-first+1)
		if issuedPorts.seen[port] {
			continue
		}
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			continue // in use, or reserved by the host
		}
		l.Close()
		issuedPorts.seen[port] = true
		return fmt.Sprintf("127.0.0.1:%d", port)
	}
	t.Fatalf("no free loopback port in %d-%d", first, last)
	return ""
}

// Port is the port of a host:port address.
func Port(addr string) string {
	_, p, _ := net.SplitHostPort(addr)
	return p
}

// The separate-network probe also isolates its port by the configured offset. Its
// optional host firewall rule must match this address and the test binary.
func WSLDataAddress(t *testing.T, host string) string {
	t.Helper()
	return net.JoinHostPort(host, Port(DemoTestAddress(t, "127.0.0.1:18443")))
}
