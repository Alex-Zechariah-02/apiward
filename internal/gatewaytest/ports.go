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

// issuedPorts are the ports FreeAddr has returned to tests of this process
// that have not ended, from the block first-last that the package's TestMain
// gave Main.
var issuedPorts = struct {
	sync.Mutex
	first, last int
	seen        map[int]bool
}{seen: map[int]bool{}}

// FreeAddr returns a loopback address that was free when checked, for a
// gateway to bind later. Ports come from this process's share of the
// package's block of 20000-29999, below the ranges Linux (32768-60999) and
// Windows (49152-65535) give to outgoing connections, so a connection the
// tests open cannot take the port in the meantime. Test packages run at the
// same time, so each has its own block, and no port is returned again before
// the test that took it ends.
func FreeAddr(t testing.TB) string {
	t.Helper()
	issuedPorts.Lock()
	defer issuedPorts.Unlock()
	first, last := issuedPorts.first, issuedPorts.last
	if first == 0 {
		t.Fatal("no port block: the package's TestMain must call Main")
	}
	// 1000 draws: enough to find a free port in practice, and quick to end a full block.
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
		t.Cleanup(func() {
			issuedPorts.Lock()
			defer issuedPorts.Unlock()
			delete(issuedPorts.seen, port)
		})
		return fmt.Sprintf("127.0.0.1:%d", port)
	}
	t.Fatalf("no free loopback port in %d-%d", first, last)
	return ""
}

// portShares is how many processes of one test package can hold ports at
// once: a package's tests run from two shells, or on Windows and in WSL,
// whose loopback ports are shared, each take one share of its block.
const portShares = 10

// portLock holds the first port of this process's share for the life of the
// process; the operating system releases it when the process ends, even
// after a crash, so no share stays claimed.
var portLock net.Listener

// claimPorts gives this process the first share of first-last whose first
// port no other process holds, and draws from the rest of that share.
func claimPorts(first, last int) error {
	span := (last - first + 1) / portShares
	for start := first; start+span-1 <= last; start += span {
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", start))
		if err != nil {
			continue // another process holds this share, or the host reserves the port
		}
		portLock = l
		issuedPorts.Lock()
		defer issuedPorts.Unlock()
		issuedPorts.first, issuedPorts.last = start+1, start+span-1
		return nil
	}
	return fmt.Errorf("every share of test ports %d-%d is held by another test process", first, last)
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
