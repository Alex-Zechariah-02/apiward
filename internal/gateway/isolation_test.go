// The local half of bypass protection: upstreams bind only to loopback.

package gateway

import (
	"net"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

// TestUpstreamsBindOnlyToLoopback checks the local half of bypass protection:
// upstreams accept connections only on loopback, so they are unreachable
// through any other interface of the host. It cannot show that a client on
// another machine is blocked; that requires a separate network position.
func TestUpstreamsBindOnlyToLoopback(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	probed := 0
	for _, a := range addrs {
		ip, _, _ := net.ParseCIDR(a.String())
		if ip == nil || ip.IsLoopback() || ip.To4() == nil {
			continue
		}
		for _, rc := range []*gatewaytest.Receiver{e.A, e.B, e.C} {
			target := net.JoinHostPort(ip.String(), gatewaytest.Port(rc.Addr))
			if gatewaytest.Dialable(target) {
				t.Fatalf("receiver %s reachable at %s", rc.Name, target)
			}
			probed++
		}
	}
	t.Logf("probed %d non-loopback interface addresses; none reached a receiver", probed)
	if probed == 0 {
		t.Skip("no non-loopback IPv4 interface to probe")
	}
}
