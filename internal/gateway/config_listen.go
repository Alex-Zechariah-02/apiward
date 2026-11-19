// Configuration checks of the listener addresses: the data-plane address and
// the distinct ports of every listener.

package gateway

import (
	"fmt"
	"net/netip"
)

// checkDataListen requires the data-plane address to be a literal IP address
// and port that names one interface, or every interface when all is set. An
// IPv4-mapped IPv6 address is checked as the IPv4 address it binds:
// "[::ffff:0.0.0.0]" listens on every interface.
func checkDataListen(listen string, all bool) error {
	addr, err := netip.ParseAddrPort(listen)
	ip := addr.Addr().Unmap()
	if err != nil || addr.Port() == 0 || (ip.IsUnspecified() && !all) || ip.IsMulticast() {
		return fmt.Errorf("data.listen %q must be a literal IP address of one interface with a port (all interfaces only with data.listen_all_interfaces)", listen)
	}
	return nil
}

// checkDistinct refuses two listeners that would bind the same port on a
// shared address, so the conflict is named here rather than met at the bind.
func checkDistinct(d dataSettings, admin, metrics, health string) error {
	listeners := []struct{ name, address string }{{"data.listen", d.Listen}, {"gateway.admin_listen", admin}, {"gateway.metrics_listen", metrics}}
	if health != "" {
		listeners = append(listeners, struct{ name, address string }{"gateway.health_listen", health})
	}
	if d.RedirectHTTP != nil {
		listeners = append(listeners, struct{ name, address string }{"data.redirect_http.listen", d.RedirectHTTP.Listen})
	}
	for i, a := range listeners {
		for _, b := range listeners[:i] {
			if overlap(a.address, b.address) {
				return fmt.Errorf("%s and %s must not share an address and port", b.name, a.name)
			}
		}
	}
	return nil
}

// overlap reports whether two listen addresses take the same port on a
// shared address: the same address, or a wildcard of the other's family. An
// IPv6 wildcard ("[::]") also takes IPv4, as Go listens dual-stack there. An
// address that is not a literal IP and port is compared as written.
func overlap(a, b string) bool {
	x, errX := netip.ParseAddrPort(a)
	y, errY := netip.ParseAddrPort(b)
	if errX != nil || errY != nil {
		return a == b
	}
	p, q := x.Addr().Unmap(), y.Addr().Unmap()
	if x.Port() != y.Port() {
		return false
	}
	covers := func(wild, other netip.Addr) bool { return wild.IsUnspecified() && (wild.Is6() || other.Is4()) }
	return p == q || covers(p, q) || covers(q, p)
}
