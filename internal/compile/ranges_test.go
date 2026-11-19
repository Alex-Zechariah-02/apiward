// Allow lists as merged address ranges: overlapping, nested and adjacent
// prefixes, both families and IPv4-mapped client addresses.

package compile

import (
	"net/netip"
	"testing"
)

func TestAllowRanges(t *testing.T) {
	var prefixes []netip.Prefix
	for _, text := range []string{"10.0.1.0/24", "10.0.0.0/24", "10.0.0.128/25", "192.0.2.7/32", "2001:db8::/32", "0.0.0.0/8"} {
		prefixes = append(prefixes, netip.MustParsePrefix(text))
	}
	r := newRanges(prefixes)
	if len(r) != 4 {
		t.Fatalf("%d ranges %v, want 4 (the adjacent and nested prefixes merged)", len(r), r)
	}
	for address, want := range map[string]bool{
		"10.0.0.0": true, "10.0.1.255": true, "10.0.2.0": false, "9.255.255.255": false,
		"0.0.0.0": true, "0.255.255.255": true, "192.0.2.7": true, "192.0.2.8": false, "192.0.2.6": false,
		"::ffff:10.0.0.5": true, "2001:db8:ffff::1": true, "2001:db9::": false, "::a00:5": false,
	} {
		if got := r.contains(netip.MustParseAddr(address).Unmap()); got != want {
			t.Errorf("%s: %v, want %v", address, got, want)
		}
	}
}
