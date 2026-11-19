// The blocked address lookup made on every request while the list is not
// empty: it agrees with testing every entry, and its cost is benchmarked.

package store_test

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// fullList is MaxBlockedAddresses entries: IPv4 hosts and /24 ranges and
// IPv6 /64 ranges, the shapes an operator blocks during an incident.
func fullList() map[string]store.BlockedAddress {
	list := map[string]store.BlockedAddress{}
	for i := 0; len(list) < store.MaxBlockedAddresses; i++ {
		var text string
		switch i % 3 {
		case 0:
			text = fmt.Sprintf("10.%d.%d.%d/32", i>>16&255, i>>8&255, i&255)
		case 1:
			text = fmt.Sprintf("172.%d.%d.0/24", 16+i>>8&15, i&255)
		default:
			text = fmt.Sprintf("2001:db8:%x:%x::/64", i>>8, i&255)
		}
		prefix := netip.MustParsePrefix(text)
		list[text] = store.BlockedAddress{Range: text, Prefix: prefix, Reason: "incident", BlockedBy: "admin"}
	}
	return list
}

// The index answers as a test of every entry would, for covered and
// uncovered addresses of both families, IPv4-mapped addresses and an entry
// past its expiry.
func TestBlocksMatchesScan(t *testing.T) {
	entries := fullList()
	now := time.Now()
	past, future := now.Add(-time.Minute), now.Add(time.Minute)
	for text, until := range map[string]*time.Time{"192.0.2.0/24": &past, "198.51.100.7/32": &future, "0.0.0.0/1": &past, "2001:db8::/32": &past} {
		entries[text] = store.BlockedAddress{Range: text, Prefix: netip.MustParsePrefix(text), ExpiresAt: until}
	}
	list := store.NewAddressIndex(entries)
	for _, text := range []string{"10.0.0.0", "10.0.1.2", "10.0.1.3", "172.16.5.9", "172.31.255.1", "192.0.2.10", "198.51.100.7",
		"::ffff:198.51.100.7", "::ffff:172.16.5.9", "2001:db8:0:5::1", "2001:db8:ffff::1", "8.8.8.8", "fe80::1%eth0"} {
		addr := netip.MustParseAddr(text)
		want := false
		for _, entry := range entries {
			if entry.Prefix.Contains(addr.Unmap()) && entry.Active(now) {
				want = true
			}
		}
		if got := list.Blocks(addr, now); got != want {
			t.Errorf("Blocks(%s) = %v, want %v", text, got, want)
		}
	}
}

func BenchmarkBlocks(b *testing.B) {
	scan := store.BlockedAddresses(fullList())
	index := store.NewAddressIndex(scan)
	now := time.Now()
	for _, tc := range []struct {
		name string
		addr netip.Addr
	}{
		{"miss", netip.MustParseAddr("192.0.2.10")},
		{"hit", netip.MustParseAddr("172.16.5.9")},
		{"miss-v6", netip.MustParseAddr("2001:db8:ffff::1")},
	} {
		b.Run("scan-"+tc.name, func(b *testing.B) {
			for b.Loop() {
				scan.Blocks(tc.addr, now)
			}
		})
		b.Run("index-"+tc.name, func(b *testing.B) {
			for b.Loop() {
				index.Blocks(tc.addr, now)
			}
		})
	}
}
