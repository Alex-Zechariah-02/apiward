// Client address allow lists compiled into sorted, disjoint address
// ranges, so a request's address is found by binary search.

package compile

import (
	"net/netip"
	"slices"
)

// span is the inclusive address range of one or more merged prefixes.
type span struct {
	first, last netip.Addr
}

// ranges is an allow list as disjoint spans in address order; IPv4 sorts
// before IPv6, so the families never mix inside a span.
type ranges []span

// newRanges merges prefixes into ranges.
func newRanges(prefixes []netip.Prefix) ranges {
	spans := make([]span, 0, len(prefixes))
	for _, p := range prefixes {
		spans = append(spans, span{first: p.Masked().Addr(), last: lastAddr(p)})
	}
	slices.SortFunc(spans, func(a, b span) int { return a.first.Compare(b.first) })
	out := ranges{}
	for _, s := range spans {
		if n := len(out); n > 0 && adjoins(out[n-1].last, s.first) {
			if out[n-1].last.Less(s.last) {
				out[n-1].last = s.last
			}
			continue
		}
		out = append(out, s)
	}
	return out
}

// adjoins reports whether a range ending at last reaches first: it covers
// it or ends just before it, within one address family.
func adjoins(last, first netip.Addr) bool {
	if last.BitLen() != first.BitLen() {
		return false
	}
	return !last.Less(first) || last.Next() == first
}

// lastAddr is the highest address of p.
func lastAddr(p netip.Prefix) netip.Addr {
	bytes := p.Masked().Addr().AsSlice()
	for bit := p.Bits(); bit < len(bytes)*8; bit++ {
		bytes[bit/8] |= 0x80 >> (bit % 8)
	}
	addr, _ := netip.AddrFromSlice(bytes)
	return addr
}

// contains reports whether addr lies in one of the ranges.
func (r ranges) contains(addr netip.Addr) bool {
	i, _ := slices.BinarySearchFunc(r, addr, func(s span, target netip.Addr) int {
		if s.last.Less(target) {
			return -1
		}
		if target.Less(s.first) {
			return 1
		}
		return 0
	})
	return i < len(r) && !addr.Less(r[i].first) && !r[i].last.Less(addr)
}
