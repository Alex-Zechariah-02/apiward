// The client address behind trusted proxies, and the Max-Forwards rule for
// OPTIONS requests.

package pipeline

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
)

// MaxProxies bounds data.trusted_proxies: a deployment names a few load
// balancers or one network of them, and each request may test every entry.
const MaxProxies = 64

// ParseProxies reads data.trusted_proxies: each entry an IP address or a
// CIDR prefix. None trusts no peer, so the socket peer is always the client.
func ParseProxies(entries []string) ([]netip.Prefix, error) {
	if len(entries) > MaxProxies {
		return nil, fmt.Errorf("at most %d entries", MaxProxies)
	}
	prefixes := make([]netip.Prefix, 0, len(entries))
	for _, entry := range entries {
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			addr, addrErr := netip.ParseAddr(entry)
			if addrErr != nil || addr.Zone() != "" {
				return nil, fmt.Errorf("%q is not an IP address or CIDR prefix", entry)
			}
			prefix = netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen())
		}
		if prefix != prefix.Masked() {
			return nil, fmt.Errorf("%q has bits set past its prefix length", entry)
		}
		// Peers are compared unmapped, and an IPv4 address never matches an
		// IPv6 prefix: an IPv4-mapped prefix becomes the IPv4 one it names.
		if prefix.Addr().Is4In6() {
			if prefix.Bits() < 96 {
				return nil, fmt.Errorf("%q covers more than IPv4-mapped addresses", entry)
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		prefixes = append(prefixes, prefix)
	}
	if len(prefixes) == 0 {
		return nil, nil
	}
	return prefixes, nil
}

// trusted reports whether addr is a configured proxy.
func (h *Handler) trusted(addr netip.Addr) bool {
	for _, prefix := range h.proxies {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// clientAddress is the address a request is decided and recorded by: the
// socket peer, unless the peer is a trusted proxy. Then X-Forwarded-For is
// read from the right, past every trusted proxy, and the first address that
// is not one is the client; when all are trusted, the leftmost is. An entry
// that is not an IP address ends the walk at the address before it, which
// the client cannot have written. When the peer is a trusted proxy and at
// least one entry was validated, the second return value is the validated
// chain with the peer appended for the upstream X-Forwarded-For header;
// otherwise it is empty so the proxy sends the direct peer alone.
func (h *Handler) clientAddress(peer netip.Addr, header http.Header) (netip.Addr, string) {
	if !h.trusted(peer) {
		return peer, ""
	}
	client := peer
	var hops []string
	values := header.Values("X-Forwarded-For")
	for _, value := range slices.Backward(values) {
		for _, entry := range slices.Backward(strings.Split(value, ",")) {
			addr, err := netip.ParseAddr(strings.TrimSpace(entry))
			if err != nil || addr.Zone() != "" {
				return client, forwardedChain(hops, peer)
			}
			client = addr.Unmap()
			hops = append(hops, client.String())
			if !h.trusted(client) {
				return client, forwardedChain(hops, peer)
			}
		}
	}
	return client, forwardedChain(hops, peer)
}

// forwardedChain formats the validated hops (collected right-to-left) in
// left-to-right order with peer appended; empty when no hop was validated.
func forwardedChain(hops []string, peer netip.Addr) string {
	if len(hops) == 0 {
		return ""
	}
	slices.Reverse(hops)
	hops = append(hops, peer.String())
	return strings.Join(hops, ", ")
}

// errMaxForwards is a Max-Forwards field that is not one decimal number.
var errMaxForwards = errors.New("invalid Max-Forwards")

// maxForwards applies RFC 9110 section 7.6.2 to an OPTIONS request: with
// Max-Forwards 0 the gateway answers it itself, as the final recipient,
// naming the methods of the target in Allow; a larger value is decremented
// for the upstream. A field that is not one number is refused. It reports
// whether the request was answered.
func maxForwards(q *request, r *http.Request, allow string) bool {
	values := r.Header.Values("Max-Forwards")
	if len(values) == 0 {
		return false
	}
	remaining, err := forwardsLeft(values)
	if err != nil {
		q.event.Reason = "max_forwards"
		q.reject(audit.StageRoute, http.StatusBadRequest, "bad_request")
		return true
	}
	if remaining > 0 {
		r.Header.Set("Max-Forwards", strconv.FormatUint(remaining-1, 10))
		return false
	}
	q.w.Header().Set("Allow", allow)
	q.answered("allowed", "max_forwards", audit.StagePass)
	return true
}

// forwardsLeft reads the one Max-Forwards field: 1*DIGIT (RFC 9110).
func forwardsLeft(values []string) (uint64, error) {
	if len(values) != 1 || values[0] == "" || strings.Trim(values[0], "0123456789") != "" {
		return 0, errMaxForwards
	}
	return strconv.ParseUint(values[0], 10, 64)
}
