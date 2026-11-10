// Ingress checks: requests no policy can act on, client addresses on the
// blocked address list, and the key an address-based rate counter uses for
// each address.

package pipeline

import (
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/compile"
)

// admitAddress refuses a request whose client address an active entry of
// the blocked address list covers (403 address_blocked at INGRESS). An
// address that does not parse is refused while any entry exists, since it
// cannot be shown not to match. The list is unset only when the store could
// not be opened; no policy is then published, so CAPTURE refuses the request.
func (h *Handler) admitAddress(q *request) bool {
	list := h.authority.Addresses()
	if list == nil || len(*list) == 0 {
		return true
	}
	addr, err := netip.ParseAddr(q.event.ClientAddress)
	if err != nil {
		q.event.Reason = "invalid_peer_address"
		q.reject(audit.StageIngress, http.StatusBadRequest, "bad_request")
		return false
	}
	if list.Blocks(addr, compile.TrustedNow()) {
		q.event.Reason = "address_blocked"
		q.reject(audit.StageIngress, http.StatusForbidden, "address_blocked")
		return false
	}
	return true
}

// ingressRefusal names why a request no policy can act on is refused, or
// returns "": only origin-form targets, no tunnelling, bounded declared size.
// A protocol upgrade would turn an admitted request into a raw stream the
// policy never sees. The proxy removes every header named in Connection, so
// naming a gateway header there would strip it after it is set. HTTP/2 reads
// an unparseable Content-Length as 0 and keeps the stream open, where HTTP/1
// refuses the request; both are refused.
func (h *Handler) ingressRefusal(r *http.Request) string {
	switch {
	case r.Method == http.MethodConnect:
		return "connect"
	case !strings.HasPrefix(r.RequestURI, "/"):
		return "target"
	case r.Header.Get("Upgrade") != "":
		return "upgrade"
	case slices.ContainsFunc(connectionNames(r.Header), compile.IsGatewayHeader):
		return "connection_header"
	case slices.ContainsFunc(r.Header.Values("Content-Length"), func(v string) bool { return v != strconv.FormatInt(r.ContentLength, 10) }):
		return "content_length"
	case r.ContentLength > h.maxBodyBytes:
		return "too_large"
	}
	return ""
}

// rateAddress is the rate key of a client address: an IPv4 address itself,
// an IPv6 address masked to the configured prefix. text is addr's text
// form, already built for the record. Blocked-address checks and the
// security log keep the exact address.
func (h *Handler) rateAddress(addr netip.Addr, text string) string {
	if !addr.Is6() {
		return text
	}
	// New accepts only prefix lengths 48 to 128, which every IPv6 address has.
	prefix, _ := addr.Prefix(h.ipv6Prefix)
	return prefix.String()
}
