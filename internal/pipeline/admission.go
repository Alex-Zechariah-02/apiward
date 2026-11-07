// Refusal of client addresses on the blocked address list, at ingress.

package pipeline

import (
	"net/http"
	"net/netip"

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
