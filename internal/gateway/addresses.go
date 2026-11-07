// Admin API changes to the blocked address list.

package gateway

import (
	"database/sql"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

func (s *adminAPI) handleBlockedAddresses(w http.ResponseWriter, r *http.Request, who caller) {
	current := s.control.Addresses()
	if current == nil {
		adminError(w, http.StatusServiceUnavailable, "gateway_unavailable", "")
		return
	}
	now := compile.TrustedNow()
	items := []store.BlockedAddress{}
	for _, entry := range *current {
		if entry.Active(now) {
			items = append(items, entry)
		}
	}
	slices.SortFunc(items, func(a, b store.BlockedAddress) int { return strings.Compare(a.Range, b.Range) })
	pipeline.WriteJSON(w, http.StatusOK, list{Items: items})
}

// addressRange reads the {range} path value: a CIDR range in canonical form,
// IPv4-mapped IPv6 accepted as the IPv4 range it covers.
func addressRange(w http.ResponseWriter, r *http.Request) (netip.Prefix, bool) {
	prefix, ok := store.BlockRange(r.PathValue("range"))
	if !ok {
		adminError(w, http.StatusBadRequest, "bad_request", "range")
	}
	return prefix, ok
}

func (s *adminAPI) handleBlockAddress(w http.ResponseWriter, r *http.Request, who caller) {
	prefix, ok := addressRange(w, r)
	if !ok {
		return
	}
	key, ok := idempotencyKey(w, r)
	if !ok {
		return
	}
	var request struct {
		Reason    string     `json:"reason"`
		ExpiresAt *time.Time `json:"expires_at,omitempty"`
	}
	if !decodeBody(w, r, maxAdminBody, &request) {
		return
	}
	if !store.ValidBlockReason(request.Reason) {
		adminError(w, http.StatusBadRequest, "bad_request", "reason")
		return
	}
	if request.ExpiresAt != nil {
		ahead := time.Until(*request.ExpiresAt)
		if ahead < store.MinAddressExpiry || ahead > store.MaxAddressExpiry {
			adminError(w, http.StatusBadRequest, "bad_request", "expires_at")
			return
		}
		at := request.ExpiresAt.UTC().Truncate(time.Millisecond)
		request.ExpiresAt = &at
	}
	t := adminTransition(who, key, "address.block", prefix.String(), sql.NullInt64{}, request)
	body, status := s.control.BlockAddress(r.Context(), t, store.BlockedAddress{Range: prefix.String(), Prefix: prefix, Reason: request.Reason, ExpiresAt: request.ExpiresAt})
	pipeline.WriteJSON(w, status, body)
}

func (s *adminAPI) handleUnblockAddress(w http.ResponseWriter, r *http.Request, who caller) {
	prefix, ok := addressRange(w, r)
	if !ok || !noRequestBody(w, r) {
		return
	}
	key, ok := idempotencyKey(w, r)
	if !ok {
		return
	}
	t := adminTransition(who, key, "address.unblock", prefix.String(), sql.NullInt64{}, nil)
	body, status := s.control.UnblockAddress(r.Context(), t, store.BlockedAddress{Range: prefix.String(), Prefix: prefix})
	pipeline.WriteJSON(w, status, body)
}
