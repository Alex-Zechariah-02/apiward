// Order status changes and who may see an order.

package services

import (
	"net/http"
	"time"
)

func seesOrder(r *http.Request, order Order) bool {
	subject := r.Header.Get("X-Gateway-Subject")
	return hasRole(r, "SUPPORT") || hasRole(r, "OPERATIONS") ||
		hasRole(r, "CUSTOMER") && order.Customer == subject ||
		ownsMerchant(r, order.Merchant) ||
		hasRole(r, "RIDER") && order.Rider != nil && *order.Rider == subject
}
func (d *orders) transition(r *http.Request, id, action string) result {
	order := d.find(id)
	if order == nil {
		return notFound()
	}
	subject := r.Header.Get("X-Gateway-Subject")
	want, next := "", ""
	switch action {
	case "accept", "ready":
		if !ownsMerchant(r, order.Merchant) {
			return notFound()
		}
		if action == "accept" {
			want, next = "placed", "accepted"
		} else {
			want, next = "accepted", "ready"
		}
	case "cancel":
		if !hasRole(r, "CUSTOMER") || order.Customer != subject {
			return notFound()
		}
		want, next = "placed", "cancelled"
	case "pickup":
		if !hasRole(r, "RIDER") || subject == "" {
			return notFound()
		}
		if order.Rider != nil && *order.Rider != subject {
			return failure(409, "already_assigned", "Another rider has taken this order.", "")
		}
		want, next = "ready", "picked_up"
	case "deliver":
		if !hasRole(r, "RIDER") || order.Rider == nil || *order.Rider != subject {
			return notFound()
		}
		want, next = "picked_up", "delivered"
	default:
		return notFound()
	}
	if order.Status != want {
		return failure(409, "invalid_transition", "That action is not available for the current order status.", "")
	}
	releaseConfirmed := true
	if key := d.reservations[id]; key != "" {
		if action == "cancel" {
			releaseConfirmed = d.release(r.Context(), key)
		}
		if action == "deliver" {
			status, _, err := d.inventory.call(r.Context(), "POST", "/internal/reservations/"+key+"/commit", nil, key)
			if err != nil || status != 200 {
				return inventoryUnavailable()
			}
		}
	}
	if action == "pickup" {
		rider := subject
		order.Rider = &rider
	}
	if action == "cancel" && order.Payment == "wallet" {
		d.wallets[subject] += order.Total
	}
	order.Status = next
	order.Timeline = append(order.Timeline, TimelineEntry{next, time.Now().UTC()})
	if !releaseConfirmed {
		return inventoryUnavailable()
	}
	return result{status: 200, body: map[string]any{"order": *order}, effect: next + " " + id}
}
