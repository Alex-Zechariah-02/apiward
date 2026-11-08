// Checkout for the Orders API: request checks, stock reservation through
// Inventory and the idempotent placing of an order.

package services

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"time"
)

func inventoryUnavailable() result {
	return failure(503, "inventory_unavailable", "Inventory could not confirm this request. Check the order before trying again.", "")
}

func (d *orders) create(r *http.Request, body []byte) result {
	subject := r.Header.Get("X-Gateway-Subject")
	if _, found := d.wallets[subject]; !found || !hasRole(r, "CUSTOMER") {
		return notFound()
	}
	values := r.Header.Values("Idempotency-Key")
	if len(values) > 1 || len(values) == 1 && !idempotencyKey(values[0]) {
		return failure(400, "invalid_request", "Use an idempotency key of 16 to 64 letters, digits, underscores or hyphens.", "Idempotency-Key")
	}
	key := r.Header.Get("Idempotency-Key")
	scope := subject + ":" + key
	digest := sha256.Sum256(body)
	if previous, found := d.idempotency[scope]; key != "" && found {
		if previous.digest != digest {
			return failure(409, "idempotency_conflict", "This checkout key was used for a different order.", "")
		}
		return result{status: previous.status, body: previous.body}
	}
	res := d.place(r, body, key)
	if key != "" {
		encoded, _ := json.Marshal(res.body)
		d.idempotency[scope] = savedOrderResult{digest, res.status, encoded}
		res.body = json.RawMessage(encoded)
	}
	return res
}
func (d *orders) place(r *http.Request, body []byte, key string) result {
	var request orderRequest
	if rejected := decodeBody(r, body, 4096, &request); rejected != nil {
		return *rejected
	}
	if !validOrderRequest(request) {
		return failure(400, "invalid_request", "Check the items, delivery address and payment choice.", "")
	}
	subject := r.Header.Get("X-Gateway-Subject")
	if key == "" {
		key = randomID()
	}
	hash := sha256.Sum256([]byte(subject + ":" + key))
	reservationKey := hex.EncodeToString(hash[:])
	data, _ := json.Marshal(purchase{request.Merchant, request.Items})
	status, reply, err := d.inventory.call(r.Context(), "POST", "/internal/reservations", data, reservationKey)
	if err != nil || status >= 500 || status == 401 {
		d.release(r.Context(), reservationKey)
		return inventoryUnavailable()
	}
	if status != 200 {
		var problem apiError
		if json.Unmarshal(reply, &problem) != nil || problem.Error == "" {
			return inventoryUnavailable()
		}
		return result{status: status, body: problem}
	}
	var reserved reservationResult
	if json.Unmarshal(reply, &reserved) != nil || reserved.Merchant.ID != request.Merchant || len(reserved.Items) != len(request.Items) {
		d.release(r.Context(), reservationKey)
		return inventoryUnavailable()
	}
	fee, _ := d.fee(subject, reserved.Merchant)
	total := reserved.Subtotal + fee
	if request.Payment == "wallet" && d.wallets[subject] < total {
		d.release(r.Context(), reservationKey)
		return failure(409, "insufficient_wallet", "Your Fetch wallet balance is too low for this order.", "payment")
	}
	now := time.Now().UTC()
	created := Order{ID: fmt.Sprintf("ORD-%04d", d.next), Customer: subject, Merchant: request.Merchant, MerchantName: reserved.Merchant.Name, Items: reserved.Items, Subtotal: reserved.Subtotal, DeliveryFee: fee, Total: total, Payment: request.Payment, Address: request.Address, Note: request.Note, Status: "placed", Timeline: []TimelineEntry{{"placed", now}}, CreatedAt: now}
	if request.Payment == "wallet" {
		d.wallets[subject] -= total
	}
	d.list = append(d.list, created)
	d.next++
	d.reservations[created.ID] = reservationKey
	return result{status: 201, body: map[string]any{"order": created}, effect: "created " + created.ID}
}
func validOrderRequest(request orderRequest) bool {
	if !length(request.Merchant, 7, 7) ||
		len(request.Items) < 1 || len(request.Items) > 20 ||
		!length(request.Note, 0, 200) ||
		!length(request.Address.Line1, 1, 100) ||
		!length(request.Address.Line2, 0, 100) ||
		!length(request.Address.Postcode, 5, 5) ||
		!length(request.Address.City, 1, 40) ||
		!slices.Contains(states, request.Address.State) ||
		(request.Payment != "cash" && request.Payment != "wallet") {
		return false
	}
	for _, line := range request.Items {
		if !length(line.Item, 7, 7) || line.Quantity < 1 || line.Quantity > 50 {
			return false
		}
	}
	return true
}
