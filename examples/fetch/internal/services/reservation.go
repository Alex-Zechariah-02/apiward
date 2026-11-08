// Stock reservations for checkout: reserve, release and commit.

package services

import (
	"crypto/sha256"
	"fmt"
	"net/http"
)

type Line struct {
	Item     string `json:"item"`
	Quantity int    `json:"quantity"`
}
type PricedLine struct {
	Item      string `json:"item"`
	Name      string `json:"name"`
	Quantity  int    `json:"quantity"`
	UnitPrice int64  `json:"unit_price_sen"`
}
type purchase struct {
	Merchant string `json:"merchant"`
	Items    []Line `json:"items"`
}
type reservationResult struct {
	Merchant Merchant     `json:"merchant"`
	Items    []PricedLine `json:"items"`
	Subtotal int64        `json:"subtotal_sen"`
}
type reservation struct {
	digest              [32]byte
	counts              map[string]int
	response            reservationResult
	released, committed bool
}

func (d *inventory) reserve(r *http.Request, body []byte) result {
	key := r.Header.Get("Idempotency-Key")
	if !idempotencyKey(key) {
		return failure(400, "invalid_request", "A valid idempotency key is required.", "Idempotency-Key")
	}
	digest := sha256.Sum256(body)
	if previous, found := d.reservations[key]; found {
		if previous.digest != digest || previous.released {
			return failure(409, "idempotency_conflict", "That reservation identity is already used.", "")
		}
		return result{status: 200, body: previous.response}
	}
	var request purchase
	if rejected := decodeBody(r, body, 4096, &request); rejected != nil {
		return *rejected
	}
	merchant, found := d.merchant(request.Merchant)
	if !found {
		return notFound()
	}
	if !merchant.Open {
		return failure(422, "merchant_closed", "This merchant is closed.", "merchant")
	}
	if len(request.Items) < 1 || len(request.Items) > 20 {
		return failure(422, "invalid_change", "Choose from one to twenty items.", "items")
	}
	response := reservationResult{Merchant: merchant, Items: []PricedLine{}}
	counts := map[string]int{}
	for i, line := range request.Items {
		field := fmt.Sprintf("items[%d].item", i)
		stock := d.item(line.Item)
		if stock == nil || !stock.Item.Available {
			return failure(422, "item_unavailable", "This item is unavailable.", field)
		}
		if stock.Item.Merchant != request.Merchant {
			return failure(422, "mixed_merchants", "Choose items from one merchant.", field)
		}
		if line.Quantity < 1 || line.Quantity > 50 {
			return failure(422, "invalid_change", "Choose a quantity from one to fifty.", fmt.Sprintf("items[%d].quantity", i))
		}
		counts[line.Item] += line.Quantity
		if stock.Stock != nil && counts[line.Item] > *stock.Stock-stock.Reserved {
			return failure(409, "out_of_stock", stock.Item.Name+" is out of stock.", field)
		}
		response.Items = append(response.Items, PricedLine{line.Item, stock.Item.Name, line.Quantity, stock.Item.Price})
		response.Subtotal += int64(line.Quantity) * stock.Item.Price
	}
	for id, quantity := range counts {
		if stock := d.item(id); stock.Stock != nil {
			stock.Reserved += quantity
		}
	}
	d.reservations[key] = reservation{digest: digest, counts: counts, response: response}
	return result{status: 200, body: response, effect: "reserved stock"}
}

func (d *inventory) release(key string) result {
	if !idempotencyKey(key) {
		return failure(400, "invalid_request", "A valid reservation identity is required.", "")
	}
	entry, found := d.reservations[key]
	if found && entry.committed {
		return failure(409, "invalid_transition", "This reservation was already consumed.", "")
	}
	if found && !entry.released {
		for id, quantity := range entry.counts {
			if stock := d.item(id); stock.Stock != nil {
				stock.Reserved -= quantity
			}
		}
	}
	// A release may arrive before a timed-out prepare. Keep a tombstone so
	// that delayed request cannot reserve orphaned stock afterwards.
	entry.released = true
	d.reservations[key] = entry
	return result{status: 200, body: map[string]any{"released": true}}
}

func (d *inventory) commit(key string) result {
	entry, found := d.reservations[key]
	if !found || entry.released {
		return notFound()
	}
	if !entry.committed {
		for id, quantity := range entry.counts {
			if stock := d.item(id); stock.Stock != nil {
				*stock.Stock -= quantity
				stock.Reserved -= quantity
			}
		}
		entry.committed = true
		d.reservations[key] = entry
	}
	return result{status: 200, body: map[string]any{"committed": true}}
}
