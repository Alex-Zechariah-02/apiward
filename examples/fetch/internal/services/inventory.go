// The Inventory API: merchants, items, stock and the routing of its requests.

package services

import (
	"net/http"
	"slices"
	"strings"
)

type inventory struct {
	merchants    []Merchant
	items        []stockItem
	reservations map[string]reservation
}

func (d *inventory) reset() {
	d.merchants = seedMerchants()
	d.items = seedItems()
	d.reservations = map[string]reservation{}
}
func (d *inventory) snapshot() any {
	return struct {
		Merchants []Merchant  `json:"merchants"`
		Items     []stockItem `json:"items"`
	}{d.merchants, d.items}
}
func (d *inventory) merchant(id string) (Merchant, bool) {
	for _, merchant := range d.merchants {
		if merchant.ID == id {
			return merchant, true
		}
	}
	return Merchant{}, false
}
func (d *inventory) item(id string) *stockItem {
	for i := range d.items {
		if d.items[i].Item.ID == id {
			return &d.items[i]
		}
	}
	return nil
}
func publicItem(stock stockItem) Item {
	item := stock.Item
	switch {
	case stock.Stock == nil:
		item.StockState = "made_to_order"
	case *stock.Stock-stock.Reserved <= 0:
		item.StockState = "out"
	case *stock.Stock-stock.Reserved <= 15:
		item.StockState = "low"
	default:
		item.StockState = "in_stock"
	}
	return item
}
func ownsMerchant(r *http.Request, merchant string) bool {
	user, found := userByID(r.Header.Get("X-Gateway-Subject"))
	return found && hasRole(r, "MERCHANT") && user.Merchant != nil && *user.Merchant == merchant
}

func (d *inventory) handle(r *http.Request, body []byte) result {
	path := r.URL.Path
	if path == "/internal/reservations" && r.Method == "POST" {
		return d.reserve(r, body)
	}
	if id, ok := oneID(path, "/internal/merchants/"); ok && r.Method == "GET" {
		merchant, found := d.merchant(id)
		if !found {
			return notFound()
		}
		return result{status: 200, body: map[string]any{"merchant": merchant}}
	}
	if id, ok := oneID(path, "/internal/reservations/"); ok && r.Method == "DELETE" {
		return d.release(id)
	}
	if id, ok := oneID(strings.TrimSuffix(path, "/commit"), "/internal/reservations/"); ok && strings.HasSuffix(path, "/commit") && r.Method == "POST" {
		return d.commit(id)
	}
	if r.Method == "GET" && path == "/inventory/categories" {
		if _, ok := query(r); !ok {
			return invalidQuery()
		}
		return result{status: 200, body: map[string]any{"items": seedCategories()}}
	}
	if r.Method == "GET" && path == "/inventory/merchants" {
		q, ok := query(r, "section", "category", "limit", "after")
		if !ok {
			return invalidQuery()
		}
		n, after, ok := pagination(q)
		if !ok || !validSection(q.Get("section")) {
			return invalidQuery()
		}
		if category := q.Get("category"); category != "" && !slices.ContainsFunc(seedCategories(), func(c Category) bool { return c.ID == category }) {
			return invalidQuery()
		}
		if after != "" {
			if _, found := d.merchant(after); !found {
				return invalidQuery()
			}
		}
		items := []Merchant{}
		for _, merchant := range d.merchants {
			if merchant.ID > after && (q.Get("section") == "" || merchant.Section == q.Get("section")) && (q.Get("category") == "" || merchant.Category == q.Get("category")) {
				items = append(items, merchant)
			}
		}
		response := map[string]any{"items": items[:min(n, len(items))]}
		if len(items) > n {
			response["next"] = items[n-1].ID
		}
		return result{status: 200, body: response}
	}
	if r.Method == "GET" && path == "/inventory/search" {
		q, ok := query(r, "q", "section")
		if !ok || !length(q.Get("q"), 2, 40) || !validSection(q.Get("section")) {
			return invalidQuery()
		}
		items := []map[string]any{}
		search := strings.ToLower(q.Get("q"))
		for _, stock := range d.items {
			merchant, _ := d.merchant(stock.Item.Merchant)
			if (q.Get("section") == "" || merchant.Section == q.Get("section")) && strings.Contains(strings.ToLower(stock.Item.Name+" "+stock.Item.Description+" "+merchant.Name), search) {
				items = append(items, map[string]any{"merchant": merchant, "item": publicItem(stock)})
			}
		}
		return result{status: 200, body: map[string]any{"items": items}}
	}
	if id, ok := oneID(path, "/inventory/merchants/"); ok && r.Method == "GET" {
		if _, ok := query(r); !ok {
			return invalidQuery()
		}
		merchant, found := d.merchant(id)
		if !found {
			return notFound()
		}
		type group struct {
			Group string `json:"group"`
			Items []Item `json:"items"`
		}
		menu := []group{}
		for _, stock := range d.items {
			if stock.Item.Merchant != id {
				continue
			}
			index := slices.IndexFunc(menu, func(g group) bool { return g.Group == stock.Item.Group })
			if index < 0 {
				menu = append(menu, group{stock.Item.Group, []Item{}})
				index = len(menu) - 1
			}
			menu[index].Items = append(menu[index].Items, publicItem(stock))
		}
		return result{status: 200, body: map[string]any{"merchant": merchant, "menu": menu}}
	}
	if id, ok := oneID(path, "/inventory/items/"); ok {
		stock := d.item(id)
		if stock == nil {
			return notFound()
		}
		switch r.Method {
		case "GET":
			if _, ok := query(r); !ok {
				return invalidQuery()
			}
			merchant, _ := d.merchant(stock.Item.Merchant)
			return result{status: 200, body: map[string]any{"item": publicItem(*stock), "merchant": merchant}}
		case "PATCH":
			if !ownsMerchant(r, stock.Item.Merchant) {
				return notFound()
			}
			var change struct {
				Price     *int64 `json:"price_sen"`
				Available *bool  `json:"available"`
			}
			if rejected := decodeBody(r, body, 512, &change); rejected != nil {
				return *rejected
			}
			if change.Price == nil && change.Available == nil || change.Price != nil && (*change.Price < 50 || *change.Price > 100000) {
				return failure(422, "invalid_change", "Choose a price or availability change within the allowed range.", "")
			}
			if change.Price != nil {
				stock.Item.Price = *change.Price
			}
			if change.Available != nil {
				stock.Item.Available = *change.Available
			}
			return result{status: 200, body: map[string]any{"item": publicItem(*stock)}, effect: "updated " + id}
		}
	}
	if id, ok := oneID(path, "/inventory/stock/"); ok && (r.Method == "GET" || r.Method == "PATCH") {
		stock := d.item(id)
		if stock == nil || r.Header.Get("X-Gateway-Subject") == "" {
			return notFound()
		}
		// Authorization is the gateway's decision, including temporary grants.
		// Only merchant ownership belongs here; Operations can see all stores.
		if hasRole(r, "MERCHANT") && !hasRole(r, "OPERATIONS") && !ownsMerchant(r, stock.Item.Merchant) {
			return notFound()
		}
		if stock.Stock == nil {
			return failure(422, "invalid_change", "This item is made to order and has no stock count.", "item")
		}
		if r.Method == "PATCH" {
			var change struct {
				Delta *int `json:"delta"`
			}
			if rejected := decodeBody(r, body, 256, &change); rejected != nil {
				return *rejected
			}
			if change.Delta == nil || *change.Delta == 0 || *change.Delta < -100 || *change.Delta > 100 {
				return failure(422, "invalid_change", "Choose a stock change from -100 to 100, excluding zero.", "delta")
			}
			if *stock.Stock+*change.Delta < stock.Reserved {
				return failure(409, "insufficient_stock", "That change would remove stock reserved for orders.", "delta")
			}
			*stock.Stock += *change.Delta
		} else if _, ok := query(r); !ok {
			return invalidQuery()
		}
		return result{status: 200, body: map[string]any{"item": id, "stock": *stock.Stock, "reserved": stock.Reserved}}
	}
	return notFound()
}

func validSection(section string) bool {
	return section == "" || section == "food" || section == "mart"
}
func oneID(path, prefix string) (string, bool) {
	id, ok := strings.CutPrefix(path, prefix)
	return id, ok && id != "" && !strings.Contains(id, "/")
}
