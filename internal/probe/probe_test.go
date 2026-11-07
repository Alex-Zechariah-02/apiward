// Tests of the probe generator and the judgement: boundary probes per control, their classes, ledger items and bodies.

package probe

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/exchange"
)

// fixture reads testdata/exchange.json as migrate reads an exchange file.
func fixture(t *testing.T) (map[string]any, *exchange.Ledger) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "exchange.json"))
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var root map[string]any
	if err := decoder.Decode(&root); err != nil {
		t.Fatal(err)
	}
	document, ledger, err := exchange.Split(root)
	if err != nil {
		t.Fatal(err)
	}
	return document, ledger
}

// TestProbeBoundaries checks the probes around every control of the
// fixture, the ledger item each names, the bodies, and that operations
// migrate policy leaves out get none.
func TestProbeBoundaries(t *testing.T) {
	document, ledger := fixture(t)
	file, err := Generate(document, ledger, Options{MaxBodyBytes: 16384})
	if err != nil {
		t.Fatal(err)
	}
	probes := map[string]Probe{}
	for _, p := range file.Probes {
		if _, twice := probes[p.ID]; twice {
			t.Errorf("probe %s written twice", p.ID)
		}
		probes[p.ID] = p
	}
	const orders = "openapi:operation:GET /orders/{rest}"
	want := []struct {
		id    string
		class Class
		item  string
	}{
		{"items:forwarded", Forwarded, "openapi:operation:GET /items"},
		{"items:path:deeper", NotFound, "openapi:operation:GET /items"},
		{"items:path:slash", NotFound, ""},
		{"items:path:suffix", NotFound, ""},
		{"items:path:upper", NotFound, ""},
		{"items:method:POST", Method, ""},
		{"orders.read:forwarded", Forwarded, orders + ":roles"},
		{"orders.read:path:parent", NotFound, ""},
		{"orders.read:path:slash", NotFound, ""},
		{"orders.read:path:deeper", Forwarded, ""},
		{"orders.read:method:PUT", Method, ""},
		{"orders.read:authn:none", Authn, orders + ":auth"},
		{"orders.read:authn:malformed", Authn, ""},
		{"orders.read:authn:expired", Authn, ""},
		{"orders.read:authn:wrong_issuer", Authn, ""},
		{"orders.read:authn:wrong_audience", Authn, ""},
		{"orders.read:role:STAFF", Forwarded, orders + ":roles"},
		{"orders.read:authz:no_role", Authz, orders + ":roles"},
		{"orders.read:rate", Rate, orders + ":rate"},
		{"orders.read:error", Error, orders + ":roles"},
		{"orders.write:forwarded", Forwarded, ""},
		{"orders.write:body:invalid", Validation, "openapi:operation:POST /orders/{rest}:body"},
		{"orders.write:body:oversize", Size, "openapi:operation:POST /orders/{rest}:size"},
		{"hosted:forwarded", Forwarded, ""},
		{"hosted:when:host", NotFound, "openapi:operation:GET /hosted:when"},
		{"hosted:when:depth", Forwarded, ""},
		{"hosted:when:without:X-Version", NotFound, ""},
		{"hosted:when:case:X-Version", NotFound, ""},
		{"denied:forwarded", Authz, "openapi:operation:GET /denied:access"},
		{"items:preflight:allowed", PreflightAllowed, "openapi:member:x-apiward-cors"},
		{"items:preflight:origin", PreflightRefused, ""},
		{"items:preflight:header", PreflightRefused, ""},
		{"items:preflight:method", PreflightRefused, ""},
		{"orders.write:preflight:allowed", PreflightAllowed, ""},
		{"hosted:preflight:allowed", PreflightAllowed, ""},
	}
	for _, w := range want {
		p, found := probes[w.id]
		switch {
		case !found:
			t.Errorf("no probe %s", w.id)
		case p.Expect.Class != w.class:
			t.Errorf("%s: class %s, want %s", w.id, p.Expect.Class, w.class)
		case w.item != "" && p.Expect.LedgerItem != w.item:
			t.Errorf("%s: ledger item %s, want %s", w.id, p.Expect.LedgerItem, w.item)
		}
	}
	for _, absent := range []string{"loose:forwarded", "refused:forwarded", "denied:error", "orders.read:method:GET", "orders.write:method:PUT"} {
		if _, found := probes[absent]; found {
			t.Errorf("probe %s written", absent)
		}
	}
	if p := probes["orders.write:forwarded"]; p.Path != "/orders/x" || p.Identity != "role:STAFF" || p.BodyKind != Valid {
		t.Errorf("orders.write:forwarded: %+v", p)
	}
	if p := probes["hosted:forwarded"]; p.Headers["Host"] != "a.example.com" || p.Headers["X-Version"] != "v2" {
		t.Errorf("hosted:forwarded headers: %v", p.Headers)
	}
	ops, err := Operations(document, ledger, Options{MaxBodyBytes: 16384})
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range ops {
		if o.ID != "orders.write" {
			continue
		}
		valid, _ := Body(o, Valid)
		oversized, _ := Body(o, Oversized)
		if string(valid) != `{"count":2,"item":"aaa"}` || len(oversized) != 65 {
			t.Errorf("orders.write bodies: %s and %d bytes, want the smallest valid one and 65", valid, len(oversized))
		}
	}
	again, err := Generate(document, ledger, Options{MaxBodyBytes: 16384})
	if err != nil {
		t.Fatal(err)
	}
	first, _ := file.Encode()
	second, _ := again.Encode()
	if !bytes.Equal(first, second) {
		t.Error("two runs wrote different probe files")
	}
}

// TestJudge checks that a difference passes only with an approximated
// ledger item in its direction, so a wrong ledger cannot hide one.
func TestJudge(t *testing.T) {
	item := func(class exchange.Class, direction exchange.Direction) *exchange.Item {
		return &exchange.Item{Class: class, Direction: direction}
	}
	cases := []struct {
		gateway, source Class
		item            *exchange.Item
		want            Verdict
	}{
		{Method, NotFound, nil, StatusOnly},
		{Authn, Forwarded, item(exchange.Approximated, exchange.Stricter), Expected},
		{Authn, Forwarded, item(exchange.Approximated, exchange.Looser), Unexpected},
		{Forwarded, NotFound, item(exchange.Approximated, exchange.Stricter), Unexpected},
		{Forwarded, NotFound, item(exchange.Approximated, exchange.Both), Expected},
		{Authz, Authn, item(exchange.Equivalent, ""), Unexpected},
	}
	for _, c := range cases {
		if got := Judge(c.gateway, c.source, c.item); got != c.want {
			t.Errorf("Judge(%s, %s, %+v) = %s, want %s", c.gateway, c.source, c.item, got, c.want)
		}
	}
}
