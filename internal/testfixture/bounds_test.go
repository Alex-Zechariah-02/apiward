// Fixture bounds: a control handler built with an empty secret refuses
// every caller, and every recorded header is cut at the receipt bound.

package testfixture

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestControlEmptySecret(t *testing.T) {
	control := service(t, "orders").Control(nil)
	for _, header := range []string{"", "Bearer ", "Bearer x"} {
		req := httptest.NewRequest(http.MethodPost, "/reset", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		rec := httptest.NewRecorder()
		control.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("empty secret, Authorization %q: %d", header, rec.Code)
		}
	}
}

func TestReceiptFieldsCapped(t *testing.T) {
	s := service(t, "orders")
	long := strings.Repeat("x", maxRecordedTarget+100)
	req := httptest.NewRequest(http.MethodGet, "/orders", nil)
	for _, name := range []string{"X-Request-Id", "X-Gateway-Generation", "X-Gateway-Subject", "X-Gateway-Roles"} {
		req.Header.Set(name, long)
	}
	s.ServeHTTP(httptest.NewRecorder(), req)
	r := s.receipts[0]
	for name, value := range map[string]string{"request ID": r.RequestID, "generation": r.Generation, "subject": r.Subject, "roles": r.Roles} {
		if len(value) != maxRecordedTarget {
			t.Errorf("%s kept %d bytes, want %d", name, len(value), maxRecordedTarget)
		}
	}
}
