// Admin request bodies checked at their nesting bound: two levels deeper
// than a policy may nest.

package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// The deepest body the member check allows two levels below a policy's
// depth is decoded; one level more is refused.
func TestBodyDepthAtBound(t *testing.T) {
	nest := func(levels int) string {
		return strings.Repeat(`{"a":`, levels) + "1" + strings.Repeat("}", levels)
	}
	levels := 1
	for policy.CheckMembers([]byte(nest(levels+1)), policy.MaxPolicyDepth+2) == nil {
		levels++
	}
	decode := func(body string) bool {
		var value any
		r := httptest.NewRequest(http.MethodPost, "/admin/candidates", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		return decodeBody(httptest.NewRecorder(), r, maxAdminBody, &value)
	}
	if !decode(nest(levels)) {
		t.Fatalf("a body nested %d levels was refused", levels)
	}
	if decode(nest(levels + 1)) {
		t.Fatalf("a body nested %d levels was decoded", levels+1)
	}
}
