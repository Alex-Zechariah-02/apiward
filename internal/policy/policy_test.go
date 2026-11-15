// Policy decoding problems name the member that caused them.

package policy

import (
	"errors"
	"testing"
)

func TestUnknownFieldNamed(t *testing.T) {
	head := `{"schema_version":4,"profile":"core"`
	for _, tc := range []struct{ name, document, field string }{
		{"unknown member", head + `,"extra":1}`, "extra"},
		{"case variant", head + `,"Profile":"core"}`, "Profile"},
		{"nested member", head + `,"upstreams":[{"id":"a","dial":"127.0.0.1:1","weight":2}]}`, "weight"},
	} {
		_, err := DecodePolicy([]byte(tc.document), Limits{})
		var problem *PolicyError
		if !errors.As(err, &problem) || problem.Code != "UNKNOWN_FIELD" || problem.Field != tc.field {
			t.Errorf("%s: %v, want UNKNOWN_FIELD naming %q", tc.name, err, tc.field)
		}
	}
}
