// Fetch policies: legacy policies and subjects refused.

package gateway

import (
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

func TestFetchRejectsLegacyPolicyAndSubjects(t *testing.T) {
	for document, want := range map[string]string{
		`{"schema_version":3,"profile":"core"}`:               "SCHEMA_VERSION_UNSUPPORTED",
		`{"schema_version":4,"profile":"core","subjects":[]}`: "UNKNOWN_FIELD",
	} {
		if _, err := policy.DecodePolicy([]byte(document)); errorCode(err) != want {
			t.Errorf("%s: %s, want %s", document, errorCode(err), want)
		}
	}
}
